package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// SigninMFAConfig explicitly selects UV-passkey-primary followed by confirmed
// TOTP. It never treats UV as a second factor. Known-empty accounts retain the
// ordinary signin result; enrolled accounts receive only a committed challenge.
// Lifetime is 1..300 whole seconds, capped by original assertion/browser expiry.
// Signing, replay and envelope keys retain their native independent ownership.
// Envelope and its retained key are borrowed for the original journal lifetime.
// Install the MFA continuation, TOTP and capability owner histories separately.
type SigninMFAConfig struct {
	Lifetime      time.Duration
	MaxAttempts   uint32
	IssuerURL     string
	Issuer        issuerpg.IssuerConfig
	Custody       issuerpg.IssuancePreparationConfig
	Envelope      *envelope.Service
	EnvelopeKeyID string
}

func (SigninMFAConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SigninMFAConfig(redacted)"))
}
func (SigninMFAConfig) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }
func (SigninMFAConfig) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

type signinMFAComposition struct {
	lifetime               time.Duration
	attempts               uint32
	issuerURL, envelopeKey string
	issuer                 *issuerpg.Issuer
	codec                  *issuerpg.IssuancePreparationCodec
	crypto                 *envelope.Service
}

// NewMFASigninService selects the additive native TOTP challenge profile.
// NewSigninService remains known-empty-only. No IO or randomness occurs here;
// pool, clock, authorization and envelope collaborators remain caller-owned.
func NewMFASigninService(pool *database.Pool, c SigninConfig, m SigninMFAConfig) (*SigninService, error) {
	u, err := url.Parse(m.IssuerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || m.Lifetime < time.Second || m.Lifetime > 5*time.Minute || m.Lifetime%time.Second != 0 || m.MaxAttempts < 1 || m.MaxAttempts > 100 || m.Envelope == nil || len(m.EnvelopeKeyID) == 0 || len(m.EnvelopeKeyID) > 128 || m.Issuer.Audience != c.Profile.Audience || m.Issuer.Crypto.Issuer != m.IssuerURL {
		return nil, identity.InvalidInputError{Field: "passkey_mfa"}
	}
	i, err := issuerpg.NewIssuer(m.Issuer)
	if err != nil {
		return nil, err
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(i, m.Custody)
	if err != nil {
		return nil, err
	}
	s, err := NewSigninService(pool, c)
	if err != nil {
		return nil, err
	}
	s.mfa = &signinMFAComposition{lifetime: m.Lifetime, attempts: m.MaxAttempts, issuerURL: m.IssuerURL, envelopeKey: m.EnvelopeKeyID, issuer: i, codec: codec, crypto: m.Envelope}
	return s, nil
}

// Keep all historical known-empty bytes unchanged. Explicit selection is bound
// at options so completion cannot borrow a ceremony from the default service or
// replace the original selected issuer, attempts, lifetime or custody key ID.
func (s *SigninService) signinMFAContext(original []byte) ([]byte, error) {
	if s.mfa == nil {
		return original, nil
	}
	profile, err := json.Marshal(struct {
		Issuer, Key string
		Lifetime    time.Duration
		Attempts    uint32
	}{s.mfa.issuerURL, s.mfa.envelopeKey, s.mfa.lifetime, s.mfa.attempts})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(profile)
	return json.Marshal(struct {
		Original json.RawMessage
		MFA      [32]byte
	}{original, digest})
}
