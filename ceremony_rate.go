package passkey

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RateSourceKind selects exactly one original ceremony rate dimension. It is
// not an authorization subject kind: an anonymous flow authenticates no user.
// Zero and unknown values are invalid; metadata grants no execution authority.
type RateSourceKind uint8

const (
	// RateSourceUser names the genuine existing session's enrollment user.
	RateSourceUser RateSourceKind = iota + 1
	// RateSourceIdentifier names the exact original identified signin input,
	// including an originally suppressed or ineligible account lookup.
	RateSourceIdentifier
	// RateSourceAnonymousFlow names the original identifier-free browser flow.
	RateSourceAnonymousFlow
)

// CeremonyRateSource is sensitive original rate metadata, never a validity
// lease, authentication result or permission to consume a ceremony. Exactly
// one dimension matches Kind; the other two are empty. CeremonyID is the
// original committed protocol ceremony, not a new completion attempt. Lifetime
// is its immutable original policy duration, never remaining time or a renewed
// expiry. Native completion must independently revalidate and atomically
// consume current authority. Historical consumed metadata may remain readable
// while original custody and time remain valid; it cannot issue another secret.
type CeremonyRateSource struct {
	CeremonyID      string
	Lifetime        time.Duration
	Kind            RateSourceKind
	UserID          identity.UserID
	Identifier      string
	AnonymousFlowID identity.PreAuthTransactionID
}

// RegistrationCeremonyRateRequest borrows genuine current session/action-proof
// custody for the registration-completion phase and the original ceremony ID.
// Reading metadata consumes neither proof nor ceremony and accepts no raw
// authenticator response, caller-selected user or replacement challenge.
type RegistrationCeremonyRateRequest struct {
	RegistrationRequest
	CeremonyID string
}

// SigninCeremonyRateRequest borrows original browser possession, exact original
// canonical identifier and committed ceremony ID. It authenticates the source,
// not account eligibility, a credential or the browser's raw assertion.
type SigninCeremonyRateRequest struct {
	SigninRequest
	CeremonyID string
}

// DiscoverableCeremonyRateRequest selects the original identifier-free mode.
// Only original browser/flow custody can produce its anonymous-flow dimension;
// no credential handle, assertion, user or fabricated identifier is accepted.
type DiscoverableCeremonyRateRequest struct {
	DiscoverableSigninRequest
	CeremonyID string
}

// SignupCeremonyRateRequest borrows original signup browser/flow custody and
// the committed create ceremony. Its anonymous rate dimension authenticates no
// user and never projects the prospective identity, handle or response. Native
// Signup must still revalidate and consume current authority atomically.
type SignupCeremonyRateRequest struct {
	SignupRequest
	CeremonyID string
}

func (CeremonyRateSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.CeremonyRateSource(redacted)"))
}
func (RegistrationCeremonyRateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.RegistrationCeremonyRateRequest(redacted)"))
}
func (SigninCeremonyRateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SigninCeremonyRateRequest(redacted)"))
}
func (DiscoverableCeremonyRateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.DiscoverableCeremonyRateRequest(redacted)"))
}
func (SignupCeremonyRateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SignupCeremonyRateRequest(redacted)"))
}

// MarshalJSON prohibits implicit export of correlated original rate metadata.
func (CeremonyRateSource) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit export of correlated original rate metadata.
func (CeremonyRateSource) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalJSON prohibits implicit export of original authentication custody.
func (RegistrationCeremonyRateRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit export of original authentication custody.
func (RegistrationCeremonyRateRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalJSON prohibits implicit export of original browser custody.
func (SigninCeremonyRateRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit export of original browser custody.
func (SigninCeremonyRateRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalJSON prohibits implicit export of original browser custody.
func (DiscoverableCeremonyRateRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit export of original browser custody.
func (DiscoverableCeremonyRateRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalJSON prohibits implicit export of original signup browser custody.
func (SignupCeremonyRateRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit export of original signup browser custody.
func (SignupCeremonyRateRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
