package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// SigninConfig selects one trusted identified resident UV/ES256 passkey
// deployment. Flow.Action must be identity.passkey.signin-verify. Profile and
// protocol fix tenant/RP/policy before browser input; final Remember comes only
// from the original session-owned flow. Dependencies are borrowed and must
// outlive calls. Install existing owner histories plus SigninMigrationSource.
// Options use account-independent resident discovery, but the original verified
// email is mandatory at completion through the identified methods. The additive
// Discoverable methods explicitly select identifier-free signin with the risk
// owner's startup opt-in. No signup, completed-MFA or organization profile is
// enabled.
type SigninConfig struct {
	// OptionsRequests explicitly enables the additive keyed options APIs only.
	OptionsRequests OptionsRequestConfig
	Protocol        webauthn.Config
	Profile         sessionpg.PasskeyAdmissionConfig
	Coordinator     kernel.CoordinatorConfig
	Authorization   authorization.Service
	Clock           clock.Clock
	Flow            session.PreAuthIssuerConfig
	Session         session.IssuerConfig
	CSRF            session.CSRFKey
	Repository      sessionpg.Config
	Risk            risk.AuthenticationAdmissionCustodyConfig
	IdentifierKey   []byte
}

// SigninRequest is the adapter-neutral passkey data contract.
type SigninRequest = passkey.SigninRequest

// SigninCompletion is the adapter-neutral passkey data contract.
type SigninCompletion = passkey.SigninCompletion

// SigninResult is the adapter-neutral passkey data contract.
type SigninResult = passkey.SigninResult

// SigninService composes existing preauth/risk/WebAuthn/identity/session owners.
// It owns no pool lifetime, goroutine, private journal, proof or session store.
// Concurrent calls use invocation-private participants; zero values deny.
type SigninService struct {
	pool      *database.Pool
	config    func() SigninConfig
	flow      *session.PreAuthIssuer
	directory *kernel.Repository
	protocol  *webauthnpg.Store
	policy    *policy.AuthorityStore
	risk      risk.AuthenticationAdmissionCustody
	effect    *sessionpg.PasskeySigninEffect
}

func (SigninConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SigninConfig(redacted)"))
}
func (SigninService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SigninService(redacted)"))
}

// MarshalJSON prohibits implicit configuration or credential transport.
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit configuration or credential transport.
func (SigninConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSigninService validates native composition without IO or entropy. The
// exact profile is retained across preauth issue, options and final session.
func NewSigninService(pool *database.Pool, c SigninConfig) (*SigninService, error) {
	if pool == nil || pool.Raw() == nil || c.Authorization == nil || c.Clock == nil || c.Protocol.MaximumDuration < time.Millisecond || c.Protocol.MaximumDuration > 5*time.Second || len(c.IdentifierKey) != 32 || c.Flow.Action != signinOperation(true).OperationID || c.Flow.PolicyVersion == 0 || c.Flow.Purpose != session.PreAuthSessionIssuance || c.Session.Authority != nil || c.Profile.RPNamespace == "" || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.AdmissionPolicy.PolicyVersion != c.Flow.PolicyVersion {
		return nil, identity.InvalidInputError{Field: "passkey_signin"}
	}
	if _, err := PasskeyAuthorityKey(c.Profile.RPNamespace, c.Protocol.TenantID, "validation"); err != nil {
		return nil, err
	}
	if c.Protocol.Algorithms != nil && (len(c.Protocol.Algorithms) != 1 || c.Protocol.Algorithms[0] != webauthn.ES256) {
		return nil, identity.InvalidInputError{Field: "passkey_algorithms"}
	}
	if !slices.Contains(c.Protocol.RelyingParty.Origins, c.Flow.Origin) {
		return nil, identity.InvalidInputError{Field: "passkey_origin"}
	}
	c.Protocol.RelyingParty.Origins = slices.Clone(c.Protocol.RelyingParty.Origins)
	c.Protocol.Algorithms = slices.Clone(c.Protocol.Algorithms)
	c.IdentifierKey = bytes.Clone(c.IdentifierKey)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.Flow.Clock, c.Session.Clock = c.Clock, c.Clock
	flowExecutor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: c.Repository, Coordinator: c.Coordinator, Authorization: c.Authorization, Clock: c.Clock, ActorID: c.Flow.ActorID, Action: c.Flow.Action, Origin: c.Flow.Origin, CallbackURL: c.Flow.CallbackURL, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion, AuditRetentionVersion: 1})
	if err != nil {
		return nil, err
	}
	flow, err := session.NewPreAuthIssuer(flowExecutor, c.Flow)
	if err != nil {
		return nil, err
	}
	protocol, err := webauthnpg.New(pool, webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion})
	if err != nil {
		return nil, err
	}
	if _, err := webauthn.New(c.Protocol, webauthn.Dependencies{Store: protocol}); err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Protocol.MaximumDuration})
	if err != nil {
		return nil, err
	}
	policies, err := policy.NewAuthorityStore(pool.Raw(), c.Protocol.MaximumDuration)
	if err != nil {
		return nil, err
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, err
	}
	authority, err := NewSessionAuthority(pool, SessionAuthorityConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: c.Protocol.MaximumDuration})
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewPasskeySigninEffect(c.Repository, c.Profile, authority)
	if err != nil {
		return nil, err
	}
	s := &SigninService{pool: pool, config: func() SigninConfig { return c }, flow: flow, directory: directory, protocol: protocol, policy: policies, risk: custody, effect: effect}
	if _, err := session.NewPasskeySessionIssuerWithCSRF(&signinInvocation{}, c.Session, c.CSRF); err != nil {
		return nil, err
	}
	if c.OptionsRequests.state != nil {
		p := &signinInvocation{Store: protocol, service: s, operation: signinOperation(false)}
		_, registry, err := p.runtime()
		if err != nil {
			return nil, err
		}
		if _, err := kernel.NewCoordinatorWithRequestKeys(pool, registry, c.Coordinator, c.OptionsRequests.state().request); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func signinOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.signin-options"
	if finish {
		id = "identity.passkey.signin-verify"
	}
	op := identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if !finish {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}

// PrepareFlow delegates original entropy/time/remember custody to the session
// owner. Retain the unchanged preparation for IssueFlow, never prepare a retry.
func (s *SigninService) PrepareFlow(i session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	if s == nil || s.config == nil || i.TenantID != s.config().Protocol.TenantID || i.IdentifierBinding != ([32]byte{}) {
		return session.PreparedPreAuthIssuance{}, identity.ForbiddenError{}
	}
	return s.flow.Prepare(i)
}

// IssueFlow commits the original session-owned browser flow and reveal-once
// cookie. It authenticates nobody and returns no session credential.
func (s *SigninService) IssueFlow(ctx context.Context, p session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	if s == nil || s.flow == nil {
		return session.PreAuthIssueResult{}, identity.ForbiddenError{}
	}
	return s.flow.Issue(ctx, p)
}

func (s *SigninService) prepare(ctx context.Context, r SigninRequest, finish bool) (*signinInvocation, error) {
	return s.prepareProfile(ctx, r, finish, false)
}

func (s *SigninService) prepareFlow(ctx context.Context, r SigninRequest, finish, discoverable bool) (*signinInvocation, error) {
	if ctx == nil || s == nil || s.config == nil {
		return nil, identity.InvalidInputError{Field: "passkey_signin"}
	}
	c := s.config()
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return nil, err
	}
	if r.Origin != c.Flow.Origin || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Device) == 0 || len(r.Device) > 128 || !discoverable && (len(r.Identifier) == 0 || len(r.Identifier) > 320) || discoverable && r.Identifier != "" || len(r.CorrelationID) == 0 || len(r.CorrelationID) > 128 {
		return nil, identity.ForbiddenError{}
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), c.Repository, c.Protocol.TenantID, r.FlowID)
	if err != nil {
		return nil, err
	}
	fs, err := flow.Bindings()
	if err != nil {
		return nil, err
	}
	i := fs.Binding.Intent
	if i.Action != c.Flow.Action || i.Origin != r.Origin || i.CallbackURL != c.Flow.CallbackURL || i.PolicyID != c.Flow.PolicyID || i.PolicyVersion != c.Flow.PolicyVersion || i.Purpose != session.PreAuthSessionIssuance || i.IdentifierBinding != ([32]byte{}) {
		return nil, identity.ForbiddenError{}
	}
	digest, err := r.Cookie.PreAuthDigest(c.Flow.LookupKey, fs.Binding)
	if err != nil || flow.Check(c.Clock.Now(), fs.Binding, digest) != nil {
		return nil, identity.ForbiddenError{}
	}
	identifier := ""
	if !discoverable {
		h := hmac.New(sha256.New, c.IdentifierKey)
		_, _ = h.Write([]byte("passkey-identified-email-v1\x00" + string(c.Protocol.TenantID) + "\x00" + r.Identifier))
		identifier = hex.EncodeToString(h.Sum(nil))
	}
	return &signinInvocation{Store: s.protocol, service: s, request: r, operation: signinOperation(finish), flow: flow, cookie: digest, identifier: identifier, discoverable: discoverable}, nil
}

func (s *SigninService) prepareProfile(ctx context.Context, r SigninRequest, finish, discoverable bool) (*signinInvocation, error) {
	p, err := s.prepareFlow(ctx, r, finish, discoverable)
	if err != nil {
		return nil, err
	}
	c := s.config()
	subject := risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: p.identifier}
	scope := risk.Context{Tenant: string(c.Protocol.TenantID), Operation: risk.Action(p.operation.OperationID), Attempt: string(r.CommandID)}
	// identity.security.v1's risk subset admits anonymous/human/system actors,
	// not service attribution. This remains an unauthenticated browser attempt;
	// the service still owns the actual protocol and options command actor.
	evaluated, err := c.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: r.CommandID, CorrelationID: r.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(r.CommandID)}})
	if err != nil {
		return nil, err
	}
	riskAdmission, err := s.risk.Prepare(ctx, evaluated, scope, subject)
	if err != nil {
		return nil, err
	}
	if err := p.prepareDirectory(ctx); err != nil {
		return nil, err
	}
	p.risk = riskAdmission
	if discoverable {
		return p, nil
	}
	// Options disclose no identity or credential descriptors. An ineligible
	// original lookup is retained as non-authenticating admission, never a
	// synthetic principal; later registration cannot promote that ceremony.
	if err := p.prepareRecipient(ctx); err != nil {
		if finish {
			return nil, err
		}
		p.recipient, p.factor, p.passkey, p.policy = kernel.RecipientRecord{}, 0, 0, 0
		p.handle = nil
	}
	return p, nil
}

func (p *signinInvocation) prepareRecipient(ctx context.Context) error {
	s, r := p.service, p.request
	c := s.config()
	recipient, err := s.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: c.Protocol.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: r.Identifier, Eligibility: kernel.RecipientVerified})
	if err != nil || recipient.Suppressed {
		return identity.ForbiddenError{}
	}
	recipient.Query.UserID = recipient.User.ID
	if string(recipient.User.ID) == string(c.Flow.ActorID) {
		return identity.ForbiddenError{}
	}
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.pool, c.Protocol.TenantID, recipient.User.ID, c.Protocol.MaximumDuration)
	if err != nil || enrolled {
		return identity.ForbiddenError{}
	}
	pol, err := s.policy.Get(ctx, policy.AuthorityScope{TenantID: authorization.TenantID(c.Protocol.TenantID), PolicyNamespace: c.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(recipient.User.ID)})
	if err != nil {
		return identity.ForbiddenError{}
	}
	p.recipient, p.factor, p.policy = recipient, factor, pol.Version
	return p.readMapping(ctx)
}

// AuthenticationOptions checks original flow/cookie, counted/audited risk and
// directory authority before committing account-independent resident UV options.
// No credential descriptors or account eligibility are disclosed. The private
// original identifier admission must still match the genuinely verified target.
func (s *SigninService) AuthenticationOptions(ctx context.Context, r SigninRequest) (webauthn.AssertionOptions, error) {
	if ctx == nil || s == nil || s.config == nil {
		return webauthn.AssertionOptions{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepare(ctx, r, false)
	if err != nil {
		return webauthn.AssertionOptions{}, err
	}
	protocol, err := webauthn.NewDiscoverable(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return webauthn.AssertionOptions{}, err
	}
	return protocol.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: p.ceremonyContext(), Origin: r.Origin})
}

// Signin verifies genuine original-service-attributed browser assertion before
// the self-human final command consumes flow, protocol transition and native
// session effects atomically. No provisional bearer or proof is exposed.
func (s *SigninService) Signin(ctx context.Context, r SigninCompletion) (SigninResult, error) {
	if ctx == nil || s == nil || s.config == nil || len(r.CeremonyID) != 22 || len(r.Response) == 0 || len(r.Response) > 262144 {
		return SigninResult{}, identity.InvalidInputError{Field: "passkey_signin"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepare(ctx, r.SigninRequest, true)
	if err != nil {
		return SigninResult{}, err
	}
	id, err := signinResponseCredentialID(r.Response)
	if err != nil {
		return SigninResult{}, err
	}
	if err := p.selectCredential(ctx, id); err != nil {
		return SigninResult{}, err
	}
	p.ceremonyID = r.CeremonyID
	if err := p.readContext(ctx); err != nil {
		return SigninResult{}, err
	}
	protocol, err := webauthn.NewDiscoverable(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return SigninResult{}, err
	}
	verified, err := protocol.VerifyDiscoverableAssertion(ctx, webauthn.VerifyDiscoverableAssertionRequest{Context: p.ceremonyContext(), CeremonyID: r.CeremonyID, Origin: r.Origin, Response: bytes.Clone(r.Response), ExpectedVersion: 1})
	if err != nil {
		if p.finalization == nil {
			// Before genuine signature verification, protocol/lookup error
			// classes cannot disclose whether the supplied email is eligible.
			// An entered durable finalizer instead retains its real outcome.
			if ctx.Err() != nil {
				return SigninResult{}, ctx.Err()
			}
			return SigninResult{}, identity.ForbiddenError{}
		}
		// Preserve an entered durable outcome without disclosing provisional or
		// historical credentials. Recovery remains command-metadata-only.
		out := p.output
		out.Session.Token, out.Session.Session, out.Session.Cookie = session.Token{}, session.Session{}, http.Cookie{}
		out.CSRF = session.CSRFToken{}
		return out, err
	}
	p.output.CounterRisk = verified.CounterRisk()
	return p.output, nil
}

func (p *signinInvocation) readMapping(ctx context.Context) error {
	c := p.service.config()
	var v string
	err := p.service.pool.Raw().QueryRow(ctx, `SELECT h.user_handle,h.authority_version::text FROM identity_passkey.user_handles h JOIN identity_passkey.relying_parties p USING(rp_namespace) WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(c.Protocol.TenantID), string(p.recipient.User.ID)).Scan(&p.handle, &v)
	if err != nil || len(p.handle) != 32 {
		return identity.ForbiddenError{}
	}
	p.passkey, err = strconv.ParseUint(v, 10, 64)
	if err != nil || p.passkey == 0 || strconv.FormatUint(p.passkey, 10) != v {
		return identity.UnavailableError{}
	}
	// Resident discovery returns no allowlist. Admission only needs active
	// presence; final verification selects one exact credential below. A
	// protocol descriptor-list limit must not disable otherwise valid signin.
	var active bool
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND state='active')`, c.Profile.RPNamespace, string(c.Protocol.TenantID), string(p.recipient.User.ID)).Scan(&active); err != nil {
		return identity.UnavailableError{}
	}
	if !active {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *signinInvocation) selectCredential(ctx context.Context, id []byte) error {
	c := p.service.config()
	var ref, version string
	err := p.service.pool.Raw().QueryRow(ctx, `SELECT reference_id,version::text FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND credential_id=$4 AND state='active'`, c.Profile.RPNamespace, string(c.Protocol.TenantID), string(p.recipient.User.ID), id).Scan(&ref, &version)
	if err != nil {
		return identity.ForbiddenError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != version {
		return identity.UnavailableError{}
	}
	p.reference = identity.CredentialRef{ID: identity.CredentialID(ref), TenantID: c.Protocol.TenantID, UserID: p.recipient.User.ID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: v}
	current, err := p.service.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: c.Protocol.TenantID, UserID: p.recipient.User.ID, CredentialID: p.reference.ID})
	if err != nil || identity.CheckCredentialAuthority(current, p.reference, p.recipient.CredentialAuthorityVersion, c.Clock.Now()) != nil {
		return identity.ForbiddenError{}
	}
	credential, err := p.service.protocol.LoadDiscoverableCredential(ctx, webauthn.Lookup{Context: p.ceremonyContext(), RPID: c.Protocol.RelyingParty.ID}, id, p.handle)
	if err != nil || credential.Version == 0 || !bytes.Equal(credential.UserHandle, p.handle) {
		return identity.ForbiddenError{}
	}
	p.protocolVersion = credential.Version
	return nil
}
