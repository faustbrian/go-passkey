package postgres

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// SignupConfig selects prospective passkey-only signup in one trusted tenant
// and RP. No email, password or caller-selected user is accepted. Flow.Action
// must be identity.passkey.register-verify. Risk and Counters must share the
// canonical protected registration policy; no signup-specific relaxation exists.
// Dependencies are borrowed/concurrency-safe and must outlive calls. Install
// SignupMigrationSource and all selected kernel/protocol/MFA/session histories.
// Construction performs no IO, entropy, migration or background work.
type SignupConfig struct {
	Protocol        webauthn.Config
	Profile         sessionpg.PasskeyAdmissionConfig
	Coordinator     kernel.CoordinatorConfig
	Authorization   authorization.Service
	Clock           clock.Clock
	Flow            session.PreAuthIssuerConfig
	Session         session.IssuerConfig
	CSRF            session.CSRFKey
	Repository      sessionpg.Config
	Risk            risk.ProtectedProviderAdmissionCustodyConfig
	Counters        riskpg.Config
	OptionsRequests OptionsRequestConfig
}

// SignupService composes genuine WebAuthn registration with original pre-auth,
// risk, account, credential, policy/factors, mapping and session owners in one
// Work. It starts no goroutine and owns no pool or independent journal. Zero
// denies; concurrent requests use distinct private invocations. Preparing
// options creates no identity, stable handle, credential or authenticated session.
type SignupService struct {
	core            *SigninService
	domain          *kernel.PasskeyRegistrationDomain
	effect          *sessionpg.PasskeySignupEffect
	risk            risk.ProtectedProviderAdmissionCustody
	counters        *riskpg.Repository
	evaluation      risk.Evaluator
	optionsRequests OptionsRequestConfig
}

// Format redacts trusted configuration and borrowed owner references.
func (SignupConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SignupConfig(redacted)"))
}

// MarshalJSON prohibits implicit configuration or credential transport.
func (SignupConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit configuration or credential transport.
func (SignupConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts borrowed runtime owners and correlated configuration.
func (SignupService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SignupService(redacted)"))
}

// NewSignupService explicitly selects signup without enabling enrollment,
// identified signin, HTTP routes or recovery methods. Original remember/expiry
// comes exclusively from the session-owned browser flow, not completion input.
func NewSignupService(pool *database.Pool, c SignupConfig) (*SignupService, error) {
	if c.Counters.CommandCounters == nil || !c.Counters.EnforceLockouts || c.Counters.PolicyVersion != c.Flow.PolicyVersion {
		return nil, identity.InvalidInputError{Field: "passkey_signup_risk"}
	}
	custody, err := risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil || custody.ValidateCounterPolicy(c.Counters.CommandCounters.Policy) != nil {
		return nil, identity.InvalidInputError{Field: "passkey_signup_risk"}
	}
	counters, err := riskpg.NewRepository(c.Counters)
	if err != nil {
		return nil, err
	}
	core, err := newSigninRuntime(pool, SigninConfig{Protocol: c.Protocol, Profile: c.Profile, Coordinator: c.Coordinator, Authorization: c.Authorization, Clock: c.Clock, Flow: c.Flow, Session: c.Session, CSRF: c.CSRF, Repository: c.Repository}, true)
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewPasskeyRegistrationDomain(core.directory)
	if err != nil {
		return nil, err
	}
	authority, err := NewSessionAuthority(pool, SessionAuthorityConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: c.Protocol.MaximumDuration})
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewPasskeySignupEffect(c.Repository, c.Profile, authority)
	if err != nil {
		return nil, err
	}
	s := &SignupService{core: core, domain: domain, effect: effect, risk: custody, counters: counters, evaluation: c.Risk.Evaluation, optionsRequests: c.OptionsRequests}
	if c.OptionsRequests.state != nil {
		p := &signupInvocation{Store: core.protocol, service: s, operation: signupOperation(false)}
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

func signupOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.register-options"
	if finish {
		id = "identity.passkey.register-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// PrepareFlow delegates original entropy/time/remember custody to the session
// owner. Retain the preparation unchanged for IssueFlow; do not prepare retries.
func (s *SignupService) PrepareFlow(i session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	if s == nil || s.core == nil {
		return session.PreparedPreAuthIssuance{}, identity.ForbiddenError{}
	}
	return s.core.PrepareFlow(i)
}

// IssueFlow commits only the original unauthenticated browser flow/cookie.
func (s *SignupService) IssueFlow(ctx context.Context, p session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	if s == nil || s.core == nil {
		return session.PreAuthIssueResult{}, identity.ForbiddenError{}
	}
	return s.core.IssueFlow(ctx, p)
}

func (s *SignupService) prepare(ctx context.Context, r passkey.SignupRequest, finish bool) (*signupInvocation, error) {
	if s == nil || s.core == nil || ctx == nil {
		return nil, identity.ForbiddenError{}
	}
	base, err := s.core.prepareFlow(ctx, SigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID}, finish, true)
	if err != nil {
		return nil, err
	}
	if err := base.prepareDirectory(ctx); err != nil {
		return nil, err
	}
	p := &signupInvocation{Store: s.core.protocol, service: s, request: r, operation: signupOperation(finish), flow: base.flow, cookie: base.cookie, directory: base.directory}
	return p, nil
}

// RegistrationOptions commits original session/browser/risk admission and a
// genuine resident-required UV/none ceremony in the selected ES256/Ed25519
// profile. The opaque prospective user
// and handle remain bounded intent only; no durable account or mapping exists.
func (s *SignupService) RegistrationOptions(ctx context.Context, r passkey.SignupRequest) (webauthn.RegistrationOptions, error) {
	if s == nil || s.core == nil || ctx == nil {
		return webauthn.RegistrationOptions{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, s.core.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepare(ctx, r, false)
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	user, err := identity.NewSubjectID()
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	p.user = identity.UserID(user)
	handle, err := (passkey.UserHandlePolicy{}).Generate(ctx)
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	p.handle, err = handle.Bytes()
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	if err := p.prepareRisk(ctx); err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	protocol, err := webauthn.New(s.core.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	return protocol.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: p.ceremonyContext(), Origin: r.Origin, UserHandle: bytes.Clone(p.handle), ResidentKeyRequired: true})
}

// Signup verifies the real original authenticator before creating the account
// and all required effects atomically. Only a newly acknowledged commit reveals
// bearer/CSRF; ambiguity/replay/failure returns no historical credential.
func (s *SignupService) Signup(ctx context.Context, r passkey.SignupCompletion) (passkey.SignupResult, error) {
	if s == nil || s.core == nil || ctx == nil || len(r.CeremonyID) != 22 || len(r.Response) == 0 || len(r.Response) > 262144 {
		return passkey.SignupResult{}, identity.InvalidInputError{Field: "passkey_signup"}
	}
	ctx, stop := context.WithTimeout(ctx, s.core.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepare(ctx, r.SignupRequest, true)
	if err != nil {
		return passkey.SignupResult{}, err
	}
	label, err := passkey.NewDeviceLabel(r.Label)
	if err != nil && r.Label != "" {
		return passkey.SignupResult{}, err
	}
	p.label = label.Value()
	p.ceremonyID = r.CeremonyID
	if err := p.readContext(ctx); err != nil {
		return passkey.SignupResult{}, err
	}
	if err := p.prepareRisk(ctx); err != nil {
		return passkey.SignupResult{}, err
	}
	protocol, err := webauthn.New(s.core.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return passkey.SignupResult{}, err
	}
	_, err = protocol.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: p.ceremonyContext(), CeremonyID: r.CeremonyID, Origin: r.Origin, Response: bytes.Clone(r.Response), ExpectedVersion: 1})
	if err != nil {
		out := p.output
		out.Session.Token, out.Session.Session, out.Session.Cookie = session.Token{}, session.Session{}, http.Cookie{}
		out.CSRF = session.CSRFToken{}
		if p.finalization == nil && ctx.Err() == nil {
			err = identity.ForbiddenError{}
		}
		return out, err
	}
	return p.output, nil
}
