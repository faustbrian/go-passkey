package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// SessionManagementConfig selects inline UV label management under one real
// current passkey session. It enables neither password-proof management nor a
// separately reusable reauthentication proof. The native owner composes its
// actual session/mapping/factor readers; applications supply no domain store.
// Both phases use the protected update risk policy. Install existing mapping,
// signin-context, metadata-version, request-key and selected owner histories.
// Dependencies are borrowed; MaximumDuration comes from Protocol (1ms..5s).
type SessionManagementConfig struct {
	Protocol          webauthn.Config
	Profile           sessionpg.PasskeyAdmissionConfig
	Validation        session.ServiceConfig
	SessionRepository sessionpg.Config
	OptionsRequests   OptionsRequestConfig
	Coordinator       kernel.CoordinatorConfig
	Authorization     authorization.Service
	Clock             clock.Clock
	Transport         session.CredentialKind
	CSRFKeys          []session.CSRFKey
	Risk              *riskpg.Repository
	PolicyID          string
	PolicyVersion     uint64
}

// SessionManagementService composes actual current-session and WebAuthn owners
// in the sole kernel transaction. Each invocation owns its participants; frozen
// configuration supports concurrent independent calls. No resource lifetime,
// private proof/session store, retry journal or goroutine is introduced.
type SessionManagementService struct {
	pool      *database.Pool
	config    func() SessionManagementConfig
	directory *kernel.Repository
	sessions  *session.SessionService
	authority *SessionAuthority
	protocol  *webauthnpg.Store
}

// Format redacts configuration, keys and deployment correlation.
func (SessionManagementConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SessionManagementConfig(redacted)"))
}

// MarshalJSON prohibits implicit configuration/key export.
func (SessionManagementConfig) MarshalJSON() ([]byte, error) { return nil, passkey.ErrPrivateValue }

// MarshalText prohibits implicit configuration/key export.
func (SessionManagementConfig) MarshalText() ([]byte, error) { return nil, passkey.ErrPrivateValue }

// Format redacts borrowed resources and deployment correlation.
func (SessionManagementService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SessionManagementService(redacted)"))
}

// MarshalJSON prohibits implicit borrowed-owner export.
func (SessionManagementService) MarshalJSON() ([]byte, error) { return nil, passkey.ErrPrivateValue }

// MarshalText prohibits implicit borrowed-owner export.
func (SessionManagementService) MarshalText() ([]byte, error) { return nil, passkey.ErrPrivateValue }

// NewSessionManagementService validates and freezes selected native owners
// without IO. Bearer and cookie are disjoint; cookies require retained original
// CSRF keys, and bearer selection accepts none. The pool must outlive calls.
func NewSessionManagementService(pool *database.Pool, c SessionManagementConfig) (*SessionManagementService, error) {
	invalid := identity.InvalidInputError{Field: "passkey_session_management"}
	if pool == nil || pool.Raw() == nil || c.Clock == nil || c.Authorization == nil || c.Risk == nil || c.OptionsRequests.state == nil || c.PolicyVersion == 0 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.AdmissionPolicy.PolicyVersion != c.PolicyVersion || c.Protocol.MaximumDuration < time.Millisecond || c.Protocol.MaximumDuration > 5*time.Second || c.Validation.MaximumDuration > c.Protocol.MaximumDuration || c.Transport != session.CredentialBearer && c.Transport != session.CredentialCookie || c.Transport == session.CredentialBearer && len(c.CSRFKeys) != 0 || c.Transport == session.CredentialCookie && (len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 4) {
		return nil, invalid
	}
	if _, err := identity.ParseIdentifierID(c.PolicyID); err != nil {
		return nil, invalid
	}
	for i, key := range c.CSRFKeys {
		if key.Version() == 0 || i > 0 && c.CSRFKeys[i-1].Version() <= key.Version() {
			return nil, invalid
		}
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	c.Protocol.RelyingParty.Origins = slices.Clone(c.Protocol.RelyingParty.Origins)
	c.Protocol.Algorithms = slices.Clone(c.Protocol.Algorithms)
	c.Validation.Clock = c.Clock
	c.Validation.LookupKeys = slices.Clone(c.Validation.LookupKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	authority, err := NewSessionAuthority(pool, SessionAuthorityConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: c.Protocol.MaximumDuration})
	if err != nil {
		return nil, err
	}
	sessions, err := sessionpg.NewPasskeySessionService(pool, sessionpg.PasskeySessionServiceConfig{Repository: c.SessionRepository, Profile: c.Profile, Validation: c.Validation, Authority: authority})
	if err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Protocol.MaximumDuration})
	if err != nil {
		return nil, err
	}
	protocol, err := webauthnpg.New(pool, webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion})
	if err != nil {
		return nil, err
	}
	if _, err := webauthn.New(c.Protocol, webauthn.Dependencies{Store: protocol}); err != nil {
		return nil, err
	}
	s := &SessionManagementService{pool: pool, config: func() SessionManagementConfig { return c }, directory: directory, sessions: sessions, authority: authority, protocol: protocol}
	if _, _, err := s.runtime(&sessionUpdateInvocation{service: s}); err != nil {
		return nil, err
	}
	return s, nil
}

func sessionUpdateOperation(finish bool) identity.FeatureOperation {
	schema := "identity.passkey.update.options-v1"
	if finish {
		schema = "identity.passkey.update.assertion-v1"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *SessionManagementService) authenticate(ctx context.Context, r passkey.SessionUpdateRequest) (session.GetResult, session.SessionSpec, error) {
	c := s.config()
	deny := func() (session.GetResult, session.SessionSpec, error) {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	if r.Credential.Kind() != c.Transport || r.Caller.Validate() != nil || uint64(r.Caller.PolicyRevision) != c.PolicyVersion || r.Caller.Request.Tenant != authorization.TenantID(c.Protocol.TenantID) || r.Caller.Request.Subject.Kind != authorization.SubjectUser || r.Caller.Request.Action != "identity.passkey.update" || r.Caller.Request.Resource.Type != "identity.user" {
		return deny()
	}
	got, err := s.sessions.Get(ctx, session.GetRequest{TenantID: c.Protocol.TenantID, Credential: r.Credential})
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, err
	}
	spec, err := got.Session.Bindings()
	if !got.Authenticated || err != nil || got.ValidateAt(c.Clock.Now().UTC()) != nil || r.Caller.Request.Subject.ID != authorization.SubjectID(spec.UserID) || r.Caller.Request.Resource.ID != authorization.ResourceID(spec.UserID) {
		return deny()
	}
	if c.Transport == session.CredentialCookie {
		state := got.Session.CSRFState()
		binding, err := state.Bindings()
		var selected session.CSRFKey
		for _, key := range c.CSRFKeys {
			if key.Version() == binding.KeyVersion {
				selected = key
			}
		}
		if err != nil || selected.Version() == 0 || state.Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, r.CSRFToken, selected) != nil {
			return deny()
		}
	} else if r.CSRFToken != (session.CSRFToken{}) {
		return deny()
	}
	decision, err := c.Authorization.Decide(ctx, r.Caller)
	if ctx.Err() != nil {
		return session.GetResult{}, session.SessionSpec{}, ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != c.PolicyVersion {
		return deny()
	}
	return got, spec, nil
}

func (s *SessionManagementService) prepareRequest(ctx context.Context, r passkey.SessionUpdateRequest, key identity.IdempotencyKey, finish bool, ceremony string, response []byte) (*sessionUpdateInvocation, *kernel.Coordinator, passkey.UpdateResult, error) {
	var out passkey.UpdateResult
	if ctx == nil || s == nil || s.config == nil || key == (identity.IdempotencyKey{}) || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Origin) == 0 || len(r.Origin) > 2048 || len(response) > 262144 {
		return nil, nil, out, identity.InvalidInputError{Field: "passkey_session_update"}
	}
	if _, err := identity.ParseIdentifierID(string(r.ReferenceID)); err != nil {
		return nil, nil, out, identity.ForbiddenError{}
	}
	if _, err := passkey.NewDeviceLabel(r.Name); err != nil {
		return nil, nil, out, err
	}
	if !slices.Contains(s.config().Protocol.RelyingParty.Origins, r.Origin) {
		return nil, nil, out, identity.ForbiddenError{}
	}
	if finish {
		if _, err := identity.ParseCommandID(ceremony); err != nil || len(response) == 0 {
			return nil, nil, out, identity.InvalidInputError{Field: "passkey_update_assertion"}
		}
	}
	read, spec, err := s.authenticate(ctx, r)
	if err != nil {
		return nil, nil, out, err
	}
	p := &sessionUpdateInvocation{service: s, request: r, read: read, record: spec, finish: finish, ceremonyID: ceremony}
	coordinator, _, err := s.runtime(p)
	if err != nil {
		return nil, nil, out, err
	}
	fields, err := optionsProtocolFields(s.config().Protocol, s.config().Profile.RPNamespace, s.config().PolicyID, s.config().PolicyVersion)
	if err != nil {
		return nil, nil, out, err
	}
	digest, err := r.Credential.Digest(s.config().OptionsRequests.state().token, string(spec.TenantID))
	if err != nil {
		return nil, nil, out, err
	}
	fields = append(fields, optionsBytes("update.session", digest.Sum[:]), optionsUint("update.session-key", uint64(digest.KeyVersion)), optionsText("update.reference", string(r.ReferenceID)), optionsUint("update.version", r.ExpectedVersion), optionsText("update.name", r.Name), optionsText("update.origin", r.Origin), optionsText("update.network", r.Network), identity.FeatureField{Name: "update.finish", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: finish}})
	if s.config().Transport == session.CredentialCookie {
		csrf, err := r.CSRFToken.Digest(s.config().OptionsRequests.state().csrf, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
		if err != nil {
			return nil, nil, out, err
		}
		bound, _ := csrf.Bindings()
		fields = append(fields, optionsBytes("update.csrf", bound.Digest[:]), optionsUint("update.csrf-key", uint64(bound.KeyVersion)))
	}
	if finish {
		hash := sha256.Sum256(response)
		fields = append(fields, optionsText("update.ceremony", ceremony), optionsBytes("update.response", hash[:]))
	}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return nil, nil, out, err
	}
	scope := kernel.RequestKeyScope{TenantID: spec.TenantID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.passkey.update"}
	admitted, err := coordinator.ResolveRequestKey(ctx, scope, key, intent, optionsRequestCaller(r.Caller, scope, s.config().OptionsRequests.state().request.Policy.PolicyVersion))
	if err != nil {
		return nil, nil, out, err
	}
	p.id = admitted.CommandID
	out.CommandID = p.id
	record := string(p.id)
	if finish {
		record = string(r.ReferenceID)
	}
	query := identity.RecoveryQuery{CommandID: p.id, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, RecordID: record, OperationID: scope.RouteID}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, query, r.Caller)
	out.Outcome = out.Receipt.Outcome
	return p, coordinator, out, err
}

// UpdateOptions authenticates the current passkey session and creates one
// original action-bound identified UV ceremony. The options key and completion
// key must be distinct: they are different requests to the same protected action.
// A matching retry returns only the original command receipt, never options.
func (s *SessionManagementService) UpdateOptions(ctx context.Context, r passkey.SessionUpdateOptionsRequest) (out passkey.KeyedAssertionOptionsResult, err error) {
	if ctx == nil || s == nil || s.config == nil {
		return out, identity.InvalidInputError{Field: "passkey_session_update"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, _, observed, err := s.prepareRequest(ctx, r.SessionUpdateRequest, r.IdempotencyKey, false, "", nil)
	out.CommandID, out.Receipt, out.Replayed = observed.CommandID, observed.Receipt, observed.Replayed
	if err != nil || observed.Replayed {
		return out, err
	}
	if err := p.prepare(ctx); err != nil {
		return out, err
	}
	protocol, err := webauthn.New(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return out, err
	}
	out.Options, err = protocol.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: p.protocolContext(), UserHandle: p.authProtocol.UserHandle, Origin: r.Origin, AllowedCredentials: [][]byte{p.authProtocol.ID}})
	out.Receipt = p.result
	if err == nil {
		err = p.read.ValidateAt(s.config().Clock.Now().UTC())
	}
	return out, err
}

// Update verifies a fresh genuine UV assertion and atomically consumes its
// ceremony/counter transition with the original label CAS, risk and lifecycle.
// It issues no session or reusable proof. Same-key history returns metadata only.
func (s *SessionManagementService) Update(ctx context.Context, r passkey.SessionUpdateCompletion) (out passkey.UpdateResult, err error) {
	if ctx == nil || s == nil || s.config == nil {
		return out, identity.InvalidInputError{Field: "passkey_session_update"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, _, out, err := s.prepareRequest(ctx, r.SessionUpdateRequest, r.IdempotencyKey, true, r.CeremonyID, r.Response)
	if err != nil || out.Replayed {
		return out, err
	}
	if err := p.prepare(ctx); err != nil {
		return out, err
	}
	protocol, err := webauthn.New(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return out, err
	}
	_, err = protocol.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: p.protocolContext(), CeremonyID: r.CeremonyID, Origin: r.Origin, Response: r.Response, ExpectedVersion: 1, ExpectedCredentialVersion: p.authProtocol.Version})
	out.Receipt, out.Outcome = p.result, p.result.Outcome
	if err != nil {
		return out, err
	}
	if err := p.read.ValidateAt(s.config().Clock.Now().UTC()); err != nil || ctx.Err() != nil {
		return out, identity.UnavailableError{}
	}
	metadata := p.metadata
	metadata.Label, metadata.Version = r.Name, r.ExpectedVersion+1
	out.Credential = &metadata
	return out, nil
}
