package postgres

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// ManagementConfig selects existing-account label management under one trusted
// tenant/RP and a genuine password-session update proof source. Install the
// password owner's management proof suffix and this adapter's explicitly
// allocated MetadataVersionMigrationSource after its installed mapping/signin history
// before use. Dependencies are borrowed; no pool, goroutine or journal is owned.
// MaximumDuration is 1ms..5s. Request digest keys must remain unchanged for the
// lifetime of the kernel's retained original-request mappings.
type ManagementConfig struct {
	TenantID                         identity.TenantID
	RPNamespace, RPID, ProofAudience string
	Password                         sessionpg.SessionServiceConfig
	Source                           *passwordpg.ActionPrimarySource
	RequestKeys                      kernel.RequestKeyConfig
	RequestTokenKey                  session.DigestKey
	RequestCSRFKey                   session.CSRFKey
	Coordinator                      kernel.CoordinatorConfig
	Authorization                    authorization.Service
	Risk                             *riskpg.Repository
	PolicyID                         string
	PolicyVersion                    uint64
	MaximumDuration                  time.Duration
}

// ManagementService renames only safe credential-reference metadata. Password
// proof consumption, current authority, risk and required effects share the
// existing coordinator Work. Protocol keys/counters and credential authority
// versions are never changed. Concurrent calls borrow immutable configuration.
type ManagementService struct {
	pool      *database.Pool
	config    func() ManagementConfig
	directory *kernel.Repository
	sessions  *session.SessionService
	protocol  *webauthnpg.Store
}

func (ManagementConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.ManagementConfig(redacted)"))
}
func (ManagementService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.ManagementService(redacted)"))
}
func (ManagementConfig) MarshalJSON() ([]byte, error)  { return nil, passkey.ErrPrivateValue }
func (ManagementConfig) MarshalText() ([]byte, error)  { return nil, passkey.ErrPrivateValue }
func (ManagementService) MarshalJSON() ([]byte, error) { return nil, passkey.ErrPrivateValue }
func (ManagementService) MarshalText() ([]byte, error) { return nil, passkey.ErrPrivateValue }

func managementOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: "identity.passkey.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewManagementService freezes native readers and exact update-proof selection
// without IO. Matching historical retries still authenticate the original live
// browser/session; consumed proof metadata is not a renewable execution lease.
func NewManagementService(pool *database.Pool, c ManagementConfig) (*ManagementService, error) {
	if pool == nil || pool.Raw() == nil || c.Source == nil || !c.Source.Matches(managementOperation().OperationID, c.ProofAudience) || c.Authorization == nil || c.Risk == nil || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.PolicyVersion == 0 || c.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || len(c.RPID) == 0 || len(c.RPID) > 253 || c.Password.Profile.AuthenticationMethod != "password" || c.Password.Profile.CredentialKind != identity.CredentialPassword || c.Password.Profile.CredentialOwner != "identity/password" {
		return nil, identity.InvalidInputError{Field: "passkey_management"}
	}
	if _, err := PasskeyAuthorityKey(c.RPNamespace, c.TenantID, "configuration"); err != nil {
		return nil, err
	}
	if _, err := identity.ParseIdentifierID(c.PolicyID); err != nil {
		return nil, err
	}
	if _, err := NewOptionsRequestConfig(c.RequestKeys, c.RequestTokenKey, c.RequestCSRFKey); err != nil {
		return nil, err
	}
	c.Password.Validation.LookupKeys = slices.Clone(c.Password.Validation.LookupKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query := *c.Coordinator.QueryPolicy
	c.Coordinator.QueryPolicy = &query
	admissionPolicy := *c.Coordinator.AdmissionPolicy
	c.Coordinator.AdmissionPolicy = &admissionPolicy
	sessions, err := sessionpg.NewSessionService(pool, c.Password)
	if err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, err
	}
	protocol, err := webauthnpg.New(pool, webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion})
	if err != nil {
		return nil, err
	}
	s := &ManagementService{pool: pool, config: func() ManagementConfig { return c }, directory: directory, sessions: sessions, protocol: protocol}
	if _, _, err := s.runtime(&managementInvocation{service: s}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ManagementService) authenticate(ctx context.Context, r passkey.UpdateRequest) (session.GetResult, session.SessionSpec, error) {
	c := s.config()
	token, err := session.ParseToken(r.Primary.Session.Token())
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	got, err := s.sessions.Get(ctx, session.GetRequest{TenantID: c.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, err
	}
	spec, err := got.Session.Bindings()
	caller, p := r.Primary.Caller, r.Primary.Proof
	if !got.Authenticated || err != nil || got.ValidateAt(c.Password.Validation.Clock.Now().UTC()) != nil || caller.Validate() != nil || uint64(caller.PolicyRevision) != c.PolicyVersion || caller.Request.Tenant != authorization.TenantID(c.TenantID) || caller.Request.Subject.Kind != authorization.SubjectUser || caller.Request.Subject.ID != authorization.SubjectID(spec.UserID) || caller.Request.Action != authorization.Action(managementOperation().OperationID) || caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != authorization.ResourceID(spec.UserID) || p.Proof.Tenant != string(spec.TenantID) || p.Proof.Subject != string(spec.UserID) || p.SessionID != spec.SessionID || p.SessionVersion != spec.Version || p.Action != managementOperation().OperationID || p.Proof.Purpose != "identity.password.verify" || p.Proof.Audience != c.ProofAudience {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	decision, err := c.Authorization.Decide(ctx, caller)
	if ctx.Err() != nil {
		return session.GetResult{}, session.SessionSpec{}, ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != c.PolicyVersion {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	return got, spec, nil
}

// Update admits an exact typed key through the kernel's original-request owner.
// Incoming Primary.CommandID/RecordID must be empty: the server-allocated
// original command is bound before signed-proof preparation. Only an acknowledged
// fresh commit returns safe metadata; retries return historical receipts only.
func (s *ManagementService) Update(ctx context.Context, r passkey.UpdateRequest) (out passkey.UpdateResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Primary.CommandID != "" || r.Primary.RecordID != "" || r.Primary.TargetSubjectID != "" || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || len(r.Network) == 0 || len(r.Network) > 128 {
		return out, identity.InvalidInputError{Field: "passkey_management"}
	}
	if _, err := identity.ParseIdentifierID(string(r.ReferenceID)); err != nil {
		return out, identity.ForbiddenError{}
	}
	if _, err := passkey.NewDeviceLabel(r.Name); err != nil {
		return out, err
	}
	c := s.config()
	if r.Primary.TenantID != c.TenantID {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	read, spec, err := s.authenticate(ctx, r)
	if err != nil {
		return out, err
	}
	intent, err := s.requestIntent(r)
	if err != nil {
		return out, err
	}
	p := &managementInvocation{service: s, request: r, record: spec}
	coordinator, registry, err := s.runtime(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: c.TenantID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: managementOperation().OperationID}
	key, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, optionsRequestCaller(r.Primary.Caller, scope, c.RequestKeys.Policy.PolicyVersion))
	if err != nil {
		return out, err
	}
	p.request.Primary.CommandID = key.CommandID
	p.request.Primary.RecordID = string(r.ReferenceID)
	p.request.Primary.Caller.CorrelationID = string(key.CommandID)
	out.CommandID = key.CommandID
	query := identity.RecoveryQuery{CommandID: key.CommandID, TenantID: c.TenantID, UserID: spec.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: scope.RouteID, RecordID: string(r.ReferenceID)}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, query, r.Primary.Caller)
	out.Outcome = out.Receipt.Outcome
	if err != nil || out.Replayed {
		return s.finishMetadata(ctx, r, read, spec, out, err)
	}
	if err = p.prepare(ctx); err != nil {
		// A contender may consume the shared proof after our initial observation.
		if receipt, replayed, recoveryErr := optionsMetadata(ctx, coordinator, query, r.Primary.Caller); replayed {
			out.Receipt, out.Replayed, out.Outcome = receipt, true, receipt.Outcome
			return s.finishMetadata(ctx, r, read, spec, out, recoveryErr)
		}
		return passkey.UpdateResult{}, err
	}
	out.Receipt, err = p.execute(ctx, coordinator, registry)
	out.Outcome = out.Receipt.Outcome
	if err != nil {
		if receipt, replayed, recoveryErr := optionsMetadata(ctx, coordinator, query, r.Primary.Caller); replayed {
			out.Receipt, out.Replayed, out.Outcome = receipt, true, receipt.Outcome
			return s.finishMetadata(ctx, r, read, spec, out, recoveryErr)
		}
		return out, err
	}
	if out.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Validate() != nil {
		out.Receipt = identity.CommandResult{}
		out.Outcome = identity.CommitOutcomeUnknown
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	if !p.freshCommit {
		out.Replayed = true
		return s.finishMetadata(ctx, r, read, spec, out, nil)
	}
	if err = read.ValidateAt(c.Password.Validation.Clock.Now().UTC()); err != nil || ctx.Err() != nil {
		// Durability is already observed. Expired delivery custody suppresses
		// metadata projection, not the acknowledged original committed outcome.
		return out, identity.UnavailableError{}
	}
	out.Credential = &p.metadata
	return out, nil
}

func (s *ManagementService) finishMetadata(ctx context.Context, r passkey.UpdateRequest, original session.GetResult, spec session.SessionSpec, out passkey.UpdateResult, observedErr error) (passkey.UpdateResult, error) {
	final, current, err := s.authenticate(ctx, r)
	if err != nil || current.SessionID != spec.SessionID || current.Version != spec.Version || original.ValidateAt(s.config().Password.Validation.Clock.Now().UTC()) != nil || final.ValidateAt(s.config().Password.Validation.Clock.Now().UTC()) != nil {
		return passkey.UpdateResult{}, identity.ForbiddenError{}
	}
	return out, observedErr
}

func (s *ManagementService) requestIntent(r passkey.UpdateRequest) (identity.RequestIntent, error) {
	c := s.config()
	token, err := session.ParseToken(r.Primary.Session.Token())
	if err != nil {
		return identity.RequestIntent{}, err
	}
	digest, err := token.Digest(c.RequestTokenKey, string(c.TenantID))
	if err != nil {
		return identity.RequestIntent{}, err
	}
	p := r.Primary.Proof
	fields := []identity.FeatureField{optionsText("management.rp-namespace", c.RPNamespace), optionsText("management.rp-id", c.RPID), optionsText("management.policy", c.PolicyID), optionsUint("management.policy-version", c.PolicyVersion), optionsText("management.reference", string(r.ReferenceID)), optionsUint("management.expected", r.ExpectedVersion), optionsText("management.name", r.Name), optionsText("management.network", r.Network), optionsBytes("management.session", digest.Sum[:]), optionsUint("management.session-key", uint64(digest.KeyVersion)), optionsText("management.proof.id", string(p.Proof.ID)), optionsText("management.proof.tenant", p.Proof.Tenant), optionsText("management.proof.subject", p.Proof.Subject), optionsText("management.proof.method", p.Proof.Method), optionsUint("management.proof.assurance", uint64(p.Proof.Assurance)), optionsText("management.proof.purpose", string(p.Proof.Purpose)), optionsText("management.proof.audience", p.Proof.Audience), optionsText("management.proof.session", p.SessionID), optionsUint("management.proof.version", p.SessionVersion), optionsText("management.proof.action", p.Action), {Name: "management.proof.issued", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.Proof.IssuedAt}}, {Name: "management.proof.expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.Proof.ExpiresAt}}}
	profile := c.Password.Profile
	fields = append(fields, optionsText("management.reader.global", profile.GlobalAuthorityID), optionsText("management.reader.policy", profile.PolicyNamespace), optionsText("management.reader.audience", profile.Audience), optionsText("management.reader.schema", c.Password.Repository.Schema))
	if r.Primary.CSRFToken != (session.CSRFToken{}) {
		csrf, err := r.Primary.CSRFToken.Digest(c.RequestCSRFKey, session.CSRFBinding{TenantID: c.TenantID, SessionID: p.SessionID, SessionVersion: p.SessionVersion})
		if err != nil {
			return identity.RequestIntent{}, err
		}
		binding, err := csrf.Bindings()
		if err != nil {
			return identity.RequestIntent{}, err
		}
		fields = append(fields, optionsBytes("management.csrf", binding.Digest[:]), optionsUint("management.csrf-key", uint64(binding.KeyVersion)))
	}
	return identity.NewRequestIntent(fields)
}
