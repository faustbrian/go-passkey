package postgres

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// EnrollmentConfig selects existing-account, known-empty-MFA, resident-required
// UV/none/ES256 enrollment. Each phase has its exact signed fresh-action source;
// no boolean freshness or application domain store can replace it. Dependencies
// are borrowed and must outlive calls. The native risk owner charges protected
// attempts through this command, not a separate workflow. Apply the actual
// kernel/password/MFA/risk/WebAuthn/audit/outbox and passkey histories first.
type EnrollmentConfig struct {
	// OptionsRequests explicitly enables the additive keyed options API only.
	OptionsRequests                   OptionsRequestConfig
	Protocol                          webauthn.Config
	RPNamespace                       string
	Coordinator                       kernel.CoordinatorConfig
	Authorization                     authorization.Service
	OptionsSource, RegistrationSource *passwordpg.ActionPrimarySource
	Risk                              *riskpg.Repository
	PolicyID                          string
	PolicyVersion                     uint64
}

// RegistrationRequest is the adapter-neutral passkey data contract.
type RegistrationRequest = passkey.RegistrationRequest

// RegistrationCompletion is the adapter-neutral passkey data contract.
type RegistrationCompletion = passkey.RegistrationCompletion

// EnrollmentService owns real protocol/fresh-proof/mapping composition through
// the existing coordinator. It starts no goroutines, owns no pool lifetime and
// supports concurrent calls through invocation-private participants. It does
// not expose passkey-first registration, MFA fallback or credential management.
type EnrollmentService struct {
	pool      *database.Pool
	config    func() EnrollmentConfig
	directory *kernel.Repository
	protocol  *webauthnpg.Store
}

// Format prevents borrowed scope, keys and proof-source diagnostics.
func (EnrollmentConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.EnrollmentConfig(redacted)"))
}

// Format prevents borrowed infrastructure/configuration disclosure.
func (EnrollmentService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.EnrollmentService(redacted)"))
}

// NewEnrollmentService validates trusted owned dependencies without IO. It
// fixes the RP/profile before browser input; disabled/unsupported variants have
// no path through this service. No callback supplies missing orchestration.
func NewEnrollmentService(pool *database.Pool, c EnrollmentConfig) (*EnrollmentService, error) {
	if pool == nil || pool.Raw() == nil || c.Authorization == nil || c.OptionsSource == nil || c.RegistrationSource == nil || c.Risk == nil || c.PolicyVersion == 0 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.Protocol.MaximumDuration < time.Millisecond || c.Protocol.MaximumDuration > 5*time.Second {
		return nil, identity.InvalidInputError{Field: "passkey_enrollment"}
	}
	if _, err := PasskeyAuthorityKey(c.RPNamespace, c.Protocol.TenantID, "validation"); err != nil {
		return nil, err
	}
	if _, err := identity.ParseIdentifierID(c.PolicyID); err != nil {
		return nil, err
	}
	if c.Protocol.Algorithms != nil && (len(c.Protocol.Algorithms) != 1 || c.Protocol.Algorithms[0] != webauthn.ES256) {
		return nil, identity.InvalidInputError{Field: "passkey_algorithms"}
	}
	c.Protocol.RelyingParty.Origins = slices.Clone(c.Protocol.RelyingParty.Origins)
	c.Protocol.Algorithms = slices.Clone(c.Protocol.Algorithms)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query := *c.Coordinator.QueryPolicy
	c.Coordinator.QueryPolicy = &query
	protocol, err := webauthnpg.New(pool, webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion})
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
	s := &EnrollmentService{pool: pool, config: func() EnrollmentConfig { return c }, directory: directory, protocol: protocol}
	if c.OptionsRequests.state != nil {
		p := &enrollmentInvocation{Store: protocol, service: s, source: c.OptionsSource, operation: enrollmentOperation(false)}
		_, registry, err := s.runtime(p)
		if err != nil {
			return nil, err
		}
		if _, err := kernel.NewCoordinatorWithRequestKeys(pool, registry, c.Coordinator, c.OptionsRequests.state().request); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func enrollmentOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.register-options"
	if finish {
		id = "identity.passkey.register-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *EnrollmentService) preparePrimary(ctx context.Context, r RegistrationRequest, finish bool) (*enrollmentInvocation, error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil {
		return nil, identity.InvalidInputError{Field: "passkey_enrollment"}
	}
	c := s.config()
	op := enrollmentOperation(finish)
	if r.Primary.TenantID != c.Protocol.TenantID || r.Primary.TargetSubjectID != "" || r.Primary.Caller.Validate() != nil || r.Primary.Caller.Request.Action != authorization.Action(op.OperationID) || r.Primary.Caller.Request.Tenant != authorization.TenantID(c.Protocol.TenantID) || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Device) > 128 || len(r.Origin) > 2048 {
		return nil, identity.ForbiddenError{}
	}
	r.Primary.RecordID = string(r.Primary.CommandID)
	source := c.OptionsSource
	if finish {
		source = c.RegistrationSource
	}
	if !source.Matches(op.OperationID, r.Primary.Proof.Proof.Audience) {
		return nil, identity.ForbiddenError{}
	}
	admission, err := source.Prepare(ctx, r.Primary)
	if err != nil {
		return nil, err
	}
	original, err := admission.Original()
	if err != nil {
		return nil, err
	}
	record, err := original.Bindings()
	if err != nil || string(r.Primary.Caller.Request.Subject.ID) != string(record.UserID) || r.Primary.Caller.Request.Subject.Kind != authorization.SubjectUser {
		return nil, identity.ForbiddenError{}
	}
	allowed, err := c.Authorization.Decide(ctx, r.Primary.Caller)
	if err != nil || allowed.Outcome != authorization.Allow || uint64(allowed.Revision) != c.PolicyVersion {
		return nil, identity.ForbiddenError{}
	}
	return &enrollmentInvocation{Store: s.protocol, service: s, request: r, source: source, admission: admission, original: original, record: record, operation: op}, nil
}

func (s *EnrollmentService) prepare(ctx context.Context, r RegistrationRequest, finish bool) (*enrollmentInvocation, error) {
	p, err := s.preparePrimary(ctx, r, finish)
	if err != nil {
		return nil, err
	}
	c := s.config()
	factorBudget := min(c.Protocol.MaximumDuration, 5*time.Second)
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.pool, p.record.TenantID, p.record.UserID, factorBudget)
	if err != nil || enrolled {
		return nil, identity.ForbiddenError{}
	}
	vector, err := p.record.Authority.Bindings()
	if err != nil || vector.Organization.Present || vector.Passkey.Present {
		return nil, identity.ForbiddenError{}
	}
	var handle []byte
	var authority string
	err = s.pool.Raw().QueryRow(ctx, `SELECT user_handle,authority_version::text FROM identity_passkey.user_handles WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3`, c.RPNamespace, string(p.record.TenantID), string(p.record.UserID)).Scan(&handle, &authority)
	version := uint64(1)
	if err != nil {
		if !isAbsent(err) {
			return nil, identity.UnavailableError{}
		}
		generated, err := (passkey.UserHandlePolicy{}).Generate(ctx)
		if err != nil {
			return nil, err
		}
		handle, err = generated.Bytes()
		if err != nil {
			return nil, err
		}
	} else {
		version, err = strconv.ParseUint(authority, 10, 64)
		if err != nil || version == 0 || len(handle) != 32 || strconv.FormatUint(version, 10) != authority {
			return nil, identity.UnavailableError{}
		}
	}
	p.handle, p.authorityVersion, p.factorVersion = handle, version, factor
	p.epochs = kernel.UserAuthorityAdmission{UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version}
	return p, nil
}

// RegistrationOptions authenticates a genuine existing session and exact fresh
// enrollment proof before emitting a committed resident-required UV ceremony.
// The browser challenge is reveal-once; replay/unknown never generates another.
func (s *EnrollmentService) RegistrationOptions(ctx context.Context, r RegistrationRequest) (webauthn.RegistrationOptions, error) {
	if ctx == nil {
		return webauthn.RegistrationOptions{}, identity.InvalidInputError{Field: "context"}
	}
	if s == nil || s.config == nil {
		return webauthn.RegistrationOptions{}, identity.UnavailableError{}
	}
	bounded, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepare(bounded, r, false)
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	rows, err := s.pool.Raw().Query(bounded, `SELECT credential_id FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND state='active' ORDER BY reference_id LIMIT 101`, s.config().RPNamespace, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return webauthn.RegistrationOptions{}, identity.UnavailableError{}
	}
	var excluded [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil || len(id) == 0 || len(id) > 1024 || len(excluded) >= 100 {
			rows.Close()
			return webauthn.RegistrationOptions{}, identity.UnavailableError{}
		}
		excluded = append(excluded, bytes.Clone(id))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return webauthn.RegistrationOptions{}, identity.UnavailableError{}
	}
	protocol, err := webauthn.New(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	return protocol.BeginRegistration(bounded, webauthn.BeginRegistrationRequest{Context: p.ceremonyContext(), UserHandle: bytes.Clone(p.handle), Origin: r.Origin, ExcludedCredentials: excluded, ResidentKeyRequired: true})
}

// Register verifies the browser response with the real protocol owner, then
// atomically consumes ceremony/proof and persists mapping/kernel reference plus
// required lifecycle/audit effects. It returns no credential on ambiguous or
// historical outcomes and never issues a session for authenticated enrollment.
func (s *EnrollmentService) Register(ctx context.Context, r RegistrationCompletion) (webauthn.VerifiedRegistration, error) {
	if s == nil || s.config == nil || ctx == nil || len(r.Response) == 0 || len(r.Response) > 262144 || len(r.CeremonyID) != 22 || len(r.Label) > 128 {
		return webauthn.VerifiedRegistration{}, identity.InvalidInputError{Field: "passkey_registration"}
	}
	if r.Label != "" {
		if _, err := passkey.NewDeviceLabel(r.Label); err != nil {
			return webauthn.VerifiedRegistration{}, err
		}
	}
	bounded, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepare(bounded, r.RegistrationRequest, true)
	if err != nil {
		return webauthn.VerifiedRegistration{}, err
	}
	p.label = r.Label
	protocol, err := webauthn.New(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return webauthn.VerifiedRegistration{}, err
	}
	return protocol.VerifyRegistration(bounded, webauthn.VerifyRegistrationRequest{Context: p.ceremonyContext(), CeremonyID: r.CeremonyID, Origin: r.Origin, Response: bytes.Clone(r.Response), ExpectedVersion: 1})
}

// enrollmentPlan uses the existing audit/outbox owners, not a private receipt.
func enrollmentPlan(p *enrollmentInvocation, registry *kernel.ContributorRegistry, coordinator *kernel.Coordinator, command identity.Command) (kernel.CommandPlan, error) {
	b := p.binding()
	life := "passkey.registration-options.created.v1"
	action := p.operation.OperationID
	if p.finalization != nil {
		life = "identity.passkey.create_credential"
		action = life
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation, "passkey", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation}, CommandCounters: p.counters, Lifecycle: &kernel.LifecyclePlan{EventType: life, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}})
}

func (s *EnrollmentService) runtime(p *enrollmentInvocation) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, l, s.config().Risk, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, r, s.config().Coordinator)
	return coordinator, r, err
}

// The risk.Subject remains trusted ingress, never browser-selected authority.
func (p *enrollmentInvocation) riskSubject() risk.Subject {
	return risk.Subject{User: string(p.record.UserID), Network: p.request.Network, Session: p.record.SessionID}
}
