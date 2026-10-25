package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// Participants and opaque verifier transitions belong to one serial invocation.
// Shared configuration is immutable; no pending-work map or goroutine exists.
type sessionEnrollmentInvocation struct {
	*webauthnpg.Store
	service                      *SessionEnrollmentService
	request                      passkey.SessionEnrollmentRequestSpec
	read                         session.GetResult
	record                       session.SessionSpec
	id                           identity.CommandID
	stage                        int
	ceremonyID                   string
	authProtocol                 webauthn.Credential
	sourceFields                 []identity.FeatureField
	contextDigest, requestDigest [32]byte
	parent                       sessionEnrollmentContext
	ceiling                      time.Time
	assertion                    webauthn.AssertionTransition
	creation                     *webauthnpg.EnrollmentAssertionCreation
	authorization                *webauthnpg.EnrollmentAuthorization
	finalization                 *webauthnpg.SessionRegistrationFinalization
	registrationOptions          webauthn.RegistrationOptions
	mutation                     webauthn.RegistrationMutation
	metadata                     passkey.CredentialMetadata
	command                      identity.Command
	result                       identity.CommandResult
}

type sessionEnrollmentParticipant interface {
	Fields() ([]identity.FeatureField, error)
	Validate(identity.Command, kernel.CommandPlan) error
	Apply(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
}

func (*sessionEnrollmentInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*sessionEnrollmentInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{sessionEnrollmentOperation(0), sessionEnrollmentOperation(1), sessionEnrollmentOperation(2)}
}
func (p *sessionEnrollmentInvocation) protocolContext() webauthn.CeremonyContext {
	return webauthn.CeremonyContext{CommandID: p.id, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), CorrelationID: string(p.id)}
}
func (p *sessionEnrollmentInvocation) binding() identity.CommandBinding {
	op := sessionEnrollmentOperation(p.stage)
	c := p.service.owner.config()
	return identity.CommandBinding{CommandID: p.id, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), ActorKind: authorization.SubjectUser, RecordID: string(p.id), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: string(p.id)}
}
func (p *sessionEnrollmentInvocation) participant() sessionEnrollmentParticipant {
	if p.creation != nil {
		return p.creation
	}
	if p.authorization != nil {
		return p.authorization
	}
	if p.finalization != nil {
		return p.finalization
	}
	return nil
}
func (s *SessionEnrollmentService) runtime(p *sessionEnrollmentInvocation) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	p.Store = s.owner.protocol
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	o, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.owner.directory, a, o, s.owner.config().Risk, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.owner.pool, registry, s.owner.config().Coordinator, s.owner.config().OptionsRequests.state().request)
	return coordinator, registry, err
}

func (p *sessionEnrollmentInvocation) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	i, err := input.Intent()
	if err != nil || i.Context != p.protocolContext() || !bytes.Equal(i.UserHandle, p.authProtocol.UserHandle) || p.stage > 1 {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	if p.stage == 0 {
		if i.Kind != "get" || len(i.AllowedCredentials) != 1 || !bytes.Equal(i.AllowedCredentials[0], p.authProtocol.ID) {
			return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
		}
		p.creation, err = p.service.owner.protocol.EnrollmentAssertionCreation(input)
		if err != nil {
			return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
		}
		defer p.creation.Discard()
	} else {
		if i.Kind != "create" || !i.ResidentKeyRequired {
			return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
		}
		p.authorization, err = p.service.owner.protocol.EnrollmentAuthorization(p.assertion, input)
		if err != nil {
			return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
		}
		defer p.authorization.Discard()
		p.ceiling = p.authorization.AuthorizationExpiresAt()
		if p.ceiling.IsZero() {
			return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
		}
	}
	fields, err := p.participant().Fields()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	result, err := p.execute(ctx, fields)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, err
	}
	if p.stage == 0 {
		r, ch, err := p.creation.Result(result)
		return r, ch, result.Outcome, err
	}
	r, ch, _, err := p.authorization.Result(result)
	return r, ch, result.Outcome, err
}

func (p *sessionEnrollmentInvocation) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, err := input.Mutation()
	if p.stage != 1 || err != nil || m.Context != p.protocolContext() || m.Ceremony.ID != p.ceremonyID || !bytes.Equal(m.Before.ID, p.authProtocol.ID) || m.Before.Version != p.authProtocol.Version || m.CounterRisk {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	p.assertion = input
	excluded, err := p.excludedCredentials(ctx)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	protocol, err := webauthn.New(p.service.owner.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.registrationOptions, err = protocol.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: p.protocolContext(), UserHandle: p.authProtocol.UserHandle, Origin: p.request.Origin, ExcludedCredentials: excluded, ResidentKeyRequired: true})
	if err != nil {
		return webauthn.Credential{}, p.result.Outcome, err
	}
	return m.After, p.result.Outcome, nil
}

func (p *sessionEnrollmentInvocation) excludedCredentials(ctx context.Context) ([][]byte, error) {
	c := p.service.owner.config()
	rows, err := p.service.owner.pool.Raw().Query(ctx, `SELECT credential_id FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND state='active' ORDER BY reference_id LIMIT 101`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer rows.Close()
	var ids [][]byte
	for rows.Next() {
		var id []byte
		if rows.Scan(&id) != nil || len(id) == 0 || len(id) > 1024 || len(ids) >= 100 {
			return nil, identity.UnavailableError{}
		}
		ids = append(ids, bytes.Clone(id))
	}
	if rows.Err() != nil || len(ids) == 0 {
		return nil, identity.UnavailableError{}
	}
	return ids, nil
}

func (p *sessionEnrollmentInvocation) FinalizeRegistration(ctx context.Context, input webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, err := input.Mutation()
	if p.stage != 2 || err != nil || m.Context != p.protocolContext() || m.Ceremony.ID != p.ceremonyID || m.Credential.TenantID != p.record.TenantID || m.Credential.UserID != p.record.UserID || !bytes.Equal(m.Credential.UserHandle, p.authProtocol.UserHandle) {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	p.mutation = m
	p.finalization, err = p.service.owner.protocol.SessionRegistrationFinalization(input)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	fields, err := p.finalization.Fields()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	refFields, err := kernel.PasskeyCredentialCreationFields(p.reference(), p.epochs())
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	result, err := p.execute(ctx, append(fields, refFields...))
	if err != nil {
		return webauthn.Credential{}, result.Outcome, err
	}
	credential, err := p.finalization.Result(result)
	return credential, result.Outcome, err
}

func (p *sessionEnrollmentInvocation) epochs() kernel.UserAuthorityAdmission {
	v, _ := p.record.Authority.Bindings()
	return kernel.UserAuthorityAdmission{UserAuthorityVersion: v.User.Version, IdentifierAuthorityVersion: v.Identifier.Version, CredentialAuthorityVersion: v.Credential.Version}
}
func (p *sessionEnrollmentInvocation) reference() identity.CredentialRef {
	return identity.CredentialRef{ID: identity.CredentialID(p.id), TenantID: p.record.TenantID, UserID: p.record.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}
}

func (p *sessionEnrollmentInvocation) execute(ctx context.Context, fields []identity.FeatureField) (result identity.CommandResult, err error) {
	defer func() { p.result = result }()
	c := p.service.owner.config()
	fields = append(fields, p.sourceFields...)
	fields = append(fields, optionsBytes("passkey.enrollment.context", p.contextDigest[:]), optionsBytes("passkey.enrollment.request", p.requestDigest[:]), optionsText("passkey.enrollment.label", p.request.Label))
	if p.stage > 0 {
		fields = append(fields, optionsText("passkey.enrollment.parent", p.ceremonyID))
	}
	if p.stage > 0 && !p.ceiling.IsZero() {
		fields = append(fields, identity.FeatureField{Name: "passkey.enrollment.authorization-expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.ceiling}})
	}
	op := sessionEnrollmentOperation(p.stage)
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding(), Operation: op, Fields: fields})
	if err != nil {
		return result, err
	}
	var now time.Time
	if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return result, identity.UnavailableError{}
	}
	command, counters, err := c.Risk.PrepareCommandCounters(command, risk.Subject{User: string(p.record.UserID), Network: p.request.Network, Session: p.record.SessionID}, now.UTC())
	if err != nil {
		return result, err
	}
	p.command = command
	coordinator, registry, err := p.service.runtime(p)
	if err != nil {
		return result, err
	}
	event := []string{"passkey.reauthentication.started.v1", "passkey.registration.started.v1", "identity.passkey.create_credential"}[p.stage]
	life := kernel.LifecyclePlan{EventType: event, AfterVersion: 1}
	b := p.binding()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return result, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now.UTC(), Action: event, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return result, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "passkey", seed)
	if err != nil {
		return result, err
	}
	plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &life, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: event, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}})
	if err != nil {
		return result, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	if p.stage < 2 {
		if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: b.CommandID}
		}
		if p.stage == 0 {
			err = p.creation.Generate(ctx, now.UTC())
		} else {
			err = p.authorization.Generate(ctx, now.UTC())
		}
		if err != nil {
			return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, err
		}
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, err
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	result, err = coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return coordinator.Abort(work, err)
	}
	return coordinator.Commit(work, result)
}

func (p *sessionEnrollmentInvocation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || p.participant() == nil {
		return identity.ForbiddenError{}
	}
	return p.participant().Validate(c, plan)
}

func (p *sessionEnrollmentInvocation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || p.participant() == nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.stage > 0 {
		if err := p.checkParent(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.participant().Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.stage == 2 {
		if err := w.CreatePasskeyCredential(ctx, p, c, p.reference(), p.epochs()); err != nil {
			return identity.FeatureReceipt{}, err
		}
		var label any
		if p.request.Label != "" {
			label = p.request.Label
		}
		rows, err := w.Query(ctx, `INSERT INTO identity_passkey.credentials(rp_namespace,tenant_id,user_id,reference_id,credential_id,version,state,display_label,created_at) VALUES($1,$2,$3,$4,$5,1,'active',$6,clock_timestamp()) RETURNING created_at`, p.service.owner.config().Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.id), p.mutation.Credential.ID, label)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		var created time.Time
		valid := rows.Next() && rows.Scan(&created) == nil && !rows.Next() && rows.Err() == nil
		rows.Close()
		if !valid {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		p.metadata = passkey.CredentialMetadata{ReferenceID: string(p.id), Version: 1, Label: p.request.Label, State: "active", CreatedAt: created.UTC(), AAGUID: p.mutation.Credential.AAGUID, BackupEligible: p.mutation.Credential.BackupEligible, BackupState: p.mutation.Credential.BackupState}
	}
	if err := p.writeContext(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: sessionEnrollmentOperation(p.stage), AfterVersion: 1}, nil
}

func (p *sessionEnrollmentInvocation) current(ctx context.Context, w kernel.Work) error {
	c := p.service.owner.config()
	if err := p.read.ValidateAt(c.Clock.Now().UTC()); err != nil {
		return err
	}
	admission := sessionpg.OriginalPasskeySessionAdmission
	if c.TOTP {
		admission = sessionpg.OriginalMFAPasskeySessionAdmission
	}
	directory, credential, policy, err := admission(c.Profile, p.read.Session, p.binding())
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, c.SessionRepository, p.read.Session); err != nil {
		return err
	}
	var factorErr error
	if c.TOTP {
		factorErr = mfapg.RequireMFAPasskeySessionFactors(ctx, w, p, p.read.Session)
	} else {
		factorErr = mfapg.RequirePasskeySessionFactors(ctx, w, p, p.read.Session)
	}
	if factorErr != nil {
		return factorErr
	}
	// Keep native mapping mutations' existing factor -> RP/handle -> credential
	// lock order. Serializing this existing mapping root prevents competing
	// enrollment from promoting a newer handle generation during this command.
	rows, err := w.Query(ctx, `SELECT h.authority_version::text,h.user_handle FROM identity_passkey.relying_parties r JOIN identity_passkey.user_handles h USING(rp_namespace) WHERE r.rp_namespace=$1 AND r.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4 FOR UPDATE OF r,h`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return err
	}
	var version string
	var handle []byte
	v, _ := p.record.Authority.Bindings()
	valid := rows.Next() && rows.Scan(&version, &handle) == nil && !rows.Next() && rows.Err() == nil && version == strconv.FormatUint(v.Passkey.Binding.Version, 10) && bytes.Equal(handle, p.authProtocol.UserHandle)
	rows.Close()
	if !valid {
		return identity.ForbiddenError{}
	}
	var mappingErr error
	if c.TOTP {
		mappingErr = p.service.owner.authority.RequireMFAPasskeySession(ctx, w, p, c.Profile.RPNamespace, p.read.Session)
	} else {
		mappingErr = p.service.owner.authority.RequirePasskeySession(ctx, w, p, c.Profile.RPNamespace, p.read.Session)
	}
	if mappingErr != nil {
		return mappingErr
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || p.read.ValidateAt(now.UTC()) != nil || !p.ceiling.IsZero() && !now.Before(p.ceiling) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *sessionEnrollmentInvocation) context() sessionEnrollmentContext {
	return sessionEnrollmentContext{Stage: p.stage, Digest: p.contextDigest, RequestDigest: p.requestDigest, AuthenticationVersion: p.authProtocol.Version, Parent: p.ceremonyID, AuthorizationExpires: p.ceiling}
}
func (p *sessionEnrollmentInvocation) writeContext(ctx context.Context, w kernel.Work) error {
	wire, err := json.Marshal(p.context())
	if err != nil || len(wire) > 4096 {
		return identity.UnavailableError{}
	}
	c := p.service.owner.config()
	n, err := w.Exec(ctx, `INSERT INTO identity_passkey.signin_contexts(rp_namespace,ceremony_id,tenant_id,user_id,admission) VALUES($1,$2,$3,$4,$5)`, c.Profile.RPNamespace, string(p.id), string(p.record.TenantID), string(p.record.UserID), wire)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *sessionEnrollmentInvocation) checkContext(ctx context.Context, w kernel.Work, id string, expected sessionEnrollmentContext) error {
	wire, err := json.Marshal(expected)
	if err != nil {
		return identity.UnavailableError{}
	}
	c := p.service.owner.config()
	rows, err := w.Query(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4 FOR SHARE`, c.Profile.RPNamespace, id, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var retained []byte
	if !rows.Next() || rows.Scan(&retained) != nil || rows.Next() || rows.Err() != nil || !bytes.Equal(retained, wire) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *sessionEnrollmentInvocation) checkParent(ctx context.Context, w kernel.Work) error {
	return p.checkContext(ctx, w, p.ceremonyID, p.parent)
}

func (p *sessionEnrollmentInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || p.participant() == nil {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	if p.stage > 0 {
		if err := p.checkParent(ctx, w); err != nil {
			return err
		}
	}
	if err := p.checkContext(ctx, w, string(p.id), p.context()); err != nil {
		return err
	}
	if err := p.participant().Check(ctx, w, p, c); err != nil {
		return err
	}
	if p.stage == 2 {
		a := p.epochs()
		_, err := w.RequireActiveCredential(ctx, p, kernel.CredentialAdmission{Credential: p.reference(), UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion})
		return err
	}
	return nil
}

func (p *sessionEnrollmentInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.owner.protocol.RecoverEnrollment(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return status, err
	}
	b, feature, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	c := p.service.owner.config()
	query := `SELECT 1 FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND ceremony_id=$4`
	if feature.Operation == sessionEnrollmentOperation(2) {
		query = `SELECT 1 FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND ceremony_id=$4 UNION ALL SELECT 1 FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4`
	}
	rows, err := w.Query(ctx, query, c.Profile.RPNamespace, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}
