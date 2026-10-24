package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

type sessionDeleteFinalizer interface {
	sessionEnrollmentParticipant
	Result(identity.CommandResult) (webauthn.Credential, error)
	CheckRemainingCredential(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command, []byte) (webauthn.Credential, error)
}

type sessionDeleteInvocation struct {
	*webauthnpg.Store
	service                      *SessionDeletionService
	request                      passkey.SessionDeleteRequestSpec
	read                         session.GetResult
	record                       session.SessionSpec
	id                           identity.CommandID
	finish                       bool
	ceremonyID                   string
	reference, remaining         identity.CredentialRef
	authProtocol, targetProtocol webauthn.Credential
	remainingID                  []byte
	sourceFields                 []identity.FeatureField
	contextDigest                [32]byte
	assertionExpires             time.Time
	creation                     *webauthnpg.AssertionCreation
	finalization                 sessionDeleteFinalizer
	command                      identity.Command
	result                       identity.CommandResult
}

func (*sessionDeleteInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*sessionDeleteInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{sessionDeleteOperation(false), sessionDeleteOperation(true)}
}
func (p *sessionDeleteInvocation) protocolContext() webauthn.CeremonyContext {
	return webauthn.CeremonyContext{CommandID: p.id, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), CorrelationID: string(p.id)}
}
func (p *sessionDeleteInvocation) binding() identity.CommandBinding {
	c := p.service.owner.config()
	record := string(p.id)
	if p.finish {
		record = string(p.reference.ID)
	}
	op := sessionDeleteOperation(p.finish)
	return identity.CommandBinding{CommandID: p.id, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), ActorKind: authorization.SubjectUser, RecordID: record, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: string(p.id)}
}
func (p *sessionDeleteInvocation) participant() sessionEnrollmentParticipant {
	if p.creation != nil {
		return p.creation
	}
	if p.finalization != nil {
		return p.finalization
	}
	return nil
}

func (s *SessionDeletionService) runtime(p *sessionDeleteInvocation) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
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

func (p *sessionDeleteInvocation) execute(ctx context.Context, fields []identity.FeatureField) (result identity.CommandResult, err error) {
	defer func() { p.result = result }()
	c := p.service.owner.config()
	fields = append(fields, p.sourceFields...)
	fields = append(fields, optionsBytes("passkey.delete.context", p.contextDigest[:]), optionsText("passkey.delete.target", string(p.reference.ID)), optionsUint("passkey.delete.reference-version", p.reference.Version), optionsUint("passkey.delete.metadata-version", p.request.ExpectedVersion), optionsText("passkey.delete.remaining-reference", string(p.remaining.ID)), optionsUint("passkey.delete.remaining-version", p.remaining.Version), optionsBytes("passkey.delete.remaining-id", p.remainingID))
	if p.finish {
		removed, err := kernel.PasskeyCredentialRemovalFields(p.reference, p.epochs())
		if err != nil {
			return result, err
		}
		fields = append(fields, removed...)
	}
	op := sessionDeleteOperation(p.finish)
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
	life := kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}
	if p.finish {
		life = kernel.LifecyclePlan{EventType: removeEvent, BeforeVersion: p.reference.Version, AfterVersion: p.reference.Version + 1}
	}
	b := p.binding()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return result, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now.UTC(), Action: life.EventType, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return result, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "passkey", seed)
	if err != nil {
		return result, err
	}
	plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &life, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: life.EventType, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}})
	if err != nil {
		return result, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	if p.creation != nil {
		if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: b.CommandID}
		}
		if err := p.creation.Generate(ctx, now.UTC()); err != nil {
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

func (p *sessionDeleteInvocation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || p.participant() == nil {
		return identity.ForbiddenError{}
	}
	return p.participant().Validate(c, plan)
}

func (p *sessionDeleteInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if command != p.command || p.participant() == nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.finish {
		// Provisional reference removal acquires the kernel user's exclusive lock
		// before any user SHARE admission. It grants no success: every subsequent
		// UV, recovery, mapping, authority and required-effect failure rolls back.
		// Directory locks precede the user, matching directory lifecycle writers.
		c := p.service.owner.config()
		directory, _, _, err := sessionpg.OriginalPasskeySessionAdmission(c.Profile, p.read.Session, p.binding())
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := w.RemovePasskeyCredential(ctx, p, command, p.reference, p.epochs()); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.current(ctx, w, p.finish, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.creation != nil {
		if err := p.creation.Apply(ctx, w, p, command); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.originalContext(ctx, w, true); err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{Operation: sessionDeleteOperation(false), AfterVersion: 1}, nil
	}
	if err := p.originalContext(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.finalization.Apply(ctx, w, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.remainingCredential(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	c := p.service.owner.config()
	n, err := w.Exec(ctx, `UPDATE identity_passkey.credentials SET state='revoked',version=$1::numeric,metadata_version=$2::numeric WHERE rp_namespace=$3 AND tenant_id=$4 AND user_id=$5 AND reference_id=$6 AND version=$7::numeric AND metadata_version=$8::numeric AND state='active'`, strconv.FormatUint(p.reference.Version+1, 10), strconv.FormatUint(p.request.ExpectedVersion+1, 10), c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID), strconv.FormatUint(p.reference.Version, 10), strconv.FormatUint(p.request.ExpectedVersion, 10))
	if err != nil || n != 1 {
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	v, _ := p.record.Authority.Bindings()
	n, err = w.Exec(ctx, `UPDATE identity_passkey.user_handles SET authority_version=$1::numeric WHERE rp_namespace=$2 AND tenant_id=$3 AND user_id=$4 AND authority_version=$5::numeric`, strconv.FormatUint(v.Passkey.Binding.Version+1, 10), c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), strconv.FormatUint(v.Passkey.Binding.Version, 10))
	if err != nil || n != 1 {
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: sessionDeleteOperation(true), BeforeVersion: p.reference.Version, AfterVersion: p.reference.Version + 1}, nil
}

func (p *sessionDeleteInvocation) remainingCredential(ctx context.Context, w kernel.Work, command identity.Command) error {
	credential, err := p.finalization.CheckRemainingCredential(ctx, w, p, command, p.remainingID)
	if err != nil {
		return err
	}
	if !selectedPasskeyAlgorithm(p.service.owner.config().Protocol.Algorithms, credential.Algorithm) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *sessionDeleteInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.command || p.participant() == nil {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w, p.finish, p.finish); err != nil {
		return err
	}
	if err := p.originalContext(ctx, w, false); err != nil {
		return err
	}
	if p.creation != nil {
		return p.creation.Check(ctx, w, p, command)
	}
	if err := p.remainingCredential(ctx, w, command); err != nil {
		return err
	}
	if err := p.finalization.Check(ctx, w, p, command); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || p.read.ValidateAt(now.UTC()) != nil || p.assertionExpires.IsZero() || !now.Before(p.assertionExpires) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
