package postgres

import (
	"bytes"
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
	passkey "github.com/faustbrian/go-passkey"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

type sessionUpdateInvocation struct {
	*webauthnpg.Store
	service       *SessionManagementService
	request       passkey.SessionUpdateRequest
	read          session.GetResult
	record        session.SessionSpec
	id            identity.CommandID
	finish        bool
	ceremonyID    string
	reference     identity.CredentialRef
	metadata      passkey.CredentialMetadata
	beforeLabel   string
	authProtocol  webauthn.Credential
	sourceFields  []identity.FeatureField
	contextDigest [32]byte
	creation      *webauthnpg.AssertionCreation
	finalization  *webauthnpg.AssertionFinalization
	command       identity.Command
	result        identity.CommandResult
}

func (*sessionUpdateInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*sessionUpdateInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{sessionUpdateOperation(false), sessionUpdateOperation(true)}
}
func (p *sessionUpdateInvocation) protocolContext() webauthn.CeremonyContext {
	return webauthn.CeremonyContext{CommandID: p.id, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), CorrelationID: string(p.id)}
}
func (p *sessionUpdateInvocation) binding() identity.CommandBinding {
	c := p.service.config()
	record := string(p.id)
	if p.finish {
		record = string(p.request.ReferenceID)
	}
	op := sessionUpdateOperation(p.finish)
	return identity.CommandBinding{CommandID: p.id, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), ActorKind: authorization.SubjectUser, RecordID: record, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: string(p.id)}
}
func (s *SessionManagementService) runtime(p *sessionUpdateInvocation) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	p.Store = s.protocol
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	o, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, o, s.config().Risk, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config().Coordinator, s.config().OptionsRequests.state().request)
	return coordinator, registry, err
}

func (p *sessionUpdateInvocation) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	i, err := input.Intent()
	if p.finish || err != nil || i.Context != p.protocolContext() || !bytes.Equal(i.UserHandle, p.authProtocol.UserHandle) || len(i.AllowedCredentials) != 1 || !bytes.Equal(i.AllowedCredentials[0], p.authProtocol.ID) {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	p.creation, err = p.service.protocol.UpdateAssertionCreation(input)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	defer p.creation.Discard()
	fields, err := p.creation.Fields()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	result, err := p.execute(ctx, fields)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, err
	}
	r, challenge, err := p.creation.Result(result)
	return r, challenge, result.Outcome, err
}

func (p *sessionUpdateInvocation) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, err := input.Mutation()
	if !p.finish || err != nil || m.Context != p.protocolContext() || m.Ceremony.ID != p.ceremonyID || m.Before.TenantID != p.record.TenantID || m.Before.UserID != p.record.UserID || !bytes.Equal(m.Before.ID, p.authProtocol.ID) || m.Before.Version != p.authProtocol.Version || m.CounterRisk {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	p.finalization, err = p.service.protocol.UpdateAssertionFinalization(input)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	fields, err := p.finalization.Fields()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	if p.record.Authentication.CredentialID == string(p.reference.ID) {
		p.metadata.BackupEligible, p.metadata.BackupState = m.After.BackupEligible, m.After.BackupState
	}
	result, err := p.execute(ctx, fields)
	if err != nil {
		return webauthn.Credential{}, result.Outcome, err
	}
	credential, err := p.finalization.Result(result)
	return credential, result.Outcome, err
}

func (p *sessionUpdateInvocation) execute(ctx context.Context, fields []identity.FeatureField) (result identity.CommandResult, err error) {
	defer func() { p.result = result }()
	c := p.service.config()
	fields = append(fields, p.sourceFields...)
	fields = append(fields, optionsBytes("passkey.update.context", p.contextDigest[:]), optionsText("passkey.update.target", string(p.reference.ID)), optionsUint("passkey.update.reference-version", p.reference.Version), optionsUint("passkey.update.metadata-version", p.request.ExpectedVersion), optionsText("passkey.update.before-label", p.beforeLabel), optionsText("passkey.update.after-label", p.request.Name))
	op := sessionUpdateOperation(p.finish)
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding(), Operation: op, Fields: fields})
	if err != nil {
		return result, err
	}
	var now time.Time
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
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
		life = kernel.LifecyclePlan{EventType: renameEvent, BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}
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
		if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
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

func (p *sessionUpdateInvocation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if p.creation != nil {
		return p.creation.Validate(c, plan)
	}
	if p.finalization != nil {
		return p.finalization.Validate(c, plan)
	}
	return identity.ForbiddenError{}
}

func (p *sessionUpdateInvocation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.current(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.creation != nil {
		if err := p.creation.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.originalContext(ctx, w, true); err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{Operation: sessionUpdateOperation(false), AfterVersion: 1}, nil
	}
	if err := p.originalContext(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.finalization.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	n, err := w.Exec(ctx, `UPDATE identity_passkey.credentials SET display_label=$1,metadata_version=$2 WHERE rp_namespace=$3 AND tenant_id=$4 AND user_id=$5 AND reference_id=$6 AND version=$7 AND metadata_version=$8 AND state='active'`, p.request.Name, p.request.ExpectedVersion+1, p.service.config().Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID), p.reference.Version, p.request.ExpectedVersion)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: sessionUpdateOperation(true), BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}, nil
}

func (p *sessionUpdateInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w, true); err != nil {
		return err
	}
	if err := p.originalContext(ctx, w, false); err != nil {
		return err
	}
	if p.creation != nil {
		return p.creation.Check(ctx, w, p, c)
	}
	return p.finalization.Check(ctx, w, p, c)
}

func (p *sessionUpdateInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.protocol.RecoverUpdateAssertion(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return status, err
	}
	b, feature, life, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	c := p.service.config()
	if feature.Operation == sessionUpdateOperation(false) {
		rows, err := w.Query(ctx, `SELECT 1 FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4`, c.Profile.RPNamespace, b.RecordID, string(b.TenantID), string(b.UserID))
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		defer rows.Close()
		if rows.Next() || rows.Err() != nil {
			return kernel.RecoveryUnknown, nil
		}
		return kernel.RecoveryNotCommitted, nil
	}
	if feature.Operation != sessionUpdateOperation(true) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT metadata_version::text FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4`, c.Profile.RPNamespace, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var version string
	if !rows.Next() || rows.Scan(&version) != nil || rows.Next() || rows.Err() != nil || version != strconv.FormatUint(life.BeforeVersion, 10) {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}
