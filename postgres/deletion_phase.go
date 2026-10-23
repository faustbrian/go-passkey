package postgres

import (
	"bytes"
	"context"
	"reflect"
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
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

const removeEvent = "identity.passkey.remove_credential"

type deletionInvocation struct {
	service                       *DeletionService
	request                       passkey.DeleteRequest
	record                        session.SessionSpec
	admission                     passwordpg.ActionPrimaryAdmission
	reference                     identity.CredentialRef
	epochs                        kernel.UserAuthorityAdmission
	factorVersion, passkeyVersion uint64
	credentialID                  []byte
	removal                       *webauthnpg.CredentialRemoval
	command                       identity.Command
	plan                          kernel.CommandPlan
	freshCommit                   bool
}

func (*deletionInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*deletionInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{deletionOperation()}
}
func (p *deletionInvocation) binding() identity.CommandBinding {
	c := p.service.config()
	return identity.CommandBinding{CommandID: p.request.Primary.CommandID, TenantID: c.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), ActorKind: authorization.SubjectUser, RecordID: string(p.request.ReferenceID), OperationID: deletionOperation().OperationID, SchemaID: deletionOperation().SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: p.request.Primary.Caller.CorrelationID}
}

func (s *DeletionService) runtime(p *deletionInvocation) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	o, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.readers.directory, a, o, s.config().Risk, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.readers.pool, registry, s.config().Coordinator, s.config().RequestKeys)
	return coordinator, registry, err
}

func (p *deletionInvocation) prepare(ctx context.Context) error {
	c := p.service.config()
	a, err := c.Source.Prepare(ctx, p.request.Primary)
	if err != nil {
		return err
	}
	original, err := a.Original()
	if err != nil {
		return err
	}
	spec, err := original.Bindings()
	if err != nil || !reflect.DeepEqual(spec, p.record) {
		return identity.ForbiddenError{}
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || vector.Organization.Present || vector.Passkey.Present {
		return identity.ForbiddenError{}
	}
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, p.service.readers.pool, c.TenantID, spec.UserID, c.MaximumDuration)
	if err != nil || enrolled {
		return identity.ForbiddenError{}
	}
	authority, err := p.service.readers.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: c.TenantID, UserID: spec.UserID, CredentialID: p.request.ReferenceID})
	if err != nil {
		return identity.ForbiddenError{}
	}
	ref := authority.Credential
	if ref.Kind != identity.CredentialPasskey || ref.Owner != "passkey" || identity.CheckCredentialAuthority(authority, ref, vector.Credential.Version, c.Password.Validation.Clock.Now().UTC()) != nil || ref.Version == ^uint64(0) {
		return identity.ForbiddenError{}
	}
	var reference, metadata, passkeyVersion string
	err = p.service.readers.pool.Raw().QueryRow(ctx, `SELECT c.credential_id,c.version::text,c.metadata_version::text,h.authority_version::text FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties p USING(rp_namespace) JOIN identity_passkey.user_handles h USING(rp_namespace,tenant_id,user_id) WHERE c.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5 AND c.state='active'`, c.RPNamespace, c.RPID, string(c.TenantID), string(spec.UserID), string(ref.ID)).Scan(&p.credentialID, &reference, &metadata, &passkeyVersion)
	if err != nil {
		return identity.ForbiddenError{}
	}
	if reference != strconv.FormatUint(ref.Version, 10) || metadata != strconv.FormatUint(p.request.ExpectedVersion, 10) || len(p.credentialID) == 0 || len(p.credentialID) > 1024 {
		return identity.ConflictError{}
	}
	p.passkeyVersion, err = strconv.ParseUint(passkeyVersion, 10, 64)
	if err != nil || p.passkeyVersion == 0 || p.passkeyVersion == ^uint64(0) || passkeyVersion != strconv.FormatUint(p.passkeyVersion, 10) {
		return identity.UnavailableError{}
	}
	protocol, err := p.service.readers.protocol.LoadCredential(ctx, webauthn.Lookup{Context: webauthn.CeremonyContext{TenantID: c.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID)}, RPID: c.RPID}, p.credentialID)
	if err != nil || protocol.TenantID != c.TenantID || protocol.UserID != spec.UserID || protocol.RPID != c.RPID || !bytes.Equal(protocol.ID, p.credentialID) || protocol.Version == 0 || protocol.BackupState && !protocol.BackupEligible {
		return identity.ForbiddenError{}
	}
	b := p.binding()
	p.removal, err = p.service.readers.protocol.CredentialRemoval(webauthnpg.RemovalRequest{Context: webauthn.CeremonyContext{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, CorrelationID: b.CorrelationID}, RPID: c.RPID, CredentialID: p.credentialID, Version: protocol.Version})
	if err != nil {
		return err
	}
	p.admission, p.reference, p.factorVersion = a, ref, factor
	p.epochs = kernel.UserAuthorityAdmission{UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version}
	return nil
}

func (p *deletionInvocation) execute(ctx context.Context, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, error) {
	fields, err := p.removal.Fields()
	if err != nil {
		return identity.CommandResult{}, err
	}
	reference, err := kernel.PasskeyCredentialRemovalFields(p.reference, p.epochs)
	if err != nil {
		return identity.CommandResult{}, err
	}
	recovery, err := p.service.config().Recovery.Fields()
	if err != nil {
		return identity.CommandResult{}, err
	}
	fields = append(fields, reference...)
	fields = append(fields, recovery...)
	fields = append(fields, optionsText("passkey.removal.namespace", p.service.config().RPNamespace), optionsText("passkey.removal.rp", p.service.config().RPID), optionsBytes("passkey.removal.protocol-id", p.credentialID), optionsUint("passkey.removal.metadata-version", p.request.ExpectedVersion), optionsUint("passkey.removal.authority-version", p.passkeyVersion), optionsUint("action-primary.actor-factor-version", p.factorVersion), optionsUint("action-primary.target-factor-version", p.factorVersion))
	command, err := p.admission.Command(p.binding(), fields)
	if err != nil {
		return identity.CommandResult{}, err
	}
	var now time.Time
	if err := p.service.readers.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	command, counters, err := p.service.config().Risk.PrepareCommandCounters(command, risk.Subject{User: string(p.record.UserID), Network: p.request.Network, Session: p.record.SessionID}, now.UTC())
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command = command
	p.plan, err = p.commandPlan(coordinator, registry, &counters)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, p.binding(), command, p.plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: p.binding(), Outcome: identity.CommitOutcomeUnknown}, err
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	result, err = coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return coordinator.Abort(work, err)
	}
	result, err = coordinator.Commit(work, result)
	p.freshCommit = err == nil && result.Outcome == identity.CommitOutcomeCommitted
	return result, err
}

func (p *deletionInvocation) commandPlan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, counters *kernel.CommandCounterPlan) (kernel.CommandPlan, error) {
	b := p.binding()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	before, after := strconv.FormatUint(p.reference.Version, 10), strconv.FormatUint(p.reference.Version+1, 10)
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: removeEvent, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": before, "aggregate.after_version": after, "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, deletionOperation(), "passkey", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	p.plan = kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: deletionOperation()}, CommandCounters: counters, Lifecycle: &kernel.LifecyclePlan{EventType: removeEvent, BeforeVersion: p.reference.Version, AfterVersion: p.reference.Version + 1}, Audits: []kernel.AuditPlan{{EventType: removeEvent, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	return coordinator.PrepareCommandPlan(b, p.command, p.plan)
}

func (p *deletionInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	expected := p.plan
	if command != p.command || expected.Feature == nil || plan.Digest == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	plan.Digest, expected.Digest = [32]byte{}, [32]byte{}
	if !reflect.DeepEqual(plan, expected) {
		return identity.ForbiddenError{}
	}
	return p.removal.Validate(command, plan)
}

func (p *deletionInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if command != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.admission.Consume(ctx, w, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.RequireActionPrimaryFactors(ctx, w, p, command, p.factorVersion, p.factorVersion); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.config().Recovery.CheckPasskeyRemovalRecovery(ctx, w, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.mapping(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.removal.Apply(ctx, w, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.RemovePasskeyCredential(ctx, p, command, p.reference, p.epochs); err != nil {
		return identity.FeatureReceipt{}, err
	}
	c := p.service.config()
	n, err := w.Exec(ctx, `UPDATE identity_passkey.credentials SET state='revoked',version=$1,metadata_version=$2 WHERE rp_namespace=$3 AND tenant_id=$4 AND user_id=$5 AND reference_id=$6 AND version=$7 AND metadata_version=$8 AND state='active'`, p.reference.Version+1, p.request.ExpectedVersion+1, c.RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID), p.reference.Version, p.request.ExpectedVersion)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	// The shared RP/user passkey generation fences existing passkey sessions and
	// prepared enrollment/signin contexts. Independent password authority stays
	// unchanged, preserving the original browser's metadata-only retry.
	n, err = w.Exec(ctx, `UPDATE identity_passkey.user_handles SET authority_version=$1 WHERE rp_namespace=$2 AND tenant_id=$3 AND user_id=$4 AND authority_version=$5`, p.passkeyVersion+1, c.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.passkeyVersion)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: deletionOperation(), BeforeVersion: p.reference.Version, AfterVersion: p.reference.Version + 1}, nil
}

func (p *deletionInvocation) mapping(ctx context.Context, w kernel.Work, removed bool) error {
	c := p.service.config()
	rows, err := w.Query(ctx, `SELECT c.credential_id,c.version::text,c.metadata_version::text,c.state,h.authority_version::text FROM identity_passkey.relying_parties p JOIN identity_passkey.user_handles h USING(rp_namespace) JOIN identity_passkey.credentials c USING(rp_namespace,tenant_id,user_id) WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5 FOR UPDATE OF p,h,c`, c.RPNamespace, c.RPID, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var id []byte
	var version, metadata, state, authority string
	if err := rows.Scan(&id, &version, &metadata, &state, &authority); err != nil {
		return err
	}
	refVersion, metadataVersion, passkeyVersion := p.reference.Version, p.request.ExpectedVersion, p.passkeyVersion
	wantState := "active"
	if removed {
		refVersion, metadataVersion, passkeyVersion = refVersion+1, metadataVersion+1, passkeyVersion+1
		wantState = "revoked"
	}
	if rows.Next() || rows.Err() != nil || !bytes.Equal(id, p.credentialID) || version != strconv.FormatUint(refVersion, 10) || metadata != strconv.FormatUint(metadataVersion, 10) || authority != strconv.FormatUint(passkeyVersion, 10) || state != wantState {
		return identity.ConflictError{}
	}
	return ctx.Err()
}

func (p *deletionInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.admission.Check(ctx, w, p, command); err != nil {
		return err
	}
	if err := mfapg.RequireActionPrimaryFactors(ctx, w, p, command, p.factorVersion, p.factorVersion); err != nil {
		return err
	}
	if err := p.service.config().Recovery.CheckPasskeyRemovalRecovery(ctx, w, p, command); err != nil {
		return err
	}
	if err := w.CheckRemovedPasskeyCredential(ctx, p, command, p.reference, p.epochs); err != nil {
		return err
	}
	if err := p.mapping(ctx, w, true); err != nil {
		return err
	}
	return p.removal.Check(ctx, w, p, command)
}

func (p *deletionInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.config().Source.Recover(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return kernel.RecoveryUnknown, err
	}
	status, err = p.service.readers.protocol.RecoverRemoval(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return kernel.RecoveryUnknown, err
	}
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || feature.Operation != deletionOperation() || life.EventType != removeEvent || life.BeforeVersion == 0 || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	c := p.service.config()
	rows, err := w.Query(ctx, `SELECT c.version::text,c.metadata_version::text,c.state FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties p USING(rp_namespace) WHERE c.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5`, c.RPNamespace, c.RPID, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		return kernel.RecoveryUnknown, rows.Err()
	}
	var version, metadata, state string
	if rows.Scan(&version, &metadata, &state) != nil || rows.Next() || rows.Err() != nil || version != strconv.FormatUint(life.BeforeVersion, 10) || metadata != strconv.FormatUint(p.request.ExpectedVersion, 10) || state != "active" {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, ctx.Err()
}
