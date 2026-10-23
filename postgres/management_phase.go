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
)

const renameEvent = "identity.passkey.rename_credential"

type managementInvocation struct {
	service                       *ManagementService
	request                       passkey.UpdateRequest
	record                        session.SessionSpec
	admission                     passwordpg.ActionPrimaryAdmission
	reference                     identity.CredentialRef
	epochs                        kernel.UserAuthorityAdmission
	factorVersion, passkeyVersion uint64
	credentialID                  []byte
	beforeLabel                   string
	metadata                      passkey.CredentialMetadata
	command                       identity.Command
	counters                      *kernel.CommandCounterPlan
	plan                          kernel.CommandPlan
	freshCommit                   bool
}

func (*managementInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*managementInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{managementOperation()}
}
func (p *managementInvocation) binding() identity.CommandBinding {
	c := p.service.config()
	return identity.CommandBinding{CommandID: p.request.Primary.CommandID, TenantID: c.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), ActorKind: authorization.SubjectUser, RecordID: string(p.request.ReferenceID), OperationID: managementOperation().OperationID, SchemaID: managementOperation().SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: p.request.Primary.Caller.CorrelationID}
}

func (s *ManagementService) runtime(p *managementInvocation) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
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
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config().Coordinator, s.config().RequestKeys)
	return coordinator, registry, err
}

func (p *managementInvocation) prepare(ctx context.Context) error {
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
	// The independently configured read profile and signed source must identify
	// the exact same original session/authority, not two valid sibling sessions.
	if err != nil || !reflect.DeepEqual(spec, p.record) {
		return identity.ForbiddenError{}
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || vector.Organization.Present || vector.Passkey.Present {
		return identity.ForbiddenError{}
	}
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, p.service.pool, c.TenantID, spec.UserID, c.MaximumDuration)
	if err != nil || enrolled {
		return identity.ForbiddenError{}
	}
	authority, err := p.service.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: c.TenantID, UserID: spec.UserID, CredentialID: p.request.ReferenceID})
	if err != nil {
		return identity.ForbiddenError{}
	}
	ref := authority.Credential
	if ref.Kind != identity.CredentialPasskey || ref.Owner != "passkey" || identity.CheckCredentialAuthority(authority, ref, vector.Credential.Version, c.Password.Validation.Clock.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	var version, passkeyVersion, referenceVersion string
	var state string
	metadata := passkey.CredentialMetadata{ReferenceID: string(ref.ID)}
	err = p.service.pool.Raw().QueryRow(ctx, `SELECT c.credential_id,c.version::text,c.metadata_version::text,c.state,COALESCE(c.display_label,''),c.created_at,c.last_used_at,h.authority_version::text FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties p USING(rp_namespace) JOIN identity_passkey.user_handles h USING(rp_namespace,tenant_id,user_id) WHERE c.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5`, c.RPNamespace, c.RPID, string(c.TenantID), string(spec.UserID), string(ref.ID)).Scan(&p.credentialID, &referenceVersion, &version, &state, &metadata.Label, &metadata.CreatedAt, &metadata.LastUsedAt, &passkeyVersion)
	if err != nil {
		return identity.ForbiddenError{}
	}
	metadata.Version, err = strconv.ParseUint(version, 10, 64)
	if err != nil || version != strconv.FormatUint(metadata.Version, 10) || metadata.Version != p.request.ExpectedVersion || referenceVersion != strconv.FormatUint(ref.Version, 10) || state != "active" || len(p.credentialID) == 0 || len(p.credentialID) > 1024 {
		return identity.ConflictError{}
	}
	p.passkeyVersion, err = strconv.ParseUint(passkeyVersion, 10, 64)
	if err != nil || p.passkeyVersion == 0 || passkeyVersion != strconv.FormatUint(p.passkeyVersion, 10) {
		return identity.UnavailableError{}
	}
	protocol, err := p.service.protocol.LoadCredential(ctx, webauthn.Lookup{Context: webauthn.CeremonyContext{TenantID: c.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID)}, RPID: c.RPID}, p.credentialID)
	if err != nil || protocol.TenantID != c.TenantID || protocol.UserID != spec.UserID || protocol.RPID != c.RPID || !bytes.Equal(protocol.ID, p.credentialID) || protocol.Version == 0 || protocol.BackupState && !protocol.BackupEligible {
		return identity.ForbiddenError{}
	}
	metadata.AAGUID, metadata.BackupEligible, metadata.BackupState = protocol.AAGUID, protocol.BackupEligible, protocol.BackupState
	metadata.State = state
	p.beforeLabel = metadata.Label
	metadata.Label = p.request.Name
	metadata.Version++
	p.admission, p.reference, p.factorVersion, p.metadata = a, ref, factor, metadata
	p.epochs = kernel.UserAuthorityAdmission{UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version}
	return nil
}

func (p *managementInvocation) execute(ctx context.Context, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, error) {
	fields := []identity.FeatureField{optionsText("passkey.management.namespace", p.service.config().RPNamespace), optionsText("passkey.management.rp", p.service.config().RPID), optionsBytes("passkey.management.protocol-id", p.credentialID), optionsUint("passkey.management.reference-version", p.reference.Version), optionsUint("passkey.management.before-version", p.request.ExpectedVersion), optionsText("passkey.management.before-label", p.beforeLabel), optionsText("passkey.management.after-label", p.request.Name), optionsUint("passkey.management.authority-version", p.passkeyVersion), optionsUint("action-primary.actor-factor-version", p.factorVersion), optionsUint("action-primary.target-factor-version", p.factorVersion)}
	command, err := p.admission.Command(p.binding(), fields)
	if err != nil {
		return identity.CommandResult{}, err
	}
	var now time.Time
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	command, counter, err := p.service.config().Risk.PrepareCommandCounters(command, risk.Subject{User: string(p.record.UserID), Network: p.request.Network, Session: p.record.SessionID}, now.UTC())
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command, p.counters = command, &counter
	p.plan, err = p.commandPlan(coordinator, registry)
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

func (p *managementInvocation) commandPlan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b := p.binding()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	before, after := strconv.FormatUint(p.request.ExpectedVersion, 10), strconv.FormatUint(p.request.ExpectedVersion+1, 10)
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: renameEvent, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": before, "aggregate.after_version": after, "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, managementOperation(), "passkey", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	p.plan = kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: managementOperation()}, CommandCounters: p.counters, Lifecycle: &kernel.LifecyclePlan{EventType: renameEvent, BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}, Audits: []kernel.AuditPlan{{EventType: renameEvent, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	return coordinator.PrepareCommandPlan(b, p.command, p.plan)
}

func (p *managementInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	expected := p.plan
	if command != p.command || expected.Feature == nil || plan.Digest == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	// Coordinator computes the digest before invoking this pure native guard;
	// compare every declaration while leaving fingerprint authority with it.
	plan.Digest, expected.Digest = [32]byte{}, [32]byte{}
	if !reflect.DeepEqual(plan, expected) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *managementInvocation) requireCredential(ctx context.Context, w kernel.Work) error {
	_, err := w.RequireActiveCredential(ctx, p, kernel.CredentialAdmission{Credential: p.reference, UserAuthorityVersion: p.epochs.UserAuthorityVersion, IdentifierAuthorityVersion: p.epochs.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.epochs.CredentialAuthorityVersion})
	return err
}

func (p *managementInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if command != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.admission.Consume(ctx, w, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireCredential(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.RequireActionPrimaryFactors(ctx, w, p, command, p.factorVersion, p.factorVersion); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.mapping(ctx, w, p.request.ExpectedVersion, p.beforeLabel); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// This is a metadata CAS only. The separate version remains the kernel
	// credential-reference fence used by existing native signin consumers.
	n, err := w.Exec(ctx, `UPDATE identity_passkey.credentials SET display_label=$1,metadata_version=$2 WHERE rp_namespace=$3 AND tenant_id=$4 AND user_id=$5 AND reference_id=$6 AND version=$7 AND metadata_version=$8 AND state='active'`, p.request.Name, p.request.ExpectedVersion+1, p.service.config().RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID), p.reference.Version, p.request.ExpectedVersion)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: managementOperation(), BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}, nil
}

func (p *managementInvocation) mapping(ctx context.Context, w kernel.Work, expected uint64, label string) error {
	c := p.service.config()
	rows, err := w.Query(ctx, `SELECT c.credential_id,c.version::text,c.metadata_version::text,COALESCE(c.display_label,''),h.authority_version::text FROM identity_passkey.relying_parties p JOIN identity_passkey.user_handles h USING(rp_namespace) JOIN identity_passkey.credentials c USING(rp_namespace,tenant_id,user_id) WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5 AND c.state='active' FOR UPDATE OF p,h,c`, c.RPNamespace, c.RPID, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var id []byte
	var version, metadataVersion, currentLabel, authority string
	if err := rows.Scan(&id, &version, &metadataVersion, &currentLabel, &authority); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil || !bytes.Equal(id, p.credentialID) || version != strconv.FormatUint(p.reference.Version, 10) || metadataVersion != strconv.FormatUint(expected, 10) || authority != strconv.FormatUint(p.passkeyVersion, 10) || currentLabel != label {
		return identity.ConflictError{}
	}
	return ctx.Err()
}

func (p *managementInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.admission.Check(ctx, w, p, command); err != nil {
		return err
	}
	if err := p.requireCredential(ctx, w); err != nil {
		return err
	}
	if err := mfapg.RequireActionPrimaryFactors(ctx, w, p, command, p.factorVersion, p.factorVersion); err != nil {
		return err
	}
	return p.mapping(ctx, w, p.request.ExpectedVersion+1, p.request.Name)
}

func (p *managementInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.config().Source.Recover(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return kernel.RecoveryUnknown, err
	}
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || feature.Operation != managementOperation() || life.EventType != renameEvent || life.BeforeVersion == 0 || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	c := p.service.config()
	rows, err := w.Query(ctx, `SELECT c.metadata_version::text FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties p USING(rp_namespace) WHERE c.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5`, c.RPNamespace, c.RPID, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		return kernel.RecoveryUnknown, rows.Err()
	}
	var version string
	if rows.Scan(&version) != nil || rows.Next() || rows.Err() != nil || version != strconv.FormatUint(life.BeforeVersion, 10) {
		return kernel.RecoveryUnknown, nil
	}
	// Only unchanged original metadata plus the genuine proof owner's absent
	// consume marker proves noncommit. Changed state never reconstructs success;
	// acknowledged commit history remains the kernel's sole receipt authority.
	return kernel.RecoveryNotCommitted, ctx.Err()
}
