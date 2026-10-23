package postgres

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

type enrollmentInvocation struct {
	*webauthnpg.Store
	service                         *EnrollmentService
	request                         RegistrationRequest
	source                          *passwordpg.ActionPrimarySource
	admission                       passwordpg.ActionPrimaryAdmission
	original                        session.Session
	record                          session.SessionSpec
	operation                       identity.FeatureOperation
	handle                          []byte
	label                           string
	authorityVersion, factorVersion uint64
	epochs                          kernel.UserAuthorityAdmission
	creation                        *webauthnpg.RegistrationCreation
	finalization                    *webauthnpg.RegistrationFinalization
	mutation                        webauthn.RegistrationMutation
	command                         identity.Command
	counters                        *kernel.CommandCounterPlan
}

func isAbsent(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
func (*enrollmentInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (p *enrollmentInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation}
}
func (p *enrollmentInvocation) ceremonyContext() webauthn.CeremonyContext {
	return webauthn.CeremonyContext{CommandID: p.request.Primary.CommandID, TenantID: p.record.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID), CorrelationID: p.request.Primary.Caller.CorrelationID}
}
func (p *enrollmentInvocation) binding() identity.CommandBinding {
	c := p.service.config()
	scope := p.ceremonyContext()
	return identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: authorization.SubjectUser, RecordID: string(scope.CommandID), OperationID: p.operation.OperationID, SchemaID: p.operation.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: scope.CorrelationID}
}
func (p *enrollmentInvocation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
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
func (p *enrollmentInvocation) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	creation, err := p.service.protocol.RegistrationCreation(input)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	p.creation = creation
	defer creation.Discard()
	fields, err := creation.Fields()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	result, runErr := p.execute(ctx, fields)
	if runErr != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, runErr
	}
	record, challenge, err := creation.Result(result)
	return record, challenge, result.Outcome, err
}
func (p *enrollmentInvocation) FinalizeRegistration(ctx context.Context, input webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	mutation, err := input.Mutation()
	if err != nil || !bytes.Equal(mutation.Credential.UserHandle, p.handle) || mutation.Credential.TenantID != p.record.TenantID || mutation.Credential.UserID != p.record.UserID {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	finalization, err := p.service.protocol.RegistrationFinalization(input)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.finalization, p.mutation = finalization, mutation
	fields, err := finalization.Fields()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	ref := p.reference()
	refFields, err := kernel.PasskeyCredentialCreationFields(ref, p.epochs)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	result, runErr := p.execute(ctx, append(fields, refFields...))
	if runErr != nil {
		return webauthn.Credential{}, result.Outcome, runErr
	}
	credential, err := finalization.Result(result)
	return credential, result.Outcome, err
}
func (p *enrollmentInvocation) FinalizeAssertion(context.Context, webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
}

func (p *enrollmentInvocation) execute(ctx context.Context, fields []identity.FeatureField) (identity.CommandResult, error) {
	c := p.service.config()
	fields = append(fields, identity.FeatureField{Name: "passkey.user-handle", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.handle)}}, identity.FeatureField{Name: "passkey.authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.authorityVersion}}, identity.FeatureField{Name: "action-primary.actor-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.factorVersion}}, identity.FeatureField{Name: "action-primary.target-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.factorVersion}}, identity.FeatureField{Name: "passkey.label", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.label}})
	command, err := p.admission.Command(p.binding(), fields)
	if err != nil {
		return identity.CommandResult{}, err
	}
	var now time.Time
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	// PostgreSQL supplies microsecond precision, but pgx may attach the local
	// location. The risk owner's primary-time contract requires explicit UTC.
	now = now.UTC()
	command, counter, err := c.Risk.PrepareCommandCounters(command, p.riskSubject(), now)
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command, p.counters = command, &counter
	coordinator, registry, err := p.service.runtime(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	plan, err := enrollmentPlan(p, registry, coordinator, command)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, p.binding(), command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	if p.creation != nil {
		if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return identity.CommandResult{Binding: p.binding(), Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: p.binding().CommandID}
		}
		now = now.UTC()
		if err := p.creation.Generate(ctx, now); err != nil {
			return identity.CommandResult{Binding: p.binding(), Outcome: identity.CommitOutcomeUnknown}, err
		}
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
	return coordinator.Commit(work, result)
}

func (p *enrollmentInvocation) reference() identity.CredentialRef {
	return identity.CredentialRef{ID: identity.CredentialID(p.binding().RecordID), TenantID: p.record.TenantID, UserID: p.record.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}
}

func (p *enrollmentInvocation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.admission.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.RequireActionPrimaryFactors(ctx, w, p, c, p.factorVersion, p.factorVersion); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.mapping(ctx, w, true); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.creation != nil {
		if err := p.creation.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.enrollmentContext(ctx, w, true); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if p.finalization != nil {
		if err := p.enrollmentContext(ctx, w, false); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.finalization.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := w.CreatePasskeyCredential(ctx, p, c, p.reference(), p.epochs); err != nil {
			return identity.FeatureReceipt{}, err
		}
		var label any
		if p.label != "" {
			value, err := passkey.NewDeviceLabel(p.label)
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
			label = value.Value()
		}
		n, err := w.Exec(ctx, `INSERT INTO identity_passkey.credentials(rp_namespace,tenant_id,user_id,reference_id,credential_id,version,state,display_label,created_at) VALUES($1,$2,$3,$4,$5,1,'active',$6,clock_timestamp())`, p.service.config().RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.binding().RecordID, p.mutation.Credential.ID, label)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	} else {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.operation, AfterVersion: 1}, nil
}

func (p *enrollmentInvocation) mapping(ctx context.Context, w kernel.Work, create bool) error {
	c := p.service.config()
	if create && p.creation != nil {
		if _, err := w.Exec(ctx, `INSERT INTO identity_passkey.relying_parties(rp_namespace,rp_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, c.RPNamespace, c.Protocol.RelyingParty.ID); err != nil {
			return err
		}
		if _, err := w.Exec(ctx, `INSERT INTO identity_passkey.user_handles(rp_namespace,tenant_id,user_id,user_handle,authority_version) VALUES($1,$2,$3,$4,1) ON CONFLICT DO NOTHING`, c.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.handle); err != nil {
			return err
		}
	}
	rows, err := w.Query(ctx, `SELECT h.user_handle,h.authority_version::text FROM identity_passkey.relying_parties p JOIN identity_passkey.user_handles h USING(rp_namespace) WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4 FOR UPDATE OF p,h`, c.RPNamespace, c.Protocol.RelyingParty.ID, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var handle []byte
	var version string
	if err := rows.Scan(&handle, &version); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil || !bytes.Equal(handle, p.handle) || version != strconv.FormatUint(p.authorityVersion, 10) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *enrollmentInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.admission.Check(ctx, w, p, c); err != nil {
		return err
	}
	if err := mfapg.RequireActionPrimaryFactors(ctx, w, p, c, p.factorVersion, p.factorVersion); err != nil {
		return err
	}
	if err := p.mapping(ctx, w, false); err != nil {
		return err
	}
	if err := p.enrollmentContext(ctx, w, false); err != nil {
		return err
	}
	// Policy callbacks run before Work. Consume already fenced the original
	// authorization epoch through commit; calling application policy while
	// holding mapping/proof locks can deadlock even a bounded policy reader.
	if p.creation != nil {
		return p.creation.Check(ctx, w, p, c)
	}
	if p.finalization == nil {
		return identity.ForbiddenError{}
	}
	if err := p.finalization.Check(ctx, w, p, c); err != nil {
		return err
	}
	_, err := w.RequireActiveCredential(ctx, p, kernel.CredentialAdmission{Credential: p.reference(), UserAuthorityVersion: p.epochs.UserAuthorityVersion, IdentifierAuthorityVersion: p.epochs.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.epochs.CredentialAuthorityVersion})
	return err
}

// Preserve the options phase's admitted identity context, not a second protocol
// ceremony. Finalization cannot adopt newer authority or a sibling session even
// when the caller obtains a genuine new proof for that later state.
func (p *enrollmentInvocation) enrollmentContext(ctx context.Context, w kernel.Work, create bool) error {
	id := string(p.request.Primary.CommandID)
	if p.finalization != nil {
		id = p.mutation.Ceremony.ID
	}
	args := []any{p.service.config().RPNamespace, id, string(p.record.TenantID), string(p.record.UserID), p.record.SessionID, p.record.Version, p.epochs.UserAuthorityVersion, p.epochs.IdentifierAuthorityVersion, p.epochs.CredentialAuthorityVersion, p.factorVersion, p.authorityVersion}
	if create {
		n, err := w.Exec(ctx, `INSERT INTO identity_passkey.enrollment_contexts(rp_namespace,ceremony_id,tenant_id,user_id,session_id,session_version,user_epoch,identifier_epoch,credential_epoch,factor_epoch,passkey_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM identity_passkey.enrollment_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4 AND session_id=$5 AND session_version=$6 AND user_epoch=$7 AND identifier_epoch=$8 AND credential_epoch=$9 AND factor_epoch=$10 AND passkey_epoch=$11 FOR SHARE`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	var one int
	if rows.Scan(&one) != nil || one != 1 || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return ctx.Err()
}

func (p *enrollmentInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.protocol.RecoverRegistration(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return status, err
	}
	status, err = p.source.Recover(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return kernel.RecoveryUnknown, err
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	query := `SELECT 1 FROM identity_passkey.enrollment_contexts WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND ceremony_id=$4`
	if f.Operation == enrollmentOperation(true) {
		query = `SELECT 1 FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4`
	}
	rows, err := w.Query(ctx, query, p.service.config().RPNamespace, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if rows.Next() {
		return kernel.RecoveryUnknown, nil
	}
	if err := rows.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryNotCommitted, ctx.Err()
}
