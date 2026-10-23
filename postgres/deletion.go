package postgres

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
)

// DeletionConfig selects one trusted tenant/RP, genuine delete-specific signed
// password proof and actual configured emailed-password-reset recovery source.
// ManagementConfig supplies the shared password reader, original-key, risk and
// coordinator configuration, but Source must select identity.passkey.delete.
// Install the password owner's append-only deletion proof suffix after the
// complete installed proof history. Dependencies and the primary pool are
// borrowed; keep them immutable and alive for concurrent calls.
type DeletionConfig struct {
	ManagementConfig
	Recovery *passwordpg.PasskeyRemovalRecoverySource
}

// DeletionService removes authority for an existing self-user passkey. The
// original signed proof, recovery check, protocol/key erasure, disabled kernel
// reference, mapping/passkey versions and canonical audit/lifecycle effects
// share the existing coordinator Work. It owns no transaction, journal, retry,
// goroutine or pool. Removed identifiers remain reserved; no authenticator-local
// erasure is claimed. Password-session authority is not revoked by removal.
type DeletionService struct {
	readers *ManagementService
	config  func() DeletionConfig
}

func (DeletionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.DeletionConfig(redacted)"))
}
func (DeletionService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.DeletionService(redacted)"))
}
func (DeletionConfig) MarshalJSON() ([]byte, error)  { return nil, passkey.ErrPrivateValue }
func (DeletionConfig) MarshalText() ([]byte, error)  { return nil, passkey.ErrPrivateValue }
func (DeletionService) MarshalJSON() ([]byte, error) { return nil, passkey.ErrPrivateValue }
func (DeletionService) MarshalText() ([]byte, error) { return nil, passkey.ErrPrivateValue }

func deletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewDeletionService validates and freezes actual native owners without IO.
// A boolean recovery assertion, completion-only reset owner, foreign primary,
// different password realm or wrong proof action cannot enable this service.
func NewDeletionService(pool *database.Pool, c DeletionConfig) (*DeletionService, error) {
	if c.Recovery == nil || !c.Recovery.Matches(pool, c.Password, c.PolicyID, c.PolicyVersion) {
		return nil, identity.InvalidInputError{Field: "passkey_deletion"}
	}
	readers, err := newManagementReaders(pool, c.ManagementConfig, deletionOperation())
	if err != nil {
		return nil, err
	}
	c.ManagementConfig = readers.config()
	s := &DeletionService{readers: readers, config: func() DeletionConfig { return c }}
	if _, _, err := s.runtime(&deletionInvocation{service: s}); err != nil {
		return nil, err
	}
	return s, nil
}

// Delete admits exact original-key self-removal. Incoming command/record/target
// overrides deny. ExpectedVersion is the observed safe metadata version; kernel
// reference and protocol versions are separately fenced. Fresh commitment and
// historical retry return metadata only. A matching retry authenticates the
// original current password session but never consumes proof, checks recovery
// anew or reruns removal. Unknown is not rollback: retain the same key/input.
func (s *DeletionService) Delete(ctx context.Context, r passkey.DeleteRequest) (out passkey.DeleteResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.readers == nil || r.Primary.CommandID != "" || r.Primary.RecordID != "" || r.Primary.TargetSubjectID != "" || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || len(r.Network) == 0 || len(r.Network) > 128 {
		return out, identity.InvalidInputError{Field: "passkey_deletion"}
	}
	if _, err := identity.ParseIdentifierID(string(r.ReferenceID)); err != nil {
		return out, identity.ForbiddenError{}
	}
	c := s.config()
	if r.Primary.TenantID != c.TenantID {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	read, spec, err := s.readers.authenticatePrimary(ctx, r.Primary, deletionOperation())
	if err != nil {
		return out, err
	}
	recovery, err := c.Recovery.Fields()
	if err != nil {
		return out, err
	}
	intent, err := s.readers.managementRequestIntent(r.Primary, r.ReferenceID, r.ExpectedVersion, r.Network, recovery)
	if err != nil {
		return out, err
	}
	p := &deletionInvocation{service: s, request: r, record: spec}
	coordinator, registry, err := s.runtime(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: c.TenantID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: deletionOperation().OperationID}
	key, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, optionsRequestCaller(r.Primary.Caller, scope, c.RequestKeys.Policy.PolicyVersion))
	if err != nil {
		return out, err
	}
	p.request.Primary.CommandID, p.request.Primary.RecordID = key.CommandID, string(r.ReferenceID)
	p.request.Primary.Caller.CorrelationID = string(key.CommandID)
	out.CommandID = key.CommandID
	query := identity.RecoveryQuery{CommandID: key.CommandID, TenantID: c.TenantID, UserID: spec.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: scope.RouteID, RecordID: string(r.ReferenceID)}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, query, r.Primary.Caller)
	out.Outcome = out.Receipt.Outcome
	if err != nil || out.Replayed {
		return s.finishMetadata(ctx, r, read, spec, out, err)
	}
	if err = p.prepare(ctx); err != nil {
		if receipt, replayed, recoveryErr := optionsMetadata(ctx, coordinator, query, r.Primary.Caller); replayed {
			out.Receipt, out.Replayed, out.Outcome = receipt, true, receipt.Outcome
			return s.finishMetadata(ctx, r, read, spec, out, recoveryErr)
		}
		return passkey.DeleteResult{}, err
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
		out.Receipt, out.Outcome = identity.CommandResult{}, identity.CommitOutcomeUnknown
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	if !p.freshCommit {
		out.Replayed = true
		return s.finishMetadata(ctx, r, read, spec, out, nil)
	}
	if read.ValidateAt(c.Password.Validation.Clock.Now().UTC()) != nil || ctx.Err() != nil {
		return out, identity.UnavailableError{}
	}
	return out, nil
}

func (s *DeletionService) finishMetadata(ctx context.Context, r passkey.DeleteRequest, original session.GetResult, spec session.SessionSpec, out passkey.DeleteResult, observedErr error) (passkey.DeleteResult, error) {
	if err := s.readers.metadataAdmission(ctx, r.Primary, deletionOperation(), original, spec); err != nil {
		return passkey.DeleteResult{}, err
	}
	return out, observedErr
}
