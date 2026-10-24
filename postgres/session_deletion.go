package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// SessionDeletionConfig selects actual passkey-session, CSRF, protocol, policy
// and risk owners. This explicit profile permits removal only when another
// live resident passkey in the selected algorithm profile remains usable.
// Password/email/OTP recovery is
// not inferred or substituted. Installing it enables no HTTP route. Install
// the selected owner histories before use; the primary pool is borrowed.
type SessionDeletionConfig = SessionManagementConfig

// SessionDeletionService consumes genuine action-bound UV with exact credential
// removal, independently usable remaining-key admission and passkey-session
// invalidation in the sole native Work. No proof store, transaction owner,
// goroutine or automatic retry is introduced. Configuration is immutable;
// independent invocations may run concurrently.
type SessionDeletionService struct{ owner *SessionManagementService }

// NewSessionDeletionService validates and freezes concrete owners without IO.
// This selected resident-key recovery profile does not enable the independent
// password-proof deletion service. The pool must outlive all calls.
func NewSessionDeletionService(pool *database.Pool, c SessionDeletionConfig) (*SessionDeletionService, error) {
	if !validPasskeyAlgorithms(c.Protocol.Algorithms) {
		return nil, identity.InvalidInputError{Field: "passkey_deletion_algorithms"}
	}
	owner, err := NewSessionManagementService(pool, c)
	if err != nil {
		return nil, err
	}
	s := &SessionDeletionService{owner: owner}
	if _, _, err := s.runtime(&sessionDeleteInvocation{service: s}); err != nil {
		return nil, err
	}
	return s, nil
}

// Format excludes borrowed owners and deployment correlation.
func (SessionDeletionService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeypostgres.SessionDeletionService(redacted)"))
}

// MarshalJSON rejects implicit owner export.
func (SessionDeletionService) MarshalJSON() ([]byte, error) { return nil, passkey.ErrPrivateValue }

// MarshalText rejects implicit owner export.
func (SessionDeletionService) MarshalText() ([]byte, error) { return nil, passkey.ErrPrivateValue }

func sessionDeleteOperation(finish bool) identity.FeatureOperation {
	schema := "identity.passkey.delete.options-v1"
	if finish {
		schema = "identity.passkey.delete.assertion-v1"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *SessionDeletionService) request(ctx context.Context, custody passkey.SessionDeleteRequest) (passkey.SessionDeleteRequestSpec, session.GetResult, session.SessionSpec, error) {
	var empty passkey.SessionDeleteRequestSpec
	if ctx == nil || s == nil || s.owner == nil {
		return empty, session.GetResult{}, session.SessionSpec{}, identity.InvalidInputError{Field: "passkey_session_deletion"}
	}
	r, err := custody.Bindings()
	if err != nil || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Origin) == 0 || len(r.Origin) > 2048 {
		return empty, session.GetResult{}, session.SessionSpec{}, identity.InvalidInputError{Field: "passkey_session_deletion"}
	}
	if _, err := identity.ParseIdentifierID(string(r.ReferenceID)); err != nil || !slices.Contains(s.owner.config().Protocol.RelyingParty.Origins, r.Origin) {
		return empty, session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	read, record, err := s.owner.authenticateAction(ctx, passkey.SessionUpdateRequest{Credential: r.Credential, CSRFToken: r.CSRFToken, Caller: r.Caller}, "identity.passkey.delete")
	return r, read, record, err
}

func (s *SessionDeletionService) prepareRequest(ctx context.Context, custody passkey.SessionDeleteRequest, key identity.IdempotencyKey, finish bool, ceremony string, response []byte) (*sessionDeleteInvocation, passkey.DeleteResult, error) {
	var out passkey.DeleteResult
	if key == (identity.IdempotencyKey{}) || len(response) > 262144 {
		return nil, out, identity.InvalidInputError{Field: "passkey_session_deletion"}
	}
	r, read, record, err := s.request(ctx, custody)
	if err != nil {
		return nil, out, err
	}
	if finish {
		if _, err := identity.ParseCommandID(ceremony); err != nil || len(response) == 0 {
			return nil, out, identity.InvalidInputError{Field: "passkey_removal_assertion"}
		}
	}
	p := &sessionDeleteInvocation{service: s, request: r, read: read, record: record, finish: finish, ceremonyID: ceremony}
	coordinator, _, err := s.runtime(p)
	if err != nil {
		return nil, out, err
	}
	c := s.owner.config()
	fields, err := optionsProtocolFields(c.Protocol, c.Profile.RPNamespace, c.PolicyID, c.PolicyVersion)
	if err != nil {
		return nil, out, err
	}
	digest, err := r.Credential.Digest(c.OptionsRequests.state().token, string(record.TenantID))
	if err != nil {
		return nil, out, err
	}
	fields = append(fields, optionsBytes("delete.session", digest.Sum[:]), optionsUint("delete.session-key", uint64(digest.KeyVersion)), optionsText("delete.reference", string(r.ReferenceID)), optionsUint("delete.version", r.ExpectedVersion), optionsText("delete.origin", r.Origin), optionsText("delete.network", r.Network), identity.FeatureField{Name: "delete.finish", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: finish}})
	if c.Transport == session.CredentialCookie {
		csrf, err := r.CSRFToken.Digest(c.OptionsRequests.state().csrf, session.CSRFBinding{TenantID: record.TenantID, SessionID: record.SessionID, SessionVersion: record.Version})
		if err != nil {
			return nil, out, err
		}
		bound, err := csrf.Bindings()
		if err != nil {
			return nil, out, err
		}
		fields = append(fields, optionsBytes("delete.csrf", bound.Digest[:]), optionsUint("delete.csrf-key", uint64(bound.KeyVersion)))
	}
	if finish {
		hash := sha256.Sum256(response)
		fields = append(fields, optionsText("delete.ceremony", ceremony), optionsBytes("delete.response", hash[:]))
	}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return nil, out, err
	}
	scope := kernel.RequestKeyScope{TenantID: record.TenantID, ActorID: identity.ActorID(record.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.passkey.delete"}
	admitted, err := coordinator.ResolveRequestKey(ctx, scope, key, intent, optionsRequestCaller(r.Caller, scope, c.OptionsRequests.state().request.Policy.PolicyVersion))
	if err != nil {
		return nil, out, err
	}
	p.id, out.CommandID = admitted.CommandID, admitted.CommandID
	recordID := string(p.id)
	if finish {
		recordID = string(r.ReferenceID)
	}
	query := identity.RecoveryQuery{CommandID: p.id, TenantID: record.TenantID, UserID: record.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, RecordID: recordID, OperationID: scope.RouteID}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, query, r.Caller)
	// Historical metadata is still a disclosure under this invocation's
	// original positive read, not permission to renew its validity after IO.
	if stopped := ctx.Err(); stopped != nil {
		return nil, passkey.DeleteResult{}, stopped
	}
	if read.ValidateAt(c.Clock.Now().UTC()) != nil {
		return nil, passkey.DeleteResult{}, identity.ForbiddenError{}
	}
	out.Outcome = out.Receipt.Outcome
	return p, out, err
}

// DeleteOptions authenticates the actual current passkey session and creates
// original identified UV options bound to its intended target/version. The
// options and completion keys are distinct requests to the same protected action.
// An original retry returns metadata only, never another challenge or ceremony.
func (s *SessionDeletionService) DeleteOptions(ctx context.Context, r passkey.SessionDeleteOptionsRequest) (out passkey.KeyedAssertionOptionsResult, err error) {
	if ctx == nil || s == nil || s.owner == nil {
		return out, identity.InvalidInputError{Field: "passkey_session_deletion"}
	}
	ctx, stop := context.WithTimeout(ctx, s.owner.config().Protocol.MaximumDuration)
	defer stop()
	p, observed, err := s.prepareRequest(ctx, r.SessionDeleteRequest, r.IdempotencyKey, false, "", nil)
	out.CommandID, out.Receipt, out.Replayed = observed.CommandID, observed.Receipt, observed.Replayed
	if err != nil || observed.Replayed {
		return out, err
	}
	if err := p.prepare(ctx); err != nil {
		return out, err
	}
	protocol, err := webauthn.New(s.owner.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return out, err
	}
	out.Options, err = protocol.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: p.protocolContext(), UserHandle: p.authProtocol.UserHandle, Origin: p.request.Origin, AllowedCredentials: [][]byte{p.authProtocol.ID}})
	out.Receipt = p.result
	if err == nil {
		err = p.read.ValidateAt(s.owner.config().Clock.Now().UTC())
	}
	return out, err
}

// Delete verifies genuine action-bound UV and atomically removes exactly the
// intended own key only if an independent usable resident key remains. It
// advances passkey authority, invalidating affected passkey sessions without
// revoking independent password sessions. Acknowledgement belongs only to this
// original authenticated invocation: a new call with its invalidated session
// denies. Unknown is not rollback; preserve original command/key/input custody.
func (s *SessionDeletionService) Delete(ctx context.Context, custody passkey.SessionDeleteCompletion) (passkey.SessionDeleteResult, error) {
	var out passkey.DeleteResult
	if ctx == nil || s == nil || s.owner == nil {
		return passkey.SessionDeleteResult{}, identity.InvalidInputError{Field: "passkey_session_deletion"}
	}
	r, err := custody.Bindings()
	if err != nil {
		return passkey.SessionDeleteResult{}, err
	}
	ctx, stop := context.WithTimeout(ctx, s.owner.config().Protocol.MaximumDuration)
	defer stop()
	p, out, err := s.prepareRequest(ctx, r.SessionDeleteRequest, r.IdempotencyKey, true, r.CeremonyID, r.Response)
	if err != nil || out.Replayed {
		return passkey.NewSessionDeleteResult(out), err
	}
	if err := p.prepare(ctx); err != nil {
		return passkey.NewSessionDeleteResult(out), err
	}
	protocol, err := webauthn.New(s.owner.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return passkey.NewSessionDeleteResult(out), err
	}
	_, err = protocol.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: p.protocolContext(), CeremonyID: r.CeremonyID, Origin: p.request.Origin, Response: r.Response, ExpectedVersion: 1, ExpectedCredentialVersion: p.authProtocol.Version})
	out.Receipt, out.Outcome = p.result, p.result.Outcome
	if err == nil && (p.read.ValidateAt(s.owner.config().Clock.Now().UTC()) != nil || ctx.Err() != nil) {
		err = identity.UnavailableError{}
	}
	return passkey.NewSessionDeleteResult(out), err
}

// RecoverDelete returns only original durability metadata under an actual
// currently valid same-user passkey session and delete policy. After successful
// removal the original session is invalid: authenticate with a surviving key
// before using this recovery entry point. Query must retain the original
// command and target; recovery never repeats an assertion or removal, issues a
// session, adopts an old validity lease or treats an unknown outcome as rollback.
func (s *SessionDeletionService) RecoverDelete(ctx context.Context, custody passkey.SessionDeleteRequest, query identity.RecoveryQuery) (passkey.SessionDeleteResult, error) {
	if ctx == nil || s == nil || s.owner == nil {
		return passkey.SessionDeleteResult{}, identity.InvalidInputError{Field: "passkey_session_deletion"}
	}
	ctx, stop := context.WithTimeout(ctx, s.owner.config().Protocol.MaximumDuration)
	defer stop()
	r, read, record, err := s.request(ctx, custody)
	if err != nil {
		return passkey.SessionDeleteResult{}, err
	}
	if query.TenantID != record.TenantID || query.UserID != record.UserID || query.ActorKind != authorization.SubjectUser || string(query.ActorID) != string(record.UserID) || query.OperationID != "identity.passkey.delete" || query.RecordID != string(r.ReferenceID) || query.AnonymousFlowID != "" {
		return passkey.SessionDeleteResult{}, identity.ForbiddenError{}
	}
	p := &sessionDeleteInvocation{service: s, request: r, read: read, record: record}
	coordinator, _, err := s.runtime(p)
	if err != nil {
		return passkey.SessionDeleteResult{}, err
	}
	receipt, err := coordinator.RecoverFeatureCommand(ctx, query, r.Caller)
	if stopped := ctx.Err(); stopped != nil {
		return passkey.SessionDeleteResult{}, stopped
	}
	if read.ValidateAt(s.owner.config().Clock.Now().UTC()) != nil {
		return passkey.SessionDeleteResult{}, identity.UnavailableError{}
	}
	return passkey.NewSessionDeleteResult(passkey.DeleteResult{CommandID: query.CommandID, Receipt: receipt, Outcome: receipt.Outcome, Replayed: true}), err
}
