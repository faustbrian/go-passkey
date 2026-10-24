package postgres

import (
	"context"
	"crypto/hmac"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	"github.com/jackc/pgx/v5"
)

// RecoverSignup authorizes and reconciles only the original completion's
// durability metadata. Retain CommandID, FlowID, original cookie/origin and
// CeremonyID. The caller is trusted service attribution on identity.anonymous-flow,
// not a browser-selected identity. The native context supplies the original
// credential reference; consumers need no private SQL or reconstructed command.
// Original cookie possession and current coordinator query policy are required.
// Consumed/expired flow state and later user epochs do not renew authentication
// or prevent historical metadata recovery. Results contain no bearer, CSRF,
// user/credential payload or permission to execute again. Retain original flow
// records and their configured lookup key while this recovery is supported.
func (s *SignupService) RecoverSignup(ctx context.Context, r passkey.SignupRequest, ceremonyID string, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if len(ceremonyID) != 22 {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "passkey_signup_recovery"}
	}
	return s.recoverSignup(ctx, r, ceremonyID, true, caller)
}

// RecoverRegistrationOptions returns only the original options command's
// historical metadata under original cookie possession and current query policy.
// It never returns a challenge or prepares another ceremony. Keyed callers can
// instead repeat KeyedRegistrationOptions with their exact retained request.
func (s *SignupService) RecoverRegistrationOptions(ctx context.Context, r passkey.SignupRequest, caller authorization.DecisionContext) (identity.CommandResult, error) {
	return s.recoverSignup(ctx, r, "", false, caller)
}

func (s *SignupService) recoverSignup(ctx context.Context, r passkey.SignupRequest, ceremonyID string, finish bool, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || s == nil || s.core == nil || s.core.config == nil {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "passkey_signup_recovery"}
	}
	c := s.core.config()
	op := signupOperation(finish)
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "passkey_signup_recovery"}
	}
	if r.Origin != c.Flow.Origin || caller.Validate() != nil || caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Subject.ID != authorization.SubjectID(c.Flow.ActorID) || caller.Request.Tenant != authorization.TenantID(c.Protocol.TenantID) || caller.Request.Action != authorization.Action(op.OperationID) || caller.Request.Resource.Type != "identity.anonymous-flow" || caller.Request.Resource.ID != authorization.ResourceID(r.FlowID) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	flow, err := sessionpg.ReadPreAuth(ctx, s.core.pool.Raw(), c.Repository, c.Protocol.TenantID, r.FlowID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	stored, err := flow.Bindings()
	if err != nil {
		return identity.CommandResult{}, err
	}
	i := stored.Binding.Intent
	// ReadPreAuth preserves original physical/record agreement. Compare original
	// possession with its owner-framed digest, deliberately without a live Check:
	// expiry/consumption denies execution, not metadata about that old execution.
	digest, err := r.Cookie.PreAuthDigest(c.Flow.LookupKey, stored.Binding)
	if err != nil || i.Action != c.Flow.Action || i.Origin != r.Origin || i.CallbackURL != c.Flow.CallbackURL || i.PolicyID != c.Flow.PolicyID || i.Purpose != session.PreAuthSessionIssuance || i.IdentifierBinding != ([32]byte{}) || digest.KeyVersion != stored.Cookie.KeyVersion || !hmac.Equal(digest.Sum[:], stored.Cookie.Sum[:]) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	recordID := string(r.CommandID)
	if finish {
		var wire []byte
		if err := s.core.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signup_contexts WHERE rp_namespace=$1 AND tenant_id=$2 AND ceremony_id=$3`, c.Profile.RPNamespace, string(c.Protocol.TenantID), ceremonyID).Scan(&wire); err != nil {
			if ctx.Err() != nil {
				return identity.CommandResult{}, ctx.Err()
			}
			if errors.Is(err, pgx.ErrNoRows) {
				return identity.CommandResult{}, identity.ForbiddenError{}
			}
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		original, err := decodeSignupContext(wire)
		if err != nil {
			return identity.CommandResult{}, err
		}
		if original.Flow != string(r.FlowID) || original.Namespace != c.Profile.RPNamespace || original.RP != c.Protocol.RelyingParty.ID || original.Actor != string(c.Flow.ActorID) || original.Global != c.Profile.GlobalAuthorityID || original.Policy != c.Profile.PolicyNamespace {
			return identity.CommandResult{}, identity.ForbiddenError{}
		}
		recordID = original.Credential
	}
	p := &signupInvocation{Store: s.core.protocol, service: s, operation: op}
	coordinator, _, err := p.runtime()
	if err != nil {
		return identity.CommandResult{}, err
	}
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: c.Protocol.TenantID, AnonymousFlowID: string(r.FlowID), ActorID: c.Flow.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: recordID}
	return coordinator.RecoverFeatureCommand(ctx, q, caller)
}
