package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RecoverSignin authorizes exact historical metadata through the existing
// coordinator query policy. It discloses no challenge, assertion, session,
// bearer or continuation, and never reexecutes the operation. Options retain
// original service actor; verification retains verified self-user attribution.
func (s *SigninService) RecoverSignin(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || s == nil || s.config == nil {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "passkey_signin_recovery"}
	}
	c := s.config()
	finish := q.OperationID == signinOperation(true).OperationID
	op := signinOperation(finish)
	actor, kind := c.Flow.ActorID, authorization.SubjectServiceAccount
	if finish {
		actor, kind = identity.ActorID(q.UserID), authorization.SubjectUser
	}
	if q.OperationID != op.OperationID || q.TenantID != c.Protocol.TenantID || q.ActorID != actor || q.ActorKind != kind || q.RecordID != string(q.CommandID) || q.LinkMode != 0 || finish && (q.UserID == "" || q.AnonymousFlowID != "") || !finish && (q.UserID != "" || q.AnonymousFlowID == "") {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	p := &signinInvocation{Store: s.protocol, service: s, operation: op}
	coordinator, _, err := p.runtime()
	if err != nil {
		return identity.CommandResult{}, err
	}
	return coordinator.RecoverFeatureCommand(ctx, q, caller)
}
