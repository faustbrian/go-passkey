package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RecoverEnrollment discloses or reconciles only the exact original options or
// completion command under the current coordinator QueryPolicy. The caller must
// supply trusted authenticated attribution; a historical proof or ceremony is
// not disclosure authority. Results are historical command metadata, never a
// challenge, verified credential, session or permission to replay effects.
// Calls borrow the configured pool and honor its bounded operation deadline.
func (s *EnrollmentService) RecoverEnrollment(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out identity.CommandResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil {
		return out, identity.InvalidInputError{Field: "passkey_enrollment_recovery"}
	}
	c := s.config()
	finish := q.OperationID == enrollmentOperation(true).OperationID
	op := enrollmentOperation(finish)
	if q.OperationID != op.OperationID || q.TenantID != c.Protocol.TenantID || q.UserID == "" || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) || q.RecordID != string(q.CommandID) || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	source := c.OptionsSource
	if finish {
		source = c.RegistrationSource
	}
	p := &enrollmentInvocation{Store: s.protocol, service: s, source: source, operation: op}
	coordinator, _, err := s.runtime(p)
	if err != nil {
		return out, err
	}
	return coordinator.RecoverFeatureCommand(ctx, q, caller)
}
