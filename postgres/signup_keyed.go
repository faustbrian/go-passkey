package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	passkey "github.com/faustbrian/go-passkey"
)

// KeyedRegistrationOptions admits one original signup options request through
// the existing kernel request-key owner. It requires explicit OptionsRequests
// configuration and empty CommandID. Matching retries authenticate the immutable
// original cookie/input digest before metadata disclosure, even after the flow
// is consumed or expires. Historical outcomes reveal no options and never rerun
// admission, allocate an identity or refresh original authority. Only a freshly
// acknowledged winner receives the protocol owner's reveal-once options.
func (s *SignupService) KeyedRegistrationOptions(ctx context.Context, r passkey.KeyedSignupOptionsRequest) (out KeyedRegistrationOptionsResult, err error) {
	if ctx == nil || s == nil || s.core == nil || s.optionsRequests.state == nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.CommandID != "" {
		return out, invalidOptionsRequest()
	}
	c := s.core.config()
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	k := s.optionsRequests.state()
	op := signupOperation(false)
	caller := r.Caller
	if _, err := identity.ParsePreAuthTransactionID(string(r.FlowID)); err != nil {
		return out, invalidOptionsRequest()
	}
	if caller.Validate() != nil || caller.Request.Tenant != authorization.TenantID(c.Protocol.TenantID) || caller.Request.Subject.ID != authorization.SubjectID(c.Flow.ActorID) || caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Action != authorization.Action(op.OperationID) || caller.Request.Resource.Type != "identity.anonymous-flow" || caller.Request.Resource.ID != authorization.ResourceID(r.FlowID) || r.Origin != c.Flow.Origin || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Device) == 0 || len(r.Device) > 128 {
		return out, identity.ForbiddenError{}
	}
	fields, err := optionsProtocolFields(c.Protocol, c.Profile.RPNamespace, c.Flow.PolicyID, c.Flow.PolicyVersion)
	if err != nil {
		return out, err
	}
	digest, err := r.Cookie.Digest(k.token, string(c.Protocol.TenantID))
	if err != nil {
		return out, err
	}
	fields = append(fields, optionsBytes("passkey.options.cookie", digest.Sum[:]), optionsUint("passkey.options.cookie-key", uint64(digest.KeyVersion)), optionsText("passkey.options.flow", string(r.FlowID)), optionsText("passkey.options.origin", r.Origin), optionsText("passkey.options.network", r.Network), optionsText("passkey.options.device", r.Device), optionsText("passkey.options.signup", "passkey-first-v1"), optionsText("passkey.options.callback", c.Flow.CallbackURL), optionsText("passkey.options.action", c.Flow.Action), optionsText("passkey.options.audience", c.Profile.Audience), optionsText("passkey.options.global", c.Profile.GlobalAuthorityID), optionsText("passkey.options.policy-namespace", c.Profile.PolicyNamespace))
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, err
	}
	p := &signupInvocation{Store: s.core.protocol, service: s, operation: op}
	_, registry, err := p.runtime()
	if err != nil {
		return out, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.core.pool, registry, c.Coordinator, k.request)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: c.Protocol.TenantID, ActorID: c.Flow.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: op.OperationID}
	admission, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, optionsRequestCaller(caller, scope, k.request.Policy.PolicyVersion))
	if err != nil {
		return out, err
	}
	out.CommandID = admission.CommandID
	q := identity.RecoveryQuery{CommandID: admission.CommandID, TenantID: scope.TenantID, AnonymousFlowID: string(r.FlowID), ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: op.OperationID, RecordID: string(admission.CommandID)}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, q, caller)
	if err != nil || out.Replayed {
		return out, err
	}
	native := r.SignupRequest
	native.CommandID, native.CorrelationID = admission.CommandID, string(admission.CommandID)
	options, nativeErr := s.RegistrationOptions(ctx, native)
	out.Receipt, _, err = optionsMetadata(ctx, coordinator, q, caller)
	if nativeErr != nil {
		out.Replayed = out.Receipt.Outcome != identity.CommitOutcomeInvalid
		if out.Replayed {
			return out, err
		}
		if err != nil {
			return out, identity.UnknownCommitError{CommandID: out.CommandID}
		}
		return out, nativeErr
	}
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	out.Options = options
	return out, nil
}
