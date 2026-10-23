package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	webauthn "github.com/faustbrian/go-webauthn"
)

// OptionsRequestConfig explicitly enables original keyed-options admission.
// Zero keeps the released keyless APIs unchanged and disables keyed methods.
// It owns no journal, transaction, goroutine or resource lifetime. Install the
// kernel's RequestKeyMigrationSource before use; immutable mappings have the
// kernel's non-expiring retention and unknown-outcome reconciliation semantics.
type OptionsRequestConfig struct{ state func() optionsRequestKeys }

type optionsRequestKeys struct {
	request kernel.RequestKeyConfig
	token   session.DigestKey
	csrf    session.CSRFKey
}

// NewOptionsRequestConfig freezes existing request-key and digest owners without
// IO. token and csrf must be dedicated independent keys used only for this
// original-input correlation, not session/preauth lookup or CSRF validation.
// Keep these keys unchanged while mappings are retained: replacing them causes
// original requests to conflict, never silently allocates replacement commands.
// QueryPolicy and AdmissionPolicy must additionally be configured on the native
// service's Coordinator, and RequestKeys.Policy must authorize request admission.
// Full request-key policy validation is performed by the native constructor.
func NewOptionsRequestConfig(keys kernel.RequestKeyConfig, token session.DigestKey, csrf session.CSRFKey) (OptionsRequestConfig, error) {
	if keys.Namespace == "" || keys.Policy.PolicyVersion == 0 || token == (session.DigestKey{}) || csrf.Version() == 0 {
		return OptionsRequestConfig{}, invalidOptionsRequest()
	}
	return OptionsRequestConfig{state: func() optionsRequestKeys { return optionsRequestKeys{keys, token, csrf} }}, nil
}

func (OptionsRequestConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.OptionsRequestConfig(redacted)"))
}
func (OptionsRequestConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (OptionsRequestConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// KeyedRegistrationOptionsRequest carries the exact original key and native
// authenticated enrollment input. Primary.CommandID and RecordID must be empty:
// the existing request-key owner allocates the original random command. Caller
// is trusted authenticated attribution, not browser-selected subject authority.
// Session/CSRF possession and every structural proof field bind original intent;
// consumed or expired proofs may reconcile metadata but never create a ceremony.
type KeyedRegistrationOptionsRequest struct {
	RegistrationRequest
	IdempotencyKey identity.IdempotencyKey
}

// KeyedSigninOptionsRequest carries exact original browser possession and key.
// CommandID must be empty; correlation is selected from the original random
// command. Caller is trusted service attribution and must match the configured
// actor/tenant/action. The query resource is identity.anonymous-flow with FlowID,
// as required by the kernel metadata owner, distinct from execution's preauth
// resource. Identified mode retains the exact owner-canonical Identifier.
type KeyedSigninOptionsRequest struct {
	SigninRequest
	IdempotencyKey identity.IdempotencyKey
	Caller         authorization.DecisionContext
}

// KeyedDiscoverableOptionsRequest selects identifier-free options under the same
// original-key contract. It cannot reinterpret an identified request, and never
// supplies user, tenant, actor or RP authority from browser data.
type KeyedDiscoverableOptionsRequest struct {
	DiscoverableSigninRequest
	IdempotencyKey identity.IdempotencyKey
	Caller         authorization.DecisionContext
}

// KeyedRegistrationOptionsResult retains the original command and safe native
// receipt. Options exists only for the fresh committed winner; all replays,
// pending and unknown outcomes are metadata-only. Replayed does not authorize
// another reveal. A zero Receipt means no command outcome was established.
type KeyedRegistrationOptionsResult struct {
	CommandID identity.CommandID
	Receipt   identity.CommandResult
	Replayed  bool
	Options   webauthn.RegistrationOptions
}

// KeyedAssertionOptionsResult has the same commit/replay semantics as keyed
// registration, without authenticating anybody. Only the fresh committed winner
// can TransferJSON once. Completion still needs its own one-use native command.
type KeyedAssertionOptionsResult struct {
	CommandID identity.CommandID
	Receipt   identity.CommandResult
	Replayed  bool
	Options   webauthn.AssertionOptions
}

func (KeyedRegistrationOptionsRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.KeyedRegistrationOptionsRequest(redacted)"))
}
func (KeyedSigninOptionsRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.KeyedSigninOptionsRequest(redacted)"))
}
func (KeyedDiscoverableOptionsRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.KeyedDiscoverableOptionsRequest(redacted)"))
}
func (KeyedRegistrationOptionsResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.KeyedRegistrationOptionsResult(redacted)"))
}
func (KeyedAssertionOptionsResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.KeyedAssertionOptionsResult(redacted)"))
}
func (KeyedRegistrationOptionsRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedRegistrationOptionsRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedSigninOptionsRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedSigninOptionsRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedDiscoverableOptionsRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedDiscoverableOptionsRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedRegistrationOptionsResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedRegistrationOptionsResult) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedAssertionOptionsResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (KeyedAssertionOptionsResult) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func invalidOptionsRequest() error {
	return identity.InvalidInputError{Field: "passkey_options_request"}
}

// Safe protocol framing deliberately excludes opaque cryptographic keys. RP
// versions are the protocol owner's explicit in-flight profile boundary.
func optionsProtocolFields(c webauthn.Config, namespace, policy string, version uint64) ([]identity.FeatureField, error) {
	wire, err := json.Marshal(struct {
		Tenant            identity.TenantID
		RP                webauthn.RelyingParty
		Extensions        webauthn.ExtensionRequestSet
		Algorithms        []webauthn.Algorithm
		Development       bool
		Namespace, Policy string
		Version           uint64
	}{c.TenantID, c.RelyingParty, c.Extensions, c.Algorithms, c.DevelopmentLocalhostHTTP, namespace, policy, version})
	if err != nil {
		return nil, invalidOptionsRequest()
	}
	digest := sha256.Sum256(wire)
	return []identity.FeatureField{optionsBytes("passkey.options.profile", digest[:])}, nil
}

func optionsText(name, value string) identity.FeatureField {
	return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
}
func optionsBytes(name string, value []byte) identity.FeatureField {
	return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: value}}
}
func optionsUint(name string, value uint64) identity.FeatureField {
	return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
}

func optionsRequestCaller(caller authorization.DecisionContext, scope kernel.RequestKeyScope, version uint64) authorization.DecisionContext {
	caller = caller.Clone()
	caller.PolicyRevision = authorization.Revision(version)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	return caller
}

func optionsMetadata(ctx context.Context, coordinator *kernel.Coordinator, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, bool, error) {
	observed, err := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if observed.Absent && err == nil {
		return identity.CommandResult{}, false, nil
	}
	if observed.Validate() != nil {
		if err == nil {
			err = identity.UnavailableError{}
		}
		return identity.CommandResult{}, false, err
	}
	// The public recovery owner validates the complete frozen receipt and, only
	// for expired pending work, invokes its existing participant reconciliation.
	receipt, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if err == nil {
		switch receipt.Outcome {
		case identity.CommitOutcomeCommitted:
			if receipt.Validate() != nil {
				return identity.CommandResult{}, true, identity.UnavailableError{}
			}
		case identity.CommitOutcomeInProgress:
			err = identity.InProgressError{CommandID: q.CommandID, RetryAfter: receipt.RetryAfter}
		case identity.CommitOutcomeNotCommitted:
			err = identity.NotCommittedError{CommandID: q.CommandID}
		case identity.CommitOutcomeUnknown:
			err = identity.UnknownCommitError{CommandID: q.CommandID}
		default:
			err = identity.UnavailableError{}
		}
	}
	return receipt, true, err
}

// KeyedRegistrationOptions admits the original request through the existing
// kernel request-key owner before native preparation. Matching retries recover
// only original command metadata, even after proof consumption. Exact possession
// digests and structural input are checked before historical metadata disclosure.
func (s *EnrollmentService) KeyedRegistrationOptions(ctx context.Context, r KeyedRegistrationOptionsRequest) (out KeyedRegistrationOptionsResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.config().OptionsRequests.state == nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.Primary.CommandID != "" || r.Primary.RecordID != "" {
		return out, invalidOptionsRequest()
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	k := c.OptionsRequests.state()
	op := enrollmentOperation(false)
	caller := r.Primary.Caller
	if caller.Validate() != nil || r.Primary.TenantID != c.Protocol.TenantID || r.Primary.TargetSubjectID != "" || caller.Request.Tenant != authorization.TenantID(c.Protocol.TenantID) || caller.Request.Subject.Kind != authorization.SubjectUser || caller.Request.Action != authorization.Action(op.OperationID) || caller.Request.Subject.ID != authorization.SubjectID(r.Primary.Proof.Proof.Subject) || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Device) > 128 || len(r.Origin) > 2048 {
		return out, identity.ForbiddenError{}
	}
	fields, err := optionsProtocolFields(c.Protocol, c.RPNamespace, c.PolicyID, c.PolicyVersion)
	if err != nil {
		return out, err
	}
	token, err := session.ParseToken(r.Primary.Session.Token())
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	digest, err := token.Digest(k.token, string(c.Protocol.TenantID))
	if err != nil {
		return out, err
	}
	proof := r.Primary.Proof
	fields = append(fields, optionsBytes("passkey.options.session", digest.Sum[:]), optionsUint("passkey.options.session-key", uint64(digest.KeyVersion)), optionsText("passkey.options.origin", r.Origin), optionsText("passkey.options.network", r.Network), optionsText("passkey.options.device", r.Device), optionsText("passkey.options.proof.id", string(proof.Proof.ID)), optionsText("passkey.options.proof.tenant", proof.Proof.Tenant), optionsText("passkey.options.proof.subject", proof.Proof.Subject), optionsText("passkey.options.proof.method", proof.Proof.Method), optionsUint("passkey.options.proof.assurance", uint64(proof.Proof.Assurance)), optionsText("passkey.options.proof.purpose", string(proof.Proof.Purpose)), optionsText("passkey.options.proof.audience", proof.Proof.Audience), optionsText("passkey.options.proof.session", proof.SessionID), optionsUint("passkey.options.proof.version", proof.SessionVersion), optionsText("passkey.options.proof.action", proof.Action), identity.FeatureField{Name: "passkey.options.proof.issued", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: proof.Proof.IssuedAt}}, identity.FeatureField{Name: "passkey.options.proof.expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: proof.Proof.ExpiresAt}})
	if r.Primary.CSRFToken != (session.CSRFToken{}) {
		csrf, err := r.Primary.CSRFToken.Digest(k.csrf, session.CSRFBinding{TenantID: c.Protocol.TenantID, SessionID: proof.SessionID, SessionVersion: proof.SessionVersion})
		if err != nil {
			return out, err
		}
		binding, err := csrf.Bindings()
		if err != nil {
			return out, err
		}
		fields = append(fields, optionsBytes("passkey.options.csrf", binding.Digest[:]), optionsUint("passkey.options.csrf-key", uint64(binding.KeyVersion)))
	}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, err
	}
	p := &enrollmentInvocation{Store: s.protocol, service: s, source: c.OptionsSource, operation: op}
	_, registry, err := s.runtime(p)
	if err != nil {
		return out, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, c.Coordinator, k.request)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: c.Protocol.TenantID, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, Method: "POST", RouteID: op.OperationID}
	admission, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, optionsRequestCaller(caller, scope, k.request.Policy.PolicyVersion))
	if err != nil {
		return out, err
	}
	out.CommandID = admission.CommandID
	q := identity.RecoveryQuery{CommandID: admission.CommandID, TenantID: scope.TenantID, UserID: identity.UserID(scope.ActorID), ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: op.OperationID, RecordID: string(admission.CommandID)}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, q, caller)
	if err != nil || out.Replayed {
		return out, err
	}
	native := r.RegistrationRequest
	native.Primary.CommandID = admission.CommandID
	native.Primary.Caller.CorrelationID = string(admission.CommandID)
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

// KeyedAuthenticationOptions retains identified native signin's exact original
// request key, browser, identifier and profile. Replay never reruns risk or
// creates a new challenge; completion and authentication remain one-use.
func (s *SigninService) KeyedAuthenticationOptions(ctx context.Context, r KeyedSigninOptionsRequest) (KeyedAssertionOptionsResult, error) {
	return s.keyedAuthenticationOptions(ctx, r, false)
}

// KeyedDiscoverableAuthenticationOptions selects identifier-free resident
// options without changing the released identified or discoverable APIs.
func (s *SigninService) KeyedDiscoverableAuthenticationOptions(ctx context.Context, r KeyedDiscoverableOptionsRequest) (KeyedAssertionOptionsResult, error) {
	return s.keyedAuthenticationOptions(ctx, KeyedSigninOptionsRequest{SigninRequest: r.DiscoverableSigninRequest.request(), IdempotencyKey: r.IdempotencyKey, Caller: r.Caller}, true)
}

func (s *SigninService) keyedAuthenticationOptions(ctx context.Context, r KeyedSigninOptionsRequest, discoverable bool) (out KeyedAssertionOptionsResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.config().OptionsRequests.state == nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.CommandID != "" {
		return out, invalidOptionsRequest()
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	k := c.OptionsRequests.state()
	op := signinOperation(false)
	caller := r.Caller
	if _, err := identity.ParsePreAuthTransactionID(string(r.FlowID)); err != nil {
		return out, invalidOptionsRequest()
	}
	if caller.Validate() != nil || caller.Request.Tenant != authorization.TenantID(c.Protocol.TenantID) || caller.Request.Subject.ID != authorization.SubjectID(c.Flow.ActorID) || caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Action != authorization.Action(op.OperationID) || r.Origin != c.Flow.Origin || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Device) == 0 || len(r.Device) > 128 || !discoverable && (len(r.Identifier) == 0 || len(r.Identifier) > 320) || discoverable && r.Identifier != "" {
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
	fields = append(fields, optionsBytes("passkey.options.cookie", digest.Sum[:]), optionsUint("passkey.options.cookie-key", uint64(digest.KeyVersion)), optionsText("passkey.options.flow", string(r.FlowID)), optionsText("passkey.options.identifier", r.Identifier), optionsText("passkey.options.origin", r.Origin), optionsText("passkey.options.network", r.Network), optionsText("passkey.options.device", r.Device), optionsText("passkey.options.discoverable", strconv.FormatBool(discoverable)), optionsText("passkey.options.callback", c.Flow.CallbackURL), optionsText("passkey.options.action", c.Flow.Action), optionsText("passkey.options.audience", c.Profile.Audience), optionsText("passkey.options.global", c.Profile.GlobalAuthorityID), optionsText("passkey.options.policy-namespace", c.Profile.PolicyNamespace))
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, err
	}
	p := &signinInvocation{Store: s.protocol, service: s, operation: op}
	_, registry, err := p.runtime()
	if err != nil {
		return out, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, c.Coordinator, k.request)
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
	native := r.SigninRequest
	native.CommandID, native.CorrelationID = admission.CommandID, string(admission.CommandID)
	var options webauthn.AssertionOptions
	var nativeErr error
	if discoverable {
		options, nativeErr = s.DiscoverableAuthenticationOptions(ctx, DiscoverableSigninRequest{CommandID: native.CommandID, FlowID: native.FlowID, Cookie: native.Cookie, Origin: native.Origin, Network: native.Network, Device: native.Device, CorrelationID: native.CorrelationID})
	} else {
		options, nativeErr = s.AuthenticationOptions(ctx, native)
	}
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
