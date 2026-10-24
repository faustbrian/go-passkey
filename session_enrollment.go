package passkey

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SessionEnrollmentRequest retains current passkey-session custody and the
// exact intended additional resident credential's display label. It grants no
// authority by itself. The native owner must authenticate the selected
// transport, original cookie CSRF when applicable and self-user Caller, then
// require a genuine UV assertion specifically authorizing this enrollment.
// Origin and Network are bounded trusted ingress, never browser-selected RP or
// tenant overrides. Label follows DeviceLabel; it is not authenticator trust.
// All phases bind this unchanged intent and the complete original session,
// current identity/credential/factor policy and original freshness ceiling.
// Callers must not mutate custody during an invocation.
type SessionEnrollmentRequest struct {
	value func() SessionEnrollmentRequestSpec
}

// SessionEnrollmentRequestSpec is the deliberate, unredacted ingress or native
// projection of session/intent custody. Do not log or serialize it. Constructing
// custody does not validate authentication, ingress or policy; the native owner
// validates every field. Caller and opaque session values are borrowed unchanged.
type SessionEnrollmentRequestSpec struct {
	Credential session.Credential
	CSRFToken  session.CSRFToken
	Caller     authorization.DecisionContext
	Label      string
	Origin     string
	Network    string
}

// NewSessionEnrollmentRequest retains an exact snapshot of supplied fields,
// without IO or authorization. Closure storage prevents fmt from reaching PII
// through unexported enclosing fields, where Go skips nested Formatter methods.
func NewSessionEnrollmentRequest(spec SessionEnrollmentRequestSpec) SessionEnrollmentRequest {
	return SessionEnrollmentRequest{value: func() SessionEnrollmentRequestSpec { return spec }}
}

// Bindings explicitly projects the original borrowed session/intent for native
// validation. Zero custody denies; a successful projection grants no authority.
func (r SessionEnrollmentRequest) Bindings() (SessionEnrollmentRequestSpec, error) {
	if r.value == nil {
		return SessionEnrollmentRequestSpec{}, ErrInvalidInput
	}
	return r.value(), nil
}

// SessionEnrollmentOptionsRequest admits one original action-bound assertion
// ceremony. Matching key retries return original metadata, never a replacement
// challenge or renewed authority. The native owner allocates its command ID.
type SessionEnrollmentOptionsRequest struct {
	SessionEnrollmentRequest
	IdempotencyKey identity.IdempotencyKey
}

// SessionEnrollmentAuthorization consumes the genuine assertion and creates
// the subsequent registration ceremony in one protected transaction. Its key
// is distinct from the assertion-options key. CeremonyID identifies those
// original assertion options; Response is bounded untrusted WebAuthn JSON,
// not proof by shape. The original assertion's authority expiry remains the
// ceiling for registration, even if protocol ceremony validity ends later.
// Response is borrowed only during the invocation and must not be mutated.
type SessionEnrollmentAuthorization struct {
	value func() SessionEnrollmentAuthorizationSpec
}

// SessionEnrollmentAuthorizationSpec is explicit unredacted ingress/projection,
// not safe diagnostics. Response is borrowed and must remain unchanged during
// use; only the protocol owner can verify it. No authentication occurs here.
type SessionEnrollmentAuthorizationSpec struct {
	SessionEnrollmentRequest
	IdempotencyKey identity.IdempotencyKey
	CeremonyID     string
	Response       []byte
}

// NewSessionEnrollmentAuthorization retains original B-phase custody without
// copying or parsing Response. The caller owns its bounded bytes and lifetime.
func NewSessionEnrollmentAuthorization(spec SessionEnrollmentAuthorizationSpec) SessionEnrollmentAuthorization {
	return SessionEnrollmentAuthorization{value: func() SessionEnrollmentAuthorizationSpec { return spec }}
}

// Bindings explicitly projects borrowed assertion custody for native validation.
// Zero denies. The returned fields and response must not be logged or mutated.
func (r SessionEnrollmentAuthorization) Bindings() (SessionEnrollmentAuthorizationSpec, error) {
	if r.value == nil {
		return SessionEnrollmentAuthorizationSpec{}, ErrInvalidInput
	}
	return r.value(), nil
}

// SessionEnrollmentCompletion finishes that original authorized registration.
// CommandID is the stable, canonical identity of this single-use completion,
// not permission to enroll; preserve it and the original ceremony/response for
// recovery. This non-keyed phase deliberately has no IdempotencyKey. The native
// owner must consume the genuine registration, persist the identity-facing
// credential/mapping and required lifecycle together, and enforce the original
// authorization ceiling and current session/owner/factor policy before commit.
// Response is bounded untrusted JSON borrowed for this invocation only.
type SessionEnrollmentCompletion struct {
	value func() SessionEnrollmentCompletionSpec
}

// SessionEnrollmentCompletionSpec is explicit unredacted ingress/projection of
// the original non-keyed C phase, never safe diagnostics or verified permission.
// Response remains borrowed; callers own its bounds, lifetime and immutability.
type SessionEnrollmentCompletionSpec struct {
	SessionEnrollmentRequest
	CommandID  identity.CommandID
	CeremonyID string
	Response   []byte
}

// NewSessionEnrollmentCompletion retains original completion custody without
// parsing or copying Response, creating authority or allocating another command.
func NewSessionEnrollmentCompletion(spec SessionEnrollmentCompletionSpec) SessionEnrollmentCompletion {
	return SessionEnrollmentCompletion{value: func() SessionEnrollmentCompletionSpec { return spec }}
}

// Bindings explicitly projects borrowed completion custody for native validation.
// Zero denies. The result must not be logged or treated as authenticated input.
func (r SessionEnrollmentCompletion) Bindings() (SessionEnrollmentCompletionSpec, error) {
	if r.value == nil {
		return SessionEnrollmentCompletionSpec{}, ErrInvalidInput
	}
	return r.value(), nil
}

// SessionEnrollmentResult contains native completion durability. Credential is
// safe metadata only for the fresh acknowledged winner. Matching recovery is
// metadata-only and must not issue credentials, options or a new session.
// Callers must preserve unknown outcomes rather than retry under a new command.
type SessionEnrollmentResult struct {
	value func() SessionEnrollmentResultSpec
}

// SessionEnrollmentResultSpec is an explicit native result projection. Select
// only permitted public metadata for transport; command correlation and display
// metadata are not safe implicit diagnostics. Credential is borrowed immutable
// metadata, never raw WebAuthn credential bytes or session bearer custody.
type SessionEnrollmentResultSpec struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	Replayed   bool
	Receipt    identity.CommandResult
	Credential *CredentialMetadata
}

// NewSessionEnrollmentResult retains exact native durability and borrowed
// immutable metadata without publishing it or changing the command outcome.
func NewSessionEnrollmentResult(spec SessionEnrollmentResultSpec) SessionEnrollmentResult {
	return SessionEnrollmentResult{value: func() SessionEnrollmentResultSpec { return spec }}
}

// Bindings explicitly projects original completion metadata. Zero denies; a
// successful projection is not evidence that any native transaction committed.
func (r SessionEnrollmentResult) Bindings() (SessionEnrollmentResultSpec, error) {
	if r.value == nil {
		return SessionEnrollmentResultSpec{}, ErrInvalidInput
	}
	return r.value(), nil
}

// Format excludes original session and enrollment intent from diagnostics.
func (SessionEnrollmentRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionEnrollmentRequest(redacted)"))
}

// MarshalJSON requires explicit credential-free projection.
func (SessionEnrollmentRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit current-session and intent export.
func (SessionEnrollmentRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes original request-key and session custody from diagnostics.
func (SessionEnrollmentOptionsRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionEnrollmentOptionsRequest(redacted)"))
}

// MarshalJSON requires explicit credential-free projection.
func (SessionEnrollmentOptionsRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit original-session/key export.
func (SessionEnrollmentOptionsRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes the original assertion and enrollment intent from diagnostics.
func (SessionEnrollmentAuthorization) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionEnrollmentAuthorization(redacted)"))
}

// MarshalJSON requires deliberate projection, not assertion export.
func (SessionEnrollmentAuthorization) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit original assertion and key export.
func (SessionEnrollmentAuthorization) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes original command and attestation custody from diagnostics.
func (SessionEnrollmentCompletion) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionEnrollmentCompletion(redacted)"))
}

// MarshalJSON requires deliberate projection, not attestation export.
func (SessionEnrollmentCompletion) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit original command/attestation export.
func (SessionEnrollmentCompletion) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes command correlation and private display metadata.
func (SessionEnrollmentResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionEnrollmentResult(redacted)"))
}

// MarshalJSON requires explicit safe metadata projection.
func (SessionEnrollmentResult) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit durability/correlation export.
func (SessionEnrollmentResult) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }
