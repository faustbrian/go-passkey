package passkey

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SessionDeleteRequest retains current passkey-session custody and the exact
// intended credential removal. It is not authentication, freshness or recovery
// permission. Native owners must verify the actual session, cookie CSRF when
// selected, self-user policy and genuine action-bound UV, then prove a usable
// independent recovery path in the same transaction as removal.
//
// Closure storage prevents diagnostics from traversing original custody even
// through enclosing unexported fields, where Go skips nested Formatter methods.
type SessionDeleteRequest struct {
	value func() SessionDeleteRequestSpec
}

// SessionDeleteRequestSpec is explicit unredacted ingress/native projection;
// do not log or implicitly serialize it. ReferenceID is the safe inventory
// reference, not a protocol credential ID. ExpectedVersion is its positive
// metadata version, independent of kernel and protocol versions. Origin and
// Network are bounded trusted ingress, not browser-selected tenant/RP scope.
// Credential, CSRFToken and Caller are borrowed unchanged; callers must not
// mutate their custody during use. Native configuration chooses allowed transport.
type SessionDeleteRequestSpec struct {
	Credential      session.Credential
	CSRFToken       session.CSRFToken
	Caller          authorization.DecisionContext
	ReferenceID     identity.CredentialID
	ExpectedVersion uint64
	Origin          string
	Network         string
}

// NewSessionDeleteRequest retains supplied scalar intent and borrowed custody
// without IO, validation or authentication. The native owner validates all fields.
func NewSessionDeleteRequest(spec SessionDeleteRequestSpec) SessionDeleteRequest {
	return SessionDeleteRequest{value: func() SessionDeleteRequestSpec { return spec }}
}

// Bindings deliberately projects the original request for native validation.
// Zero custody denies; successful projection grants no permission.
func (r SessionDeleteRequest) Bindings() (SessionDeleteRequestSpec, error) {
	if r.value == nil {
		return SessionDeleteRequestSpec{}, ErrInvalidInput
	}
	return r.value(), nil
}

// SessionDeleteOptionsRequest selects one original action-bound UV ceremony.
// Its key belongs to canonical identity.passkey.delete. The native owner
// allocates the command; matching retries reveal original metadata only.
type SessionDeleteOptionsRequest struct {
	SessionDeleteRequest
	IdempotencyKey identity.IdempotencyKey
}

// SessionDeleteCompletion carries a genuine assertion for the unchanged original
// session, target/version, origin/network and removal intent. It contains no
// caller-supplied proof or assertion of recovery eligibility. Only the WebAuthn
// owner can verify Response; only native owners can atomically consume it with
// credential removal, current authority, recovery and required effects.
type SessionDeleteCompletion struct {
	value func() SessionDeleteCompletionSpec
}

// SessionDeleteCompletionSpec is an explicit unredacted projection. CeremonyID
// identifies original deletion options. IdempotencyKey must be distinct from
// that options key; preserve both keys and all original inputs after an unknown
// outcome. Response is bounded untrusted JSON borrowed unchanged for the call.
type SessionDeleteCompletionSpec struct {
	SessionDeleteRequest
	IdempotencyKey identity.IdempotencyKey
	CeremonyID     string
	Response       []byte
}

// NewSessionDeleteCompletion borrows original assertion bytes without parsing,
// copying, consuming or authenticating them. The caller owns their lifetime.
func NewSessionDeleteCompletion(spec SessionDeleteCompletionSpec) SessionDeleteCompletion {
	return SessionDeleteCompletion{value: func() SessionDeleteCompletionSpec { return spec }}
}

// Bindings explicitly projects borrowed original completion custody. Zero denies;
// the output must not be logged or treated as verified authentication.
func (r SessionDeleteCompletion) Bindings() (SessionDeleteCompletionSpec, error) {
	if r.value == nil {
		return SessionDeleteCompletionSpec{}, ErrInvalidInput
	}
	return r.value(), nil
}

// SessionDeleteResult retains native durability metadata privately. It contains
// no fresh proof, credential or session. Removal can invalidate the original
// session; acknowledgement of this invocation is not permission to use it again.
// Preserve unknown outcomes and original command custody rather than allocating
// a replacement mutation. No result value by itself proves durable commitment.
type SessionDeleteResult struct{ value func() DeleteResult }

// NewSessionDeleteResult retains exact native metadata without interpreting the
// outcome or granting authority. Borrowed receipt metadata must remain immutable.
func NewSessionDeleteResult(spec DeleteResult) SessionDeleteResult {
	return SessionDeleteResult{value: func() DeleteResult { return spec }}
}

// Bindings explicitly projects existing DeleteResult metadata for permitted
// transport fields or recovery. Zero denies; correlation is not safe diagnostics.
func (r SessionDeleteResult) Bindings() (DeleteResult, error) {
	if r.value == nil {
		return DeleteResult{}, ErrInvalidInput
	}
	return r.value(), nil
}

// Format excludes original session, target and ingress custody.
func (SessionDeleteRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionDeleteRequest(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (SessionDeleteRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit custody export.
func (SessionDeleteRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes original request and options-key custody.
func (SessionDeleteOptionsRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionDeleteOptionsRequest(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (SessionDeleteOptionsRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit custody export.
func (SessionDeleteOptionsRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes original assertion and removal custody.
func (SessionDeleteCompletion) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionDeleteCompletion(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (SessionDeleteCompletion) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit custody export.
func (SessionDeleteCompletion) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes original command/receipt correlation.
func (SessionDeleteResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkey.SessionDeleteResult(redacted)"))
}

// MarshalJSON requires deliberate permitted metadata projection.
func (SessionDeleteResult) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit correlation export.
func (SessionDeleteResult) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }
