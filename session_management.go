package passkey

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SessionUpdateRequest retains current passkey-session custody and the exact
// intended label mutation. It grants no authentication or freshness by itself.
// The native owner must authenticate Credential and selected cookie CSRF,
// authorize Caller, and require a genuine UV assertion bound to this session,
// target, metadata version, label, RP and origin in the protected transaction.
// No password proof or session timestamp substitutes for that assertion.
//
// ReferenceID is the safe identity-facing reference returned by inventory, not
// a raw protocol credential ID. ExpectedVersion is its positive metadata
// version, independent of protocol counters and primary credential authority.
// Name follows DeviceLabel. Origin and Network are bounded trusted ingress;
// tenant/RP and allowed transport come from native configuration, not this input.
// Callers must not mutate input or borrowed opaque custody during an invocation.
type SessionUpdateRequest struct {
	Credential      session.Credential
	CSRFToken       session.CSRFToken
	Caller          authorization.DecisionContext
	ReferenceID     identity.CredentialID
	ExpectedVersion uint64
	Name            string
	Origin          string
	Network         string
}

// SessionUpdateOptionsRequest admits one original action-bound assertion
// ceremony through the existing keyed-command owner. Matching retries return
// original command metadata, never a replacement challenge or fresh permission.
// The server, not the caller, allocates the original command and ceremony IDs.
type SessionUpdateOptionsRequest struct {
	SessionUpdateRequest
	IdempotencyKey identity.IdempotencyKey
}

// SessionUpdateCompletion consumes a genuine assertion atomically with exactly
// the original label mutation. CeremonyID refers to options made for the same
// session and unchanged SessionUpdateRequest. Response is bounded untrusted
// authenticator JSON; only the WebAuthn owner can verify it. The original
// completion key resolves a separate mutation command; a matching retry returns
// durability metadata without re-verification, mutation or a new session.
type SessionUpdateCompletion struct {
	SessionUpdateRequest
	IdempotencyKey identity.IdempotencyKey
	CeremonyID     string
	Response       []byte
}

// Format excludes session/action and display-label custody from diagnostics.
func (SessionUpdateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SessionUpdateRequest(redacted)"))
}

// MarshalJSON requires deliberate credential-free transport projection.
func (SessionUpdateRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit original-session custody export.
func (SessionUpdateRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes the original request and key from diagnostics.
func (SessionUpdateOptionsRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SessionUpdateOptionsRequest(redacted)"))
}

// MarshalJSON requires deliberate credential-free transport projection.
func (SessionUpdateOptionsRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit original-key and session export.
func (SessionUpdateOptionsRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes authenticator input, original ceremony and session custody.
func (SessionUpdateCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SessionUpdateCompletion(redacted)"))
}

// MarshalJSON requires deliberate credential-free transport projection.
func (SessionUpdateCompletion) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText rejects implicit authenticator, original-key and session export.
func (SessionUpdateCompletion) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }
