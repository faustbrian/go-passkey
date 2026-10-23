package passkey

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SignupRequest carries the original anonymous browser flow and cookie for an
// explicitly enabled passkey-first profile without email or password. It does
// not select a user, tenant, RP, actor or proof. CommandID, CorrelationID and
// ingress dimensions come from trusted server code; Origin must exactly match
// the trusted flow origin. Each protected phase uses its own original command,
// retained on retries. The session owner retains the original flow's remember
// policy; no continuation may upgrade it. Zero values grant no authority.
// This data carrier performs no validation, verification or durable mutation.
type SignupRequest struct {
	CommandID                              identity.CommandID
	FlowID                                 identity.PreAuthTransactionID
	Cookie                                 session.Token
	Origin, Network, Device, CorrelationID string
}

// SignupCompletion adds the original committed registration ceremony and raw
// response to the completion phase's original command. Response is borrowed for
// the call, not owned or validated here; the native owner must bound and copy it
// before parsing or retaining it. Label is untrusted display metadata. The native
// owner must verify the actual resident-required, UV-required, none-attestation,
// ES256 protocol result before creating an account, credential, MFA authority,
// authentication or session in the same durable work. Retries retain exact
// original input and must not issue new authentication from historical results.
type SignupCompletion struct {
	SignupRequest
	CeremonyID string
	Response   []byte
	Label      string
}

// SignupResult carries session-owner issuance and CSRF custody, not evidence of
// verification or commitment by itself. The native owner must return secrets
// only for the fresh winner after acknowledged coherent commit; aborted, unknown
// and historical outcomes reveal nothing. Value copies retain the session
// owner's shared reveal-once permissions and do not permit another delivery.
type SignupResult struct {
	Session session.IssueResult
	CSRF    session.CSRFToken
}

// KeyedSignupOptionsRequest retains exact original browser possession and the
// request key. CommandID must be empty: the existing request-key owner allocates
// the original random command and its correlation, and matching retries retain
// that original intent. Caller is trusted service attribution, not browser-
// selected user, tenant, actor or RP authority. Use KeyedRegistrationOptionsResult
// for the result: only a fresh committed winner may reveal options; replay,
// pending and unknown outcomes are metadata-only and cannot create a ceremony.
type KeyedSignupOptionsRequest struct {
	SignupRequest
	IdempotencyKey identity.IdempotencyKey
	Caller         authorization.DecisionContext
}

// Format prevents browser-flow and trusted-ingress disclosure.
func (SignupRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SignupRequest(redacted)"))
}

// MarshalJSON prohibits implicit browser-flow export.
func (SignupRequest) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit browser-flow export.
func (SignupRequest) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format prevents raw attestation and original-flow disclosure.
func (SignupCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SignupCompletion(redacted)"))
}

// MarshalJSON prohibits implicit registration-response export.
func (SignupCompletion) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit registration-response export.
func (SignupCompletion) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format prevents authentication and CSRF custody disclosure.
func (SignupResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.SignupResult(redacted)"))
}

// MarshalJSON prohibits implicit authentication export.
func (SignupResult) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit authentication export.
func (SignupResult) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format prevents request-key, caller and browser-flow disclosure.
func (KeyedSignupOptionsRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.KeyedSignupOptionsRequest(redacted)"))
}

// MarshalJSON prohibits implicit keyed browser-flow export.
func (KeyedSignupOptionsRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit keyed browser-flow export.
func (KeyedSignupOptionsRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
