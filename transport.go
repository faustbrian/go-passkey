package passkey

import (
	"fmt"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	webauthn "github.com/faustbrian/go-webauthn"
	"time"
)

// RegistrationRequest carries original authenticated session and signed action
// proof through the password owner's custody contract. Trusted ingress supplies
// Caller and Network. User/actor are derived from the actual session, never
// supplied here. Primary.TargetSubjectID must be empty. Origin is allowlisted
// by the protocol owner. This selected profile requires a distinct exact action
// proof for each protected phase, consumed atomically with that phase.
type RegistrationRequest struct {
	Primary                 password.ActionPrimaryRequest
	Origin, Network, Device string
}

// RegistrationCompletion adds the bounded raw browser response and original
// creation command/ceremony ID. The new kernel credential reference is the
// completion CommandID; callers cannot select or replace an existing reference.
// Raw response bytes are borrowed for the call and copied after bounds checks.
type RegistrationCompletion struct {
	RegistrationRequest
	CeremonyID string
	Response   []byte
	Label      string
}

// Format prevents bearer/proof/ingress disclosure.
func (RegistrationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.RegistrationRequest(redacted)"))
}

// Format prevents raw response and authentication-custody disclosure.
func (RegistrationCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.RegistrationCompletion(redacted)"))
}

// SigninRequest carries original browser flow/cookie, exact owner-canonical
// verified email, and trusted ingress dimensions. IDs/correlation are selected
// by the server. Identifier is an exact lookup, not normalized by this adapter.
// Neither user nor actor can be selected by a caller. Cookie is never retained
// in a command. Origin must equal the trusted flow origin byte for byte.
type SigninRequest struct {
	CommandID                                          identity.CommandID
	FlowID                                             identity.PreAuthTransactionID
	Cookie                                             session.Token
	Identifier, Origin, Network, Device, CorrelationID string
}

// SigninCompletion adds the original committed assertion ceremony and bounded
// raw browser response. Expected protocol version is owner-derived, not client
// input. Replays and ambiguous outcomes never return new authentication.
type SigninCompletion struct {
	SigninRequest
	CeremonyID string
	Response   []byte
}

// SigninResult contains a session only after genuine root verification and the
// sole durable command commit. CSRF shares reveal-once custody with that issue.
type SigninResult struct {
	Session session.IssueResult
	CSRF    session.CSRFToken
	// CounterRisk is the root verifier's warning for a backup-eligible
	// non-increasing counter. It is available only with committed signin;
	// it neither declares compromise nor invalidates the synced passkey.
	CounterRisk bool
}

func (SigninRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SigninRequest(redacted)"))
}

// MarshalJSON prohibits implicit browser-flow export.
func (SigninRequest) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit browser-flow export.
func (SigninRequest) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SigninCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SigninCompletion(redacted)"))
}

// MarshalJSON prohibits implicit browser-response export.
func (SigninCompletion) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit browser-response export.
func (SigninCompletion) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SigninResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SigninResult(redacted)"))
}

// MarshalJSON prohibits implicit authentication export.
func (SigninResult) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit authentication export.
func (SigninResult) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// DiscoverableSigninRequest retains the original anonymous browser/remember
// flow and trusted ingress dimensions. There is deliberately no identifier,
// user, actor, RP or tenant selection. IDs and ingress are server-selected;
// Origin must exactly match trusted configuration. Secrets cannot be serialized.
type DiscoverableSigninRequest struct {
	CommandID                              identity.CommandID
	FlowID                                 identity.PreAuthTransactionID
	Cookie                                 session.Token
	Origin, Network, Device, CorrelationID string
}

// DiscoverableSigninCompletion adds the original committed anonymous resident
// ceremony and bounded raw assertion. Only the root verifier's opaque signed
// transition can select a user; caller-supplied handles are never authority.
type DiscoverableSigninCompletion struct {
	DiscoverableSigninRequest
	CeremonyID string
	Response   []byte
}

func (DiscoverableSigninRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.DiscoverableSigninRequest(redacted)"))
}
func (DiscoverableSigninCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.DiscoverableSigninCompletion(redacted)"))
}

// MarshalJSON prohibits implicit browser-flow export.
func (DiscoverableSigninRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit browser-flow export.
func (DiscoverableSigninRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalJSON prohibits implicit browser-response export.
func (DiscoverableSigninCompletion) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit browser-response export.
func (DiscoverableSigninCompletion) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

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

// InventoryRequest supplies trusted ingress attribution and a genuine selected
// session credential. The target is always that session's user. Limit is1..100;
// After is the last returned reference ID, never a protocol credential/handle.
// AttemptID is a distinct server-issued rate identity per logical read, not
// client-selected replay or authorization. Cookie parsing belongs to transport.
type InventoryRequest struct {
	Credential session.Credential
	Caller     authorization.DecisionContext
	AttemptID  identity.CommandID
	After      string
	Limit      int
}

// CredentialMetadata is the explicit safe self-user projection. ReferenceID is
// the identity-owned management reference, not the raw RP credential ID. AAGUID
// and backup flags come only from the protocol owner's stored verified record;
// labels are untrusted display text, never authenticator provenance. Public
// keys, counters, handles, challenges and authentication custody are omitted.
type CredentialMetadata struct {
	ReferenceID                 string
	Version                     uint64
	State, Label                string
	AAGUID                      [16]byte
	BackupEligible, BackupState bool
	CreatedAt                   time.Time
	LastUsedAt                  *time.Time
}

// InventoryPage owns one bounded page and its exclusive keyset cursor. Next is
// empty at the observed end; it grants no authority and is not a durable snapshot
// across subsequent calls. Concurrent changes may appear on later pages.
type InventoryPage struct {
	Credentials []CredentialMetadata
	Next        string
}

func (InventoryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.InventoryRequest(redacted)"))
}
