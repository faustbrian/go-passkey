package passkey

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	webauthn "github.com/faustbrian/go-webauthn"
)

// ConditionalAssertionOptions selects conditional browser presentation of an
// existing anonymous discoverable assertion. It shares the protocol owner's
// original challenge custody: copies and the native options together permit
// only one reveal, including after delivery failure. Zero cannot emit options.
// This is not authentication or evidence of the browser's actual mediation.
type ConditionalAssertionOptions struct{ native webauthn.AssertionOptions }

// NewConditionalAssertionOptions explicitly selects conditional presentation
// without IO, a new ceremony, extended expiry or a new assertion protocol.
// Only anonymous, account-independent discoverable protocol options qualify;
// identity/risk authorization remains the native workflow owner's responsibility.
func NewConditionalAssertionOptions(native webauthn.AssertionOptions) (ConditionalAssertionOptions, error) {
	r, ok := native.Ceremony()
	if !ok || r.Intent.Kind != "get-discoverable" || r.Intent.Context.UserID != "" || r.Intent.Context.AnonymousFlowID == "" || len(r.Intent.AllowedCredentials) != 0 || len(r.Intent.UserHandle) != 0 {
		return ConditionalAssertionOptions{}, ErrInvalidInput
	}
	return ConditionalAssertionOptions{native: native}, nil
}

// Ceremony returns unchanged original protocol metadata, not fresh authority
// or evidence that a browser used conditional mediation. Zero returns false.
func (o ConditionalAssertionOptions) Ceremony() (webauthn.CeremonyRecord, bool) {
	return o.native.Ceremony()
}

// TransferJSON reveals {mediation:"conditional",publicKey:...} exactly once
// through native option custody. The original publicKey JSON is preserved.
// Borrowed bytes are cleared after delivery; the callback owns any explicit
// copy. The browser must check support and deserialize publicKey before get().
// Completion remains ordinary discoverable assertion verification and retains
// the original server expiry even while browser conditional UI remains open.
func (o ConditionalAssertionOptions) TransferJSON(ctx context.Context, deliver func(context.Context, []byte) error) error {
	if ctx == nil || deliver == nil {
		return ErrInvalidInput
	}
	return o.native.TransferJSON(ctx, func(ctx context.Context, native []byte) error {
		// WebAuthn CR20260526 §5.1.4 selects conditional presentation on the
		// outer CredentialRequestOptions, not the signed assertion or publicKey.
		// Delegate challenge generation/custody and keep its entire JSON intact.
		wire := make([]byte, 0, len(native)+len(`"mediation":"conditional",`))
		wire = append(wire, `{"mediation":"conditional",`...)
		wire = append(wire, native[1:]...)
		defer clear(wire)
		return deliver(ctx, wire)
	})
}

// KeyedConditionalOptionsResult retains the existing discoverable command and
// receipt. Only the freshly acknowledged winner receives Options; replay,
// pending and unknown outcomes never reconstruct or reveal a challenge.
// Presentation is not an additional durable mode or request-key namespace.
type KeyedConditionalOptionsResult struct {
	CommandID identity.CommandID
	Receipt   identity.CommandResult
	Replayed  bool
	Options   ConditionalAssertionOptions
}

func (ConditionalAssertionOptions) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.ConditionalAssertionOptions(redacted)"))
}

func (KeyedConditionalOptionsResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.KeyedConditionalOptionsResult(redacted)"))
}

// MarshalJSON requires explicit reveal-once browser projection.
func (ConditionalAssertionOptions) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit challenge/correlation export.
func (ConditionalAssertionOptions) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalJSON prohibits implicit command or challenge export.
func (KeyedConditionalOptionsResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit command or challenge export.
func (KeyedConditionalOptionsResult) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
