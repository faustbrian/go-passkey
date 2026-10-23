// Package passkey owns identity-facing resident-passkey workflows. WebAuthn
// verification and cryptographic credential state stay with go-webauthn;
// session persistence and token custody stay with go-identity/session.
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	// ErrInvalidInput rejects an absent or unsupported bounded value. It never
	// includes supplied bytes, credential identifiers or identity metadata.
	ErrInvalidInput = errors.New("passkey: invalid input")
	// ErrPrivateValue prohibits accidental serialization of correlation data.
	// Explicit projection is available to the owned protocol/storage adapter.
	ErrPrivateValue = errors.New("passkey: private value")
	// ErrUnavailable redacts a failed platform or owned dependency operation.
	// It is never evidence that a durable operation rolled back.
	ErrUnavailable = errors.New("passkey: unavailable")
)

// UserHandle is an opaque identity-to-RP handle, not a public user ID, credential
// or authorization grant. Zero is invalid. A repository must persist exactly
// one handle per identity/RP and enforce uniqueness across the whole RP namespace,
// including other tenants. Copies cannot change its bytes. Never log it.
// A closure also hides bytes when fmt traverses an unexported enclosing field,
// where Go deliberately does not invoke the nested value's Formatter method.
type UserHandle struct{ value func() [32]byte }

// NewUserHandle copies an existing exact 32-byte handle losslessly. This is the
// selected go-webauthn resident-registration profile, not a general WebAuthn
// parser or a license to replace an identity's existing handle. Explicit all-zero
// bytes remain distinct from an absent Go value. No IO or authentication occurs.
func NewUserHandle(value []byte) (UserHandle, error) {
	if len(value) != 32 {
		return UserHandle{}, ErrInvalidInput
	}
	var copied [32]byte
	copy(copied[:], value)
	return UserHandle{value: func() [32]byte { return copied }}, nil
}

// Bytes returns an independently owned copy for protocol/storage composition.
// It performs no lookup and grants no cross-tenant resolution or authentication.
func (h UserHandle) Bytes() ([]byte, error) {
	if h.value == nil {
		return nil, ErrInvalidInput
	}
	value := h.value()
	return bytes.Clone(value[:]), nil
}

// Format prevents diagnostic correlation of an opaque user handle.
func (UserHandle) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("passkey.UserHandle(redacted)")) }

// MarshalJSON requires an explicit protocol projection rather than implicit ID export.
func (UserHandle) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText prohibits implicit correlation through text and map keys.
func (UserHandle) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// UserHandlePolicy generates opaque random handles for first enrollment only.
// Its zero value is usable, stateless and concurrency-safe. It has no identity-
// derived fallback, configurable entropy downgrade, resources or goroutines.
// The native owner persists the first committed handle and reuses it; calling
// Generate again must never rotate an already committed identity/RP mapping.
type UserHandlePolicy struct{}

// Generate produces the selected 32-byte profile outside the protected SQL
// transaction. The caller must retain original generated intent on retries and
// atomically bind it to the first mapping. Cancellation before or after entropy
// generation returns no handle. It does not create an identity or reserve storage.
func (UserHandlePolicy) Generate(ctx context.Context) (UserHandle, error) {
	if ctx == nil {
		return UserHandle{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return UserHandle{}, err
	}
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return UserHandle{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return UserHandle{}, err
	}
	return UserHandle{value: func() [32]byte { return value }}, nil
}

// DeviceLabel is bounded caller-supplied display metadata, never authenticator
// provenance, a device identifier or an authorization selector. Zero denotes no
// label and is not a valid explicitly supplied label. Copies are immutable.
type DeviceLabel struct{ value func() string }

// NewDeviceLabel preserves exact UTF-8 bytes, including surrounding whitespace;
// it never normalizes supplied metadata. The selected display profile is at most
// 128 bytes, contains a non-whitespace rune and no control characters. Consumers
// must escape Value for their output medium; this is not HTML sanitization.
func NewDeviceLabel(value string) (DeviceLabel, error) {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return DeviceLabel{}, ErrInvalidInput
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return DeviceLabel{}, ErrInvalidInput
		}
	}
	return DeviceLabel{value: func() string { return value }}, nil
}

// Value explicitly projects original display text. It must not be logged with
// identity/credential correlation. Zero returns an empty string.
func (l DeviceLabel) Value() string {
	if l.value == nil {
		return ""
	}
	return l.value()
}

// Format keeps caller-supplied labels out of ordinary diagnostics.
func (DeviceLabel) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.DeviceLabel(redacted)"))
}
