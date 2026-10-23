package passkey

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// UpdateRequest selects a keyed self-user display-label rename, not credential
// replacement or removal. Primary carries original password/session/action and
// selected CSRF custody; a data carrier alone grants no authentication. Native
// ownership must require a genuine signed identity.passkey.update proof.
//
// ReferenceID is the safe identity-owned management reference returned by List,
// never raw RP credential bytes. ExpectedVersion is the observed positive
// management-metadata version; Name preserves 1..128 UTF-8 bytes under DeviceLabel
// policy. Renaming must not change protocol state or credential authority.
// Network is trusted bounded ingress for the existing risk owner, not authority.
//
// This native keyed profile deliberately differs from the historical catalog's
// caller-allocated command shape: Primary.CommandID and RecordID must be empty.
// Existing request-key admission supplies one server-random original command
// before native proof preparation; it is returned for every observed outcome.
// Supplied command/record overrides deny rather than being replaced. A matching
// retry retains the same key and canonical input, including original custody;
// it recovers metadata only and never consumes another proof or repeats effects.
type UpdateRequest struct {
	Primary         password.ActionPrimaryRequest
	ReferenceID     identity.CredentialID
	ExpectedVersion uint64
	Name            string
	IdempotencyKey  identity.IdempotencyKey
	Network         string
}

// UpdateResult carries original command durability and, only for fresh
// acknowledged commitment, updated safe metadata. Receipt is the existing
// command owner's exact observation, not current authorization. Replayed means
// historical metadata: Credential must be nil and no mutation is rerun. Unknown
// is not rollback; recover this CommandID rather than allocating a replacement.
// Zero is not success. The result contains no proof, session or protocol bytes;
// consumers must still explicitly project the fields appropriate to transport.
type UpdateResult struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	Replayed   bool
	Receipt    identity.CommandResult
	Credential *CredentialMetadata
}

// Format excludes original custody, retry correlation and caller display text.
func (UpdateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.UpdateRequest(redacted)"))
}

// MarshalJSON requires explicit, credential-free transport projection.
func (UpdateRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText prohibits implicit original-custody export.
func (UpdateRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes command correlation and display metadata from diagnostics.
func (UpdateResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.UpdateResult(redacted)"))
}

// MarshalJSON requires deliberate safe metadata projection, not record export.
func (UpdateResult) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText prohibits implicit durability/correlation export.
func (UpdateResult) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }
