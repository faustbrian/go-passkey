package passkey

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// DeleteRequest selects keyed self-user credential removal, not compromise or
// authenticator-local erasure. Primary carries original password/session/action
// and selected CSRF custody; the native owner must verify a genuine signed
// identity.passkey.delete proof and a currently usable independent recovery path.
// A data carrier grants no authentication, freshness or recovery authority.
//
// ReferenceID is the safe management reference returned by List, never raw RP
// credential bytes. ExpectedVersion is its observed positive management-metadata
// version, not the independently fenced credential or protocol authority version.
// Network is trusted bounded ingress for the existing risk owner, not authority.
//
// Primary.CommandID and RecordID must be empty. The kernel's existing exact-key
// admission supplies one server-random original command before proof preparation.
// Supplied command/record overrides deny. Matching retries preserve the exact
// key, input and original custody and recover metadata without another proof
// consumption, removal, lifecycle effect or reauthentication secret projection.
type DeleteRequest struct {
	Primary         password.ActionPrimaryRequest
	ReferenceID     identity.CredentialID
	ExpectedVersion uint64
	IdempotencyKey  identity.IdempotencyKey
	Network         string
}

// DeleteResult carries only original command durability metadata, never proof,
// session or protocol bytes. Receipt is historical command observation, not
// current authorization or authenticator-local erasure. Replayed means no
// removal or required effect was rerun. Unknown is not rollback: retain the
// original key and CommandID rather than allocating a replacement. Zero is not
// success. Consumers must explicitly project suitable transport fields.
type DeleteResult struct {
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
	Replayed  bool
	Receipt   identity.CommandResult
}

// Format excludes original custody and request correlation from diagnostics.
func (DeleteRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.DeleteRequest(redacted)"))
}

// MarshalJSON requires explicit, credential-free transport projection.
func (DeleteRequest) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText prohibits implicit original-custody export.
func (DeleteRequest) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }

// Format excludes command correlation and historical receipt metadata.
func (DeleteResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkey.DeleteResult(redacted)"))
}

// MarshalJSON requires deliberate safe metadata projection, not record export.
func (DeleteResult) MarshalJSON() ([]byte, error) { return nil, ErrPrivateValue }

// MarshalText prohibits implicit durability/correlation export.
func (DeleteResult) MarshalText() ([]byte, error) { return nil, ErrPrivateValue }
