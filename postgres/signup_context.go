package postgres

import (
	"bytes"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
)

// Both execution and historical recovery read the same closed original intent.
// This validates storage framing only, never browser possession, current
// authority, protocol verification or permission to issue authentication.
func decodeSignupContext(wire []byte) (signupContext, error) {
	invalid := func() (signupContext, error) { return signupContext{}, identity.UnavailableError{} }
	if len(wire) == 0 || len(wire) > 4096 {
		return invalid()
	}
	var original signupContext
	if json.Unmarshal(wire, &original) != nil {
		return invalid()
	}
	canonical, err := json.Marshal(original)
	if err != nil || !bytes.Equal(canonical, wire) || original.Profile != "passkey-signup-context-v1" || original.Namespace == "" || original.RP == "" || original.Actor == "" || original.Global == "" || original.Policy == "" || original.GlobalVersion == 0 || original.TenantVersion == 0 || original.PolicyVersion == 0 || len(original.Handle) != 32 {
		return invalid()
	}
	if _, err := identity.ParsePreAuthTransactionID(original.Flow); err != nil {
		return invalid()
	}
	if _, err := identity.ParseSubjectID(original.User); err != nil {
		return invalid()
	}
	if _, err := identity.ParseSubjectID(original.Credential); err != nil {
		return invalid()
	}
	return original, nil
}
