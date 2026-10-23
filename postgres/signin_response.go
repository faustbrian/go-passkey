package postgres

import (
	"encoding/base64"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
)

// signinResponseCredentialID selects bounded lookup identity only. The root
// protocol verifier still owns duplicate/field checks, browser context and
// cryptographic verification; successful selection grants no authentication.
func signinResponseCredentialID(response []byte) ([]byte, error) {
	if len(response) == 0 || len(response) > 262144 {
		return nil, identity.ForbiddenError{}
	}
	var raw struct {
		RawID string `json:"rawId"`
	}
	// 1366 is the maximum unpadded base64url length for the protocol owner's
	// 1024-byte credential bound. Check it before base64 allocates output.
	if json.Unmarshal(response, &raw) != nil || len(raw.RawID) > 1366 {
		return nil, identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.DecodeString(raw.RawID)
	if err != nil || len(id) == 0 || len(id) > 1024 || base64.RawURLEncoding.EncodeToString(id) != raw.RawID {
		return nil, identity.ForbiddenError{}
	}
	return id, nil
}
