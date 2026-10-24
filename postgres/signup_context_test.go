package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
)

func signupContextFixture(t testing.TB) []byte {
	t.Helper()
	wire, err := json.Marshal(signupContext{Profile: "passkey-signup-context-v1", Flow: "AQEBAQEBAQEBAQEBAQEBAQ", User: "AAAAAAAAAAAAAAAAAAAAAQ", Credential: "AAAAAAAAAAAAAAAAAAAAAg", Namespace: "rp-a", RP: "identity.example", Actor: "signup-service", Global: "deployment", Policy: "users", Handle: bytes.Repeat([]byte{7}, 32), GlobalVersion: 1, TenantVersion: 1, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestSignupContextRequiresExactBoundedCanonicalIntent(t *testing.T) {
	valid := signupContextFixture(t)
	if original, err := decodeSignupContext(valid); err != nil || original.User != "AAAAAAAAAAAAAAAAAAAAAQ" || original.Credential != "AAAAAAAAAAAAAAAAAAAAAg" || original.GlobalVersion != 1 || len(original.Handle) != 32 {
		t.Fatal("original signup intent rejected", err)
	}
	for _, wire := range [][]byte{nil, {}, []byte(`{}`), bytes.Repeat([]byte{' '}, 4097), append(bytes.Clone(valid), ' '), bytes.Replace(valid, []byte(`"Profile":`), []byte(`"unknown":true,"Profile":`), 1), bytes.Replace(valid, []byte(`"GlobalVersion":1`), []byte(`"GlobalVersion":0`), 1), bytes.Replace(valid, []byte(`"Credential":"AAAAAAAAAAAAAAAAAAAAAg"`), []byte(`"Credential":""`), 1), bytes.Replace(valid, []byte(`"Profile":"passkey-signup-context-v1"`), []byte(`"Profile":"foreign","Profile":"passkey-signup-context-v1"`), 1)} {
		if _, err := decodeSignupContext(wire); err == nil {
			t.Fatal("malformed, noncanonical or incomplete signup intent admitted")
		}
	}
}

func FuzzSignupContext(f *testing.F) {
	f.Add(signupContextFixture(f))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Profile":"passkey-signup-context-v1"}`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		original, err := decodeSignupContext(wire)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(original)
		if err != nil || len(wire) > 4096 || !bytes.Equal(canonical, wire) || original.Profile != "passkey-signup-context-v1" || len(original.Handle) != 32 || original.GlobalVersion == 0 || original.TenantVersion == 0 || original.PolicyVersion == 0 {
			t.Fatal("accepted signup intent violates its immutable bounded profile")
		}
	})
}
