package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func identifiedRateContextFixture(t testing.TB, selected bool) (*SigninService, identifiedSigninContext, []byte) {
	t.Helper()
	s := &SigninService{}
	if selected {
		s.mfa = &signinMFAComposition{issuerURL: "https://issuer.example", envelopeKey: "primary", lifetime: time.Minute, attempts: 5}
	}
	original := identifiedSigninContext{Flow: "flow", User: "user", Identifier: "identifier", Namespace: "rp", Global: "global", Policy: "policy", Input: "passkey@example.test", GlobalVersion: 1, TenantVersion: 2, UserVersion: 3, IdentifierVersion: 4, CredentialVersion: 5, FactorVersion: 6, PasskeyVersion: 7, PolicyVersion: 8, IdentifierRecord: 9, VerificationRecord: 10}
	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = s.signinMFAContext(wire)
	if err != nil {
		t.Fatal(err)
	}
	return s, original, wire
}

func TestIdentifiedRateContextRetainsCanonicalDefaultAndSelectedProfiles(t *testing.T) {
	for _, selected := range []bool{false, true} {
		s, want, wire := identifiedRateContextFixture(t, selected)
		got, err := s.decodeIdentifiedRateContext(wire)
		if err != nil || got != want {
			t.Fatal("canonical original identified context changed", selected, err)
		}
		other, _, _ := identifiedRateContextFixture(t, !selected)
		got, err = other.decodeIdentifiedRateContext(wire)
		if err == nil || got != (identifiedSigninContext{}) {
			t.Fatal("wrong profile returned original state", selected)
		}
	}
}

func TestIdentifiedRateContextRejectsChangedSelectionAndMalformedCustody(t *testing.T) {
	_, _, wire := identifiedRateContextFixture(t, true)
	for _, field := range []string{"issuer", "key", "lifetime", "attempts"} {
		t.Run(field, func(t *testing.T) {
			changed, _, _ := identifiedRateContextFixture(t, true)
			switch field {
			case "issuer":
				changed.mfa.issuerURL = "https://other.example"
			case "key":
				changed.mfa.envelopeKey = "other"
			case "lifetime":
				changed.mfa.lifetime++
			case "attempts":
				changed.mfa.attempts++
			}
			got, err := changed.decodeIdentifiedRateContext(wire)
			if err == nil || got != (identifiedSigninContext{}) {
				t.Fatal("changed profile returned original state")
			}
		})
	}
	for _, selected := range []bool{false, true} {
		service, _, original := identifiedRateContextFixture(t, selected)
		cases := [][]byte{
			nil, []byte(`null`), []byte(`{`), bytes.Repeat([]byte{' '}, 4097),
			append(bytes.Clone(original), ' '),
			bytes.Replace(original, []byte(`"Flow":`), []byte(`"Flow" :`), 1),
			bytes.Replace(original, []byte(`"Flow":"flow"`), []byte(`"Flow":"flow","Flow":"flow"`), 1),
			bytes.Replace(original, []byte(`"Flow":"flow"`), []byte(`"flow":"flow"`), 1),
			bytes.Replace(original, []byte(`"Flow":"flow"`), []byte(`"Flow":"flow","Unknown":0`), 1),
		}
		if selected {
			var corrupt struct {
				Original json.RawMessage
				MFA      [32]byte
			}
			if err := json.Unmarshal(original, &corrupt); err != nil {
				t.Fatal(err)
			}
			corrupt.MFA[0] ^= 1
			corruptWire, err := json.Marshal(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases,
				corruptWire,
				bytes.Replace(original, []byte(`"Original":{`), []byte(`"Original": {`), 1),
				bytes.Replace(original, []byte(`"MFA":[`), []byte(`"MFA":[0,`), 1),
				bytes.Replace(original, []byte(`"MFA":[`), []byte(`"Unknown":0,"MFA":[`), 1),
				bytes.Replace(original, []byte(`"MFA":[`), []byte(`"MFA":[],"MFA":[`), 1),
				[]byte(`{"Original":null,"MFA":[]}`))
		}
		for index, candidate := range cases {
			got, err := service.decodeIdentifiedRateContext(candidate)
			if err == nil || got != (identifiedSigninContext{}) {
				t.Fatal("malformed custody returned original state", selected, index)
			}
		}
	}
}

func FuzzIdentifiedRateContext(f *testing.F) {
	for _, selected := range []bool{false, true} {
		_, _, wire := identifiedRateContextFixture(f, selected)
		f.Add(wire, selected)
	}
	f.Add([]byte(`null`), true)
	f.Fuzz(func(t *testing.T, wire []byte, selected bool) {
		if len(wire) > 4097 {
			return
		}
		s, _, _ := identifiedRateContextFixture(t, selected)
		original, err := s.decodeIdentifiedRateContext(wire)
		if err != nil {
			if original != (identifiedSigninContext{}) {
				t.Fatal("denied custody disclosed partial state")
			}
			return
		}
		canonical, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err = s.signinMFAContext(canonical)
		if err != nil || !bytes.Equal(canonical, wire) || len(wire) > 4096 {
			t.Fatal("accepted noncanonical or oversized original")
		}
	})
}
