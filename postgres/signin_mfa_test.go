package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func signinMFAEnvelopeFixture(t testing.TB) (*SigninService, identity.CommandBinding, []byte) {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{"primary": bytes.Repeat([]byte{121}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	c := SigninConfig{}
	c.Profile.RPNamespace, c.Profile.Audience = "rp", "audience"
	s := &SigninService{config: func() SigninConfig { return c }, mfa: &signinMFAComposition{crypto: crypto, envelopeKey: "primary", issuerURL: "https://issuer.example", lifetime: time.Minute, attempts: 5}}
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser, RecordID: "AQEBAQEBAQEBAQEBAQEBAQ", OperationID: signinOperation(true).OperationID, SchemaID: signinOperation(true).SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: "correlation"}
	plain, err := marshalSigninMFAOutput(signinMFAOutput{Schema: 1, PrimaryDigest: [32]byte{1}, Scope: signinStoredScope{PasskeyCommandID: b.CommandID, PrimaryProofID: "AQEBAQEBAQEBAQEBAQEBAQ"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, b, plain
}

func sealSigninMFAFixture(t testing.TB, s *SigninService, b identity.CommandBinding, generation uint64, plain []byte) []byte {
	t.Helper()
	aad, err := s.mfaOutputAAD(b, generation)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.mfa.crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: plain, KeyReference: s.mfa.envelopeKey, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestSigninMFAJournalRejectsForeignAndNoncanonicalCustody(t *testing.T) {
	s, b, plain := signinMFAEnvelopeFixture(t)
	wire := sealSigninMFAFixture(t, s, b, 7, plain)
	stored, err := s.readMFAOutput(t.Context(), b, 7, wire)
	if err != nil || stored.PrimaryDigest != ([32]byte{1}) {
		t.Fatal("original private projection", err)
	}
	for _, mode := range []string{"generation", "tenant", "actor", "record", "configuration", "ciphertext", "unknown JSON", "duplicate JSON", "oversized", "missing passkey origin", "foreign passkey origin", "verification origin"} {
		t.Run(mode, func(t *testing.T) {
			candidate := bytes.Clone(wire)
			binding, generation := b, uint64(7)
			service := *s
			composition := *s.mfa
			service.mfa = &composition
			switch mode {
			case "generation":
				generation++
			case "tenant":
				binding.TenantID = "foreign"
			case "actor":
				binding.ActorID = "foreign"
			case "record":
				binding.RecordID = "foreign"
			case "configuration":
				service.mfa.attempts++
			case "ciphertext":
				candidate[len(candidate)-1] ^= 1
			case "unknown JSON":
				candidate = sealSigninMFAFixture(t, s, b, 7, append([]byte(`{"unknown":1,`), plain[1:]...))
			case "duplicate JSON":
				candidate = sealSigninMFAFixture(t, s, b, 7, append([]byte(`{"Schema":1,`), plain[1:]...))
			case "oversized":
				candidate = make([]byte, maximumSigninMFAOutput+1)
			case "missing passkey origin", "foreign passkey origin", "verification origin":
				scope := signinStoredScope{PasskeyCommandID: b.CommandID, PrimaryProofID: "AQEBAQEBAQEBAQEBAQEBAQ"}
				switch mode {
				case "missing passkey origin":
					scope.PasskeyCommandID = ""
				case "foreign passkey origin":
					scope.PasskeyCommandID = "AgICAgICAgICAgICAgICAg"
				case "verification origin":
					scope.VerificationCommandID = b.CommandID
				}
				changed, err := marshalSigninMFAOutput(signinMFAOutput{Schema: 1, PrimaryDigest: [32]byte{1}, Scope: scope})
				if err != nil {
					t.Fatal(err)
				}
				candidate = sealSigninMFAFixture(t, s, b, 7, changed)
			}
			out, err := service.readMFAOutput(t.Context(), binding, generation, candidate)
			if err == nil || out.Schema != 0 || out.Checkpoint != nil {
				t.Fatal("foreign custody returned retained state")
			}
		})
	}
}

func TestSigninMFASelectionIsBoundWithoutChangingDefaultContext(t *testing.T) {
	original := []byte(`{"original":"context"}`)
	s := &SigninService{}
	got, err := s.signinMFAContext(original)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("default context encoding changed")
	}
	s.mfa = &signinMFAComposition{issuerURL: "https://issuer.example", envelopeKey: "primary", lifetime: time.Minute, attempts: 5}
	selected, err := s.signinMFAContext(original)
	if err != nil || bytes.Equal(selected, original) {
		t.Fatal("selected profile was not bound")
	}
	s.mfa.attempts++
	changed, err := s.signinMFAContext(original)
	if err != nil || bytes.Equal(selected, changed) {
		t.Fatal("changed selection reused original ceremony")
	}
}

func FuzzSigninMFAOutputEnvelope(f *testing.F) {
	s, b, plain := signinMFAEnvelopeFixture(f)
	f.Add(sealSigninMFAFixture(f, s, b, 7, plain))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maximumSigninMFAOutput+1 {
			return
		}
		out, err := s.readMFAOutput(t.Context(), b, 7, wire)
		if err != nil {
			if out.Schema != 0 || out.Checkpoint != nil {
				t.Fatal("error disclosed partial private state")
			}
			return
		}
		if out.Schema != 1 || out.PrimaryDigest == ([32]byte{}) {
			t.Fatal("accepted invalid private schema")
		}
	})
}
