package passkey

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestSessionEnrollmentCustodyRequiresExplicitProjection(t *testing.T) {
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	r := NewSessionEnrollmentRequest(SessionEnrollmentRequestSpec{Credential: credential, Label: "private-enrollment-label", Origin: "https://private.example"})
	a := SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: r, IdempotencyKey: managementTestKey(t)}
	b := NewSessionEnrollmentAuthorization(SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: r, IdempotencyKey: managementTestKey(t), CeremonyID: "private-original-assertion", Response: []byte("private-assertion")})
	c := NewSessionEnrollmentCompletion(SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: r, CommandID: "private-original-command", CeremonyID: "private-original-registration", Response: []byte("private-attestation")})
	result := NewSessionEnrollmentResult(SessionEnrollmentResultSpec{CommandID: "private-original-command", Credential: &CredentialMetadata{Label: "private-enrollment-label"}})
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{r, a, b, c, result} {
		if _, err := value.MarshalJSON(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("JSON custody sentinel changed")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("text custody sentinel changed")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit enrollment custody export")
		}
		for _, wire := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(wire, "private-") || strings.Contains(wire, "private.example") {
				t.Fatal("diagnostics disclosed enrollment custody")
			}
		}
	}
}

func TestSessionEnrollmentCustodyNestedDiagnostics(t *testing.T) {
	r := NewSessionEnrollmentRequest(SessionEnrollmentRequestSpec{Label: "private-enrollment-label", Origin: "https://private.example", Network: "private-network"})
	b := NewSessionEnrollmentAuthorization(SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: r, CeremonyID: "private-original-assertion", Response: []byte("private-assertion")})
	c := NewSessionEnrollmentCompletion(SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: r, CommandID: "private-original-command", CeremonyID: "private-original-registration", Response: []byte("private-attestation")})
	values := []any{
		struct{ request SessionEnrollmentRequest }{r},
		struct {
			request SessionEnrollmentOptionsRequest
		}{SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: r, IdempotencyKey: managementTestKey(t)}},
		struct {
			request SessionEnrollmentAuthorization
		}{b},
		struct{ request SessionEnrollmentCompletion }{c},
		struct{ result SessionEnrollmentResult }{NewSessionEnrollmentResult(SessionEnrollmentResultSpec{CommandID: "private-original-command", Credential: &CredentialMetadata{Label: "private-enrollment-label"}})},
	}
	for i, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
			wire := fmt.Sprintf(format, value)
			if strings.Contains(wire, "private-") || strings.Contains(wire, "private.example") || strings.Contains(wire, "112 114 105 118 97 116 101") || strings.Contains(wire, hex.EncodeToString([]byte("private-"))) {
				t.Errorf("nested carrier %d format %s disclosed custody", i, format)
			}
		}
	}
}

func TestSessionEnrollmentBindingsPreserveOriginalBorrowedCustody(t *testing.T) {
	input := SessionEnrollmentRequestSpec{Label: "original", Origin: "https://example.test", Network: "127.0.0.1"}
	r := NewSessionEnrollmentRequest(input)
	input.Label = "changed"
	got, err := r.Bindings()
	if err != nil || got.Label != "original" || got.Origin != input.Origin || got.Network != input.Network {
		t.Fatal("request lost original intent")
	}
	response := []byte("original-response")
	key := managementTestKey(t)
	b := NewSessionEnrollmentAuthorization(SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: r, IdempotencyKey: key, CeremonyID: "original-assertion", Response: response})
	binding, err := b.Bindings()
	if err != nil || binding.IdempotencyKey != key || binding.CeremonyID != "original-assertion" || &binding.Response[0] != &response[0] {
		t.Fatal("authorization lost borrowed original custody")
	}
	c := NewSessionEnrollmentCompletion(SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: r, CommandID: "original-command", CeremonyID: "original-registration", Response: response})
	completion, err := c.Bindings()
	if err != nil || completion.CommandID != "original-command" || completion.CeremonyID != "original-registration" || &completion.Response[0] != &response[0] {
		t.Fatal("completion lost borrowed original custody")
	}
	if _, err := (SessionEnrollmentRequest{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero request custody projected")
	}
	if _, err := (SessionEnrollmentAuthorization{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero assertion custody projected")
	}
	if _, err := (SessionEnrollmentCompletion{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero completion custody projected")
	}
	metadata := &CredentialMetadata{Label: "original"}
	result := NewSessionEnrollmentResult(SessionEnrollmentResultSpec{CommandID: "original-command", Credential: metadata})
	resultFields, err := result.Bindings()
	if err != nil || resultFields.CommandID != "original-command" || resultFields.Credential != metadata {
		t.Fatal("result lost original durability or borrowed metadata")
	}
	if _, err := (SessionEnrollmentResult{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero result custody projected")
	}
}
