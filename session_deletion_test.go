package passkey

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestSessionDeleteRetainsOriginalCustodyAndExplicitProjection(t *testing.T) {
	input := SessionDeleteRequestSpec{ReferenceID: "private-target", ExpectedVersion: 9, Origin: "https://private.example", Network: "private-network"}
	r := NewSessionDeleteRequest(input)
	input.ReferenceID = "changed-target"
	got, err := r.Bindings()
	if err != nil || got.ReferenceID != "private-target" || got.ExpectedVersion != 9 || got.Origin != input.Origin || got.Network != input.Network {
		t.Fatal("removal lost original intended target/version/ingress")
	}
	key := managementTestKey(t)
	options := SessionDeleteOptionsRequest{SessionDeleteRequest: r, IdempotencyKey: key}
	if options.IdempotencyKey != key {
		t.Fatal("options lost original key")
	}
	response := []byte("private-assertion")
	completion := NewSessionDeleteCompletion(SessionDeleteCompletionSpec{SessionDeleteRequest: r, IdempotencyKey: key, CeremonyID: "private-original-ceremony", Response: response})
	fields, err := completion.Bindings()
	if err != nil || fields.IdempotencyKey != key || fields.CeremonyID != "private-original-ceremony" || &fields.Response[0] != &response[0] {
		t.Fatal("removal completion lost original borrowed assertion/key")
	}
	projected, err := fields.SessionDeleteRequest.Bindings()
	if err != nil || projected.ReferenceID != got.ReferenceID || projected.ExpectedVersion != got.ExpectedVersion {
		t.Fatal("completion replaced original mutation intent")
	}
	result := NewSessionDeleteResult(DeleteResult{CommandID: "private-command", Outcome: identity.CommitOutcomeUnknown, Replayed: true})
	out, err := result.Bindings()
	if err != nil || out.CommandID != "private-command" || out.Outcome != identity.CommitOutcomeUnknown || !out.Replayed {
		t.Fatal("result changed original unknown metadata")
	}
	if _, err := (SessionDeleteRequest{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero request became authority")
	}
	if _, err := (SessionDeleteCompletion{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero completion became authority")
	}
	if _, err := (SessionDeleteResult{}).Bindings(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero result became acknowledgement")
	}
}

func TestSessionDeleteCustodyRedactsNestedDiagnosticsAndImplicitExports(t *testing.T) {
	r := NewSessionDeleteRequest(SessionDeleteRequestSpec{ReferenceID: "private-target", Origin: "https://private.example", Network: "private-network"})
	a := SessionDeleteOptionsRequest{SessionDeleteRequest: r, IdempotencyKey: managementTestKey(t)}
	b := NewSessionDeleteCompletion(SessionDeleteCompletionSpec{SessionDeleteRequest: r, CeremonyID: "private-original-ceremony", Response: []byte("private-assertion")})
	result := NewSessionDeleteResult(DeleteResult{CommandID: "private-command"})
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{r, a, b, result} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit removal JSON export")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit removal text export")
		}
	}
	for _, value := range []any{r, a, b, result, struct{ custody SessionDeleteRequest }{r}, struct{ custody SessionDeleteOptionsRequest }{a}, struct{ custody SessionDeleteCompletion }{b}, struct{ custody SessionDeleteResult }{result}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
			wire := fmt.Sprintf(format, value)
			if strings.Contains(wire, "private-") || strings.Contains(wire, "private.example") || strings.Contains(wire, "112 114 105 118 97 116 101") || strings.Contains(wire, hex.EncodeToString([]byte("private-"))) {
				t.Fatal("diagnostics disclosed original removal custody")
			}
		}
	}
}
