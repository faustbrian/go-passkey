package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/faustbrian/go-identity/session"
	"strings"
	"testing"
)

func TestSessionUpdateCustodyRequiresExplicitProjection(t *testing.T) {
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	request := SessionUpdateRequest{Credential: credential, Name: "private-authenticator-label", Origin: "https://private.example"}
	options := SessionUpdateOptionsRequest{SessionUpdateRequest: request, IdempotencyKey: managementTestKey(t)}
	completion := SessionUpdateCompletion{SessionUpdateRequest: request, IdempotencyKey: managementTestKey(t), CeremonyID: "private-original-ceremony", Response: []byte("private-authenticator-response")}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{request, options, completion} {
		if _, err := value.MarshalJSON(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("JSON privacy sentinel changed")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("text privacy sentinel changed")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit action/session/authenticator custody export")
		}
		for _, wire := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(wire, "private-") || strings.Contains(wire, "private.example") {
				t.Fatal("action/session/authenticator custody disclosed in diagnostics")
			}
		}
	}
}
