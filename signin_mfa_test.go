package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

// This is the public transport contract, not proof of a verified assertion or
// a durable challenge. Native PostgreSQL tests prove those owning boundaries.
func TestSigninResultSupportsExplicitPrivateMFAChallenge(t *testing.T) {
	value := reflect.ValueOf(&SigninResult{}).Elem()
	field := value.FieldByName("Challenge")
	if !field.IsValid() || field.Kind() != reflect.Pointer {
		t.Fatal("signin result cannot represent an explicit challenge without a session")
	}
	challenge := reflect.New(field.Type().Elem())
	field.Set(challenge)
	if got := fmt.Sprintf("%#v", challenge.Interface()); got != "passkeypostgres.SigninMFAChallenge(redacted)" {
		t.Fatal("challenge diagnostics disclose custody")
	}
	if wire, err := json.Marshal(challenge.Interface()); !errors.Is(err, session.ErrSecretSerialization) || wire != nil {
		t.Fatal("challenge implicitly exports its independent-factor credential", err)
	}
	result := value.Interface().(SigninResult)
	if result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) {
		t.Fatal("challenge-only arm disclosed final authentication")
	}
}
