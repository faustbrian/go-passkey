package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

func TestTransportRecordsRetainRedactionAndSerializationContracts(t *testing.T) {
	cookie, err := session.ParseToken(base64.RawURLEncoding.EncodeToString([]byte("synthetic-browser-cookie-32-bytes")))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("synthetic-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	registration := RegistrationRequest{Primary: password.ActionPrimaryRequest{TenantID: "private-tenant", CommandID: "private-command", RecordID: "private-record", Session: auth.NewBearerCredential("synthetic-session-bearer"), Proof: auth.ReauthenticationProof{SessionID: "private-session", Action: "private-action"}, CSRFToken: csrf}, Origin: "https://private.example", Network: "private-network", Device: "private-device"}
	signin := SigninRequest{CommandID: "private-command", FlowID: "private-flow", Cookie: cookie, Identifier: "private@example.test", Origin: registration.Origin, Network: registration.Network, Device: registration.Device, CorrelationID: "private-correlation"}
	discoverable := DiscoverableSigninRequest{CommandID: signin.CommandID, FlowID: signin.FlowID, Cookie: cookie, Origin: signin.Origin, Network: signin.Network, Device: signin.Device, CorrelationID: signin.CorrelationID}
	values := []struct {
		name  string
		value any
	}{
		{"RegistrationRequest", registration},
		{"RegistrationCompletion", RegistrationCompletion{RegistrationRequest: registration, CeremonyID: "private-ceremony", Response: []byte("private-attestation"), Label: "private-label"}},
		{"SigninRequest", signin},
		{"SigninCompletion", SigninCompletion{SigninRequest: signin, CeremonyID: "private-ceremony", Response: []byte("private-assertion")}},
		{"SigninResult", SigninResult{Session: session.IssueResult{Token: cookie, Cookie: http.Cookie{Name: "private-cookie", Value: "synthetic-session-bearer"}}, CSRF: csrf}},
		{"DiscoverableSigninRequest", discoverable},
		{"DiscoverableSigninCompletion", DiscoverableSigninCompletion{DiscoverableSigninRequest: discoverable, CeremonyID: "private-ceremony", Response: []byte("private-assertion")}},
		{"KeyedRegistrationOptionsRequest", KeyedRegistrationOptionsRequest{RegistrationRequest: registration, IdempotencyKey: key}},
		{"KeyedSigninOptionsRequest", KeyedSigninOptionsRequest{SigninRequest: signin, IdempotencyKey: key}},
		{"KeyedDiscoverableOptionsRequest", KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discoverable, IdempotencyKey: key}},
		{"KeyedRegistrationOptionsResult", KeyedRegistrationOptionsResult{CommandID: "private-command"}},
		{"KeyedAssertionOptionsResult", KeyedAssertionOptionsResult{CommandID: "private-command"}},
		{"InventoryRequest", InventoryRequest{AttemptID: "private-attempt", After: "private-cursor", Limit: 1}},
	}
	for _, test := range values {
		t.Run(test.name, func(t *testing.T) {
			if reflect.TypeOf(test.value).PkgPath() != "github.com/faustbrian/go-passkey" {
				t.Fatal("transport record is not owned by the adapter-neutral module")
			}
			want := "passkeypostgres." + test.name + "(redacted)"
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				if got := fmt.Sprintf(format, test.value); got != want {
					t.Fatal("released diagnostic contract changed")
				}
			}
			if test.name == "InventoryRequest" {
				return // Its session.Credential retains its existing field behavior.
			}
			wantError := session.ErrSecretSerialization
			if test.name == "RegistrationRequest" || test.name == "RegistrationCompletion" {
				wantError = password.ErrPasswordWork
			}
			if data, err := json.Marshal(test.value); !errors.Is(err, wantError) || data != nil {
				t.Fatal("released JSON denial changed", err)
			}
			if test.name == "RegistrationRequest" || test.name == "RegistrationCompletion" {
				return // Existing JSON denial belongs to the named Primary field.
			}
			value, ok := test.value.(interface{ MarshalText() ([]byte, error) })
			if !ok {
				t.Fatal("released text-marshaler method was lost")
			}
			if data, err := value.MarshalText(); err != wantError || data != nil {
				t.Fatal("released text denial changed", err)
			}
		})
	}
}

func TestSafeInventoryProjectionRemainsOrdinaryData(t *testing.T) {
	page := InventoryPage{Credentials: []CredentialMetadata{{ReferenceID: "safe-reference", Version: 1, State: "active", Label: "Personal key"}}, Next: "safe-reference"}
	wire, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	var decoded InventoryPage
	if err := json.Unmarshal(wire, &decoded); err != nil || !reflect.DeepEqual(page, decoded) {
		t.Fatal("safe inventory metadata changed in transport", err)
	}
}
