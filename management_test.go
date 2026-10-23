package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// Populated carriers test serialization policy only, not authentication. Native
// PostgreSQL tests must obtain genuine signed action/session custody separately.
func TestUpdateRecordsKeepNativeCustodyOutOfImplicitSerialization(t *testing.T) {
	r := UpdateRequest{Primary: password.ActionPrimaryRequest{Session: auth.NewBearerCredential("synthetic-management-bearer"), Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "synthetic-proof"}}}, ReferenceID: "AAAAAAAAAAAAAAAAAAAAAQ", ExpectedVersion: 7, Name: "Sensitive label", IdempotencyKey: managementTestKey(t)}
	out := UpdateResult{CommandID: "AAAAAAAAAAAAAAAAAAAAAg", Outcome: identity.CommitOutcomeCommitted, Credential: &CredentialMetadata{ReferenceID: string(r.ReferenceID), Version: 8, Label: r.Name}}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{r, out} {
		if _, err := value.MarshalJSON(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("management JSON lost exact privacy sentinel")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("management text lost exact privacy sentinel")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit management JSON admitted custody")
		}
		formatted := fmt.Sprintf("%v %+v %#v %x", value, value, value, value)
		for _, private := range []string{"synthetic-management-bearer", "synthetic-proof", "Sensitive label", "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg"} {
			if strings.Contains(formatted, private) {
				t.Fatal("management carrier diagnostic disclosed sensitive input")
			}
		}
	}
	if r.Primary.CommandID != "" || r.Primary.RecordID != "" || out.CommandID == "" || out.Credential.Version != r.ExpectedVersion+1 || out.Replayed {
		t.Fatal("keyed carrier replaced original command ownership or metadata version")
	}
}

func managementTestKey(t *testing.T) identity.IdempotencyKey {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-management-request"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
