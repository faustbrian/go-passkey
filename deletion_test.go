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

// These populated carriers exercise export policy only. Native integration
// obtains genuine signed deletion proof and current password-session custody.
func TestDeleteRecordsKeepOriginalCustodyOutOfImplicitSerialization(t *testing.T) {
	r := DeleteRequest{Primary: password.ActionPrimaryRequest{Session: auth.NewBearerCredential("synthetic-deletion-bearer"), Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "synthetic-deletion-proof"}}}, ReferenceID: "AAAAAAAAAAAAAAAAAAAAAQ", ExpectedVersion: 7, IdempotencyKey: managementTestKey(t), Network: "synthetic-deletion-network"}
	out := DeleteResult{CommandID: "AAAAAAAAAAAAAAAAAAAAAg", Outcome: identity.CommitOutcomeCommitted}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{r, out} {
		if _, err := value.MarshalJSON(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("deletion JSON lost exact privacy sentinel")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("deletion text lost exact privacy sentinel")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit deletion JSON admitted original custody")
		}
		formatted := fmt.Sprintf("%v %+v %#v %x", value, value, value, value)
		for _, private := range []string{"synthetic-deletion-bearer", "synthetic-deletion-proof", "synthetic-deletion-network", "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg"} {
			if strings.Contains(formatted, private) {
				t.Fatal("deletion carrier diagnostic disclosed private input")
			}
		}
	}
	if r.Primary.CommandID != "" || r.Primary.RecordID != "" || out.CommandID == "" || out.Replayed {
		t.Fatal("deletion carrier replaced original command ownership")
	}
}
