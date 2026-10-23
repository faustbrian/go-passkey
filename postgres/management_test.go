package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func TestManagementServiceRequiresActualOwnersAndDeniesZero(t *testing.T) {
	if s, err := NewManagementService(nil, ManagementConfig{}); err == nil || s != nil {
		t.Fatal("missing original owners enabled rename")
	}
	var s ManagementService
	if out, err := s.Update(context.Background(), passkey.UpdateRequest{}); err == nil || out.CommandID != "" || out.Credential != nil {
		t.Fatal("zero management service mutated or disclosed metadata")
	}
	if out, err := s.Update(nil, passkey.UpdateRequest{}); err == nil || out.CommandID != "" || out.Credential != nil {
		t.Fatal("nil context enabled mutation")
	}
	key, err := session.NewDigestKey(3, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	config := ManagementConfig{TenantID: identity.TenantID("sensitive-tenant"), RPNamespace: "sensitive-rp", RPID: "private.example", ProofAudience: "sensitive-proof-audience", RequestTokenKey: key, PolicyID: "sensitive-policy"}
	owner := ManagementService{config: func() ManagementConfig { return config }}
	for _, value := range []any{ManagementConfig{}, ManagementService{}, config, owner} {
		if _, err := json.Marshal(value); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("native management owner serialization did not deny exact sentinel")
		}
		if marshaler, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatal("native owner lacks text redaction")
		} else if _, err := marshaler.MarshalText(); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("native management text serialization changed exact sentinel")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, value); strings.Contains(got, "sensitive") || strings.Contains(got, "private.example") || strings.Contains(got, strings.Repeat("k", 32)) {
				t.Fatal("native management diagnostics disclosed populated custody")
			}
		}
	}
}
