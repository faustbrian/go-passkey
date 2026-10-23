package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	passkey "github.com/faustbrian/go-passkey"
)

func TestDeletionServiceRequiresActualOwnersAndDeniesZero(t *testing.T) {
	if owner, err := NewDeletionService(nil, DeletionConfig{}); err == nil || owner != nil {
		t.Fatal("missing original owners enabled deletion")
	}
	var owner DeletionService
	if out, err := owner.Delete(context.Background(), passkey.DeleteRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("zero deletion service admitted mutation")
	}
	if out, err := owner.Delete(nil, passkey.DeleteRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("nil context enabled deletion")
	}
	config := DeletionConfig{ManagementConfig: ManagementConfig{RPNamespace: "sensitive-removal-rp", RPID: "private-removal.example", ProofAudience: "sensitive-removal-audience"}}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{config, owner} {
		if _, err := value.MarshalJSON(); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("deletion owner JSON lost exact privacy sentinel")
		}
		if _, err := value.MarshalText(); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("deletion owner text lost exact privacy sentinel")
		}
		if _, err := json.Marshal(value); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("deletion owner implicitly serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if text := fmt.Sprintf(format, value); strings.Contains(text, "sensitive-removal") || strings.Contains(text, "private-removal.example") {
				t.Fatal("deletion owner diagnostic disclosed configured scope")
			}
		}
	}
}
