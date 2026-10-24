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

func TestSessionManagementRequiresActualOwnersAndPrivateConfiguration(t *testing.T) {
	if s, err := NewSessionManagementService(nil, SessionManagementConfig{}); err == nil || s != nil {
		t.Fatal("missing native owners enabled mutation")
	}
	for _, s := range []*SessionManagementService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if out, err := s.UpdateOptions(ctx, passkey.SessionUpdateOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("empty service/context enabled assertion")
			}
			if out, err := s.Update(ctx, passkey.SessionUpdateCompletion{}); err == nil || out.CommandID != "" || out.Credential != nil {
				t.Fatal("empty service/context enabled rename")
			}
		}
	}
	config := SessionManagementConfig{PolicyID: "sensitive-policy"}
	service := SessionManagementService{config: func() SessionManagementConfig { return config }}
	for _, value := range []any{config, service} {
		if _, err := json.Marshal(value); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("configuration JSON privacy sentinel changed")
		}
		text, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("configuration text export lacks privacy contract")
		}
		if _, err := text.MarshalText(); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("configuration text privacy sentinel changed")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), "sensitive-policy") {
			t.Fatal("native diagnostics disclosed configuration")
		}
	}
}
