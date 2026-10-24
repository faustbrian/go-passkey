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

func TestSessionDeletionRequiresActualOwnersAndExplicitCustody(t *testing.T) {
	if s, err := NewSessionDeletionService(nil, SessionDeletionConfig{}); err == nil || s != nil {
		t.Fatal("missing owners enabled removal")
	}
	for _, s := range []*SessionDeletionService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if out, err := s.DeleteOptions(ctx, passkey.SessionDeleteOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("empty service/context enabled removal options")
			}
			out, err := s.Delete(ctx, passkey.SessionDeleteCompletion{})
			if _, projected := out.Bindings(); err == nil || projected == nil {
				t.Fatal("empty service/context enabled removal acknowledgement")
			}
		}
	}
	service := SessionDeletionService{owner: &SessionManagementService{config: func() SessionManagementConfig { return SessionManagementConfig{PolicyID: "private-deployment-policy"} }}}
	if _, err := json.Marshal(service); !errors.Is(err, passkey.ErrPrivateValue) {
		t.Fatal("removal owner JSON export")
	}
	if _, err := service.MarshalText(); !errors.Is(err, passkey.ErrPrivateValue) {
		t.Fatal("removal owner text export")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", service, service, service), "private-deployment-policy") {
		t.Fatal("removal diagnostics expose deployment correlation")
	}
}
