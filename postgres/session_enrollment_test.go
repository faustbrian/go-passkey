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

func TestSessionEnrollmentRequiresActualOwnersAndPrivateConfiguration(t *testing.T) {
	if s, err := NewSessionEnrollmentService(nil, SessionEnrollmentConfig{}); err == nil || s != nil {
		t.Fatal("missing native owners enabled enrollment")
	}
	for _, s := range []*SessionEnrollmentService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if out, err := s.EnrollmentAssertionOptions(ctx, passkey.SessionEnrollmentOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("empty owner/context enabled assertion")
			}
			if out, err := s.RegistrationOptions(ctx, passkey.SessionEnrollmentAuthorization{}); err == nil || out.CommandID != "" {
				t.Fatal("empty owner/context authorized enrollment")
			}
			if out, expiry, err := s.RegistrationOptionsForDelivery(ctx, passkey.SessionEnrollmentAuthorization{}); err == nil || out.CommandID != "" || !expiry.IsZero() {
				t.Fatal("empty owner/context disclosed options or a delivery ceiling")
			}
			out, err := s.Register(ctx, passkey.SessionEnrollmentCompletion{})
			fields, e := out.Bindings()
			if err == nil || e != nil || fields.CommandID != "" || fields.Credential != nil {
				t.Fatal("empty owner/context enrolled credential")
			}
		}
	}
	config := SessionEnrollmentConfig{PolicyID: "sensitive-enrollment-policy"}
	service := SessionEnrollmentService{owner: &SessionManagementService{config: func() SessionManagementConfig { return config }}}
	for _, value := range []any{config, service} {
		if _, err := json.Marshal(value); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("configuration JSON privacy sentinel changed")
		}
		text, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("configuration text privacy absent")
		}
		if _, err := text.MarshalText(); !errors.Is(err, passkey.ErrPrivateValue) {
			t.Fatal("configuration text privacy sentinel changed")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), "sensitive-enrollment-policy") {
			t.Fatal("native configuration leaked through diagnostics")
		}
	}
}
