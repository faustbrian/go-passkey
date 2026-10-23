package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestKeyedOptionsRequireExplicitNativeCompositionAndRedact(t *testing.T) {
	if c, err := NewOptionsRequestConfig(kernel.RequestKeyConfig{}, session.DigestKey{}, session.CSRFKey{}); err == nil || c.state != nil {
		t.Fatal("zero keys enabled native request correlation")
	}
	var enrollment *EnrollmentService
	var signin *SigninService
	if out, err := enrollment.KeyedRegistrationOptions(context.Background(), KeyedRegistrationOptionsRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("unconfigured enrollment emitted options")
	}
	if out, err := signin.KeyedAuthenticationOptions(context.Background(), KeyedSigninOptionsRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("unconfigured signin emitted options")
	}
	if out, err := signin.KeyedDiscoverableAuthenticationOptions(context.Background(), KeyedDiscoverableOptionsRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("unconfigured discovery emitted options")
	}
	k, _ := identity.NewIdempotencyKey([]byte("private-original-key"))
	for _, v := range []any{KeyedRegistrationOptionsRequest{RegistrationRequest: RegistrationRequest{Origin: "private-origin"}, IdempotencyKey: k}, KeyedSigninOptionsRequest{SigninRequest: SigninRequest{Identifier: "private-email"}, IdempotencyKey: k}, KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: DiscoverableSigninRequest{Device: "private-device"}, IdempotencyKey: k}, KeyedRegistrationOptionsResult{CommandID: "private-command"}, KeyedAssertionOptionsResult{CommandID: "private-command"}, OptionsRequestConfig{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
			if strings.Contains(fmt.Sprintf(verb, v), "private-") {
				t.Fatal("native keyed custody leaked through formatting")
			}
		}
		if wire, err := json.Marshal(v); !errors.Is(err, session.ErrSecretSerialization) || len(wire) != 0 {
			t.Fatal("native keyed custody serialized")
		}
	}
}
