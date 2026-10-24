package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	passkey "github.com/faustbrian/go-passkey"
)

func TestPasskeySignupRequiresExplicitOwnedComposition(t *testing.T) {
	if s, err := NewSignupService(nil, SignupConfig{}); err == nil || s != nil {
		t.Fatal("missing native signup owners accepted")
	}
	for _, s := range []*SignupService{nil, {}} {
		if _, err := s.PrepareFlow(session.PreAuthPrepareInput{}); err == nil {
			t.Fatal("zero signup service prepared a flow")
		}
		if _, err := s.IssueFlow(t.Context(), session.PreparedPreAuthIssuance{}); err == nil {
			t.Fatal("zero signup service issued a flow")
		}
		if _, err := s.RegistrationOptions(t.Context(), passkey.SignupRequest{}); err == nil {
			t.Fatal("zero signup service emitted options")
		}
		if result, err := s.Signup(t.Context(), passkey.SignupCompletion{}); err == nil || result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) {
			t.Fatal("zero signup service authenticated")
		}
		if _, err := s.KeyedRegistrationOptions(t.Context(), passkey.KeyedSignupOptionsRequest{}); err == nil {
			t.Fatal("zero keyed signup service accepted a request")
		}
		if _, err := s.RecoverSignup(t.Context(), passkey.SignupRequest{}, "AQEBAQEBAQEBAQEBAQEBAQ", authorization.DecisionContext{}); err == nil {
			t.Fatal("zero signup service disclosed completion")
		}
		if _, err := s.RecoverRegistrationOptions(t.Context(), passkey.SignupRequest{}, authorization.DecisionContext{}); err == nil {
			t.Fatal("zero signup service disclosed options")
		}
	}
	if _, err := json.Marshal(SignupConfig{}); err == nil {
		t.Fatal("signup configuration serialized")
	}
	for _, value := range []any{SignupConfig{}, SignupService{}} {
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("signup configuration exposed")
		}
	}
}

func TestSignupMigrationAllocationAndCancellation(t *testing.T) {
	for _, version := range []migrations.Version{0, 1, migrations.Version(math.MaxInt64) + 1} {
		if _, err := (SignupMigrationSource{Version: version}).Load(t.Context()); err == nil {
			t.Fatal("invalid signup migration allocation accepted")
		}
	}
	for _, version := range []migrations.Version{2, 4} {
		steps, err := (SignupMigrationSource{Version: version}).Load(t.Context())
		if err != nil || len(steps) != 1 || steps[0].Version() != version || steps[0].DownSQL() != "" {
			t.Fatal("selected signup history lost allocation", err)
		}
	}
	if _, err := (SignupMigrationSource{Version: 2}).Load(nil); err == nil {
		t.Fatal("nil signup migration context accepted")
	}
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if _, err := (SignupMigrationSource{Version: 2}).Load(ctx); err != context.Canceled {
		t.Fatal("signup migration cancellation changed", err)
	}
}
