package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestIdentifiedPasskeySigninFailsClosedWithoutOwnedComposition(t *testing.T) {
	if s, err := NewSigninService(nil, SigninConfig{}); err == nil || s != nil {
		t.Fatal("missing native composition accepted")
	}
	var s *SigninService
	if _, err := s.AuthenticationOptions(context.Background(), SigninRequest{}); err == nil {
		t.Fatal("zero signin service emitted an assertion challenge")
	}
	if result, err := s.Signin(context.Background(), SigninCompletion{}); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("zero signin service disclosed authentication")
	}
}
