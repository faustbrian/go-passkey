package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestPasskeyAuthorityKeyPreservesUnambiguousRPScope(t *testing.T) {
	key, err := PasskeyAuthorityKey("rp-a", "tenant-a", "user-a")
	if err != nil || !strings.HasPrefix(key, "passkey:v1:") {
		t.Fatal("missing stable owned scope", err)
	}
	for _, ids := range [][3]string{{"rp-b", "tenant-a", "user-a"}, {"rp-a", "tenant-b", "user-a"}, {"rp-a", "tenant-a", "user-b"}, {"rp", "-atenant-a", "user-a"}} {
		other, err := PasskeyAuthorityKey(ids[0], identity.TenantID(ids[1]), identity.UserID(ids[2]))
		if err != nil || other == key {
			t.Fatal("authority scope aliases another RP/identity", err)
		}
	}
	again, err := PasskeyAuthorityKey("rp-a", "tenant-a", "user-a")
	if err != nil || again != key || strings.Contains(key, "tenant-a") || strings.Contains(key, "user-a") {
		t.Fatal("authority key changed or disclosed original scope")
	}
	for _, ids := range [][3]string{{"", "tenant-a", "user-a"}, {"rp-a", "", "user-a"}, {"rp-a", "tenant-a", ""}, {strings.Repeat("x", 129), "tenant-a", "user-a"}, {"rp-a", "tenant a", "user-a"}} {
		if _, err := PasskeyAuthorityKey(ids[0], identity.TenantID(ids[1]), identity.UserID(ids[2])); err == nil {
			t.Fatal("invalid authority scope admitted")
		}
	}
}

func TestPasskeySessionAuthorityRejectsMissingOwnedComposition(t *testing.T) {
	config := SessionAuthorityConfig{TenantID: "tenant-a", RPNamespace: "rp-a", RPID: "identity.example", MaximumDuration: time.Second}
	if authority, err := NewSessionAuthority(nil, config); err == nil || authority != nil {
		t.Fatal("missing primary became authority")
	}
	var authority SessionAuthority
	if _, err := authority.ObservePasskeySession(context.Background(), "rp-a", session.Session{}); err == nil {
		t.Fatal("zero authority observed a session")
	}
	if err := authority.RequirePasskeySession(context.Background(), kernel.Work{}, nil, "rp-a", session.Session{}); err == nil {
		t.Fatal("zero Work granted passkey authority")
	}
}
