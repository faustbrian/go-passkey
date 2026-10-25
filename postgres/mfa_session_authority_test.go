package postgres

import (
	"context"
	"errors"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

var _ sessionpg.MFAPasskeySessionAuthority = (*SessionAuthority)(nil)

func TestMFAPasskeySessionAuthorityRejectsMissingOwnedComposition(t *testing.T) {
	for _, authority := range []*SessionAuthority{nil, {}} {
		if _, err := authority.ObserveMFAPasskeySession(t.Context(), "rp-a", session.Session{}); err == nil {
			t.Fatal("missing mapping owner observed a completed session")
		}
		if err := authority.RequireMFAPasskeySession(t.Context(), kernel.Work{}, nil, "rp-a", session.Session{}); err == nil {
			t.Fatal("missing mapping owner or Work admitted a completed session")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := authority.ObserveMFAPasskeySession(ctx, "rp-a", session.Session{}); !errors.Is(err, context.Canceled) {
			t.Fatal("mapping observation lost earlier cancellation", err)
		}
		if err := authority.RequireMFAPasskeySession(ctx, kernel.Work{}, nil, "rp-a", session.Session{}); !errors.Is(err, context.Canceled) {
			t.Fatal("mapping fence lost earlier cancellation", err)
		}
		if _, err := authority.ObserveMFAPasskeySession(nil, "rp-a", session.Session{}); err == nil {
			t.Fatal("nil observation context admitted")
		}
		if err := authority.RequireMFAPasskeySession(nil, kernel.Work{}, nil, "rp-a", session.Session{}); err == nil {
			t.Fatal("nil fence context admitted")
		}
	}
}
