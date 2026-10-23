//go:build integration

package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestIdentifiedPasskeySigninRejectsRepeatedPositiveNonBackupCounter(t *testing.T) {
	f := newSigninFixture(t)
	first, _ := f.pending(t)
	if result, err := f.signin.Signin(f.ctx, first); err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("first real counter advance", err)
	}
	// A fresh original flow/challenge and genuine UV ES256 signature are not
	// permission to ignore the protocol owner's positive-counter regression.
	repeated, _ := f.pending(t)
	if result, err := f.signin.Signin(f.ctx, repeated); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("repeated non-backup positive counter authenticated")
	}
	var sessions, effects, compromise int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.mark_compromised')`).Scan(&sessions, &effects, &compromise); err != nil || sessions != 1 || effects != 1 || compromise != 0 {
		t.Fatal("counter denial created authentication or falsely declared compromise", err, sessions, effects, compromise)
	}
}

func TestIdentifiedPasskeySigninPreservesRootSyncedCounterWarning(t *testing.T) {
	// Genuine raw registration claims BE; root enrollment and native mapping
	// commit that profile. No protocol credential or authority row is edited.
	f := newSigninFixtureFlags(t, 0x4d)
	first, _ := f.pending(t)
	if result, err := f.signin.Signin(f.ctx, first); err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.CounterRisk {
		t.Fatal("first backup-eligible counter advance", err)
	}
	repeated, _ := f.pending(t)
	result, err := f.signin.Signin(f.ctx, repeated)
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Token == (session.Token{}) || !result.CounterRisk {
		t.Fatal("genuine root backup-counter warning lost or falsely denied", err)
	}
	var n int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records WHERE action='identity.passkey.mark_compromised'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("synced counter warning falsely declared compromise", err, n)
	}
}
