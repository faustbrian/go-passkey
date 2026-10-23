//go:build integration

package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type signinClock struct{ stamp time.Time }

func (c signinClock) Now() time.Time { return c.stamp }

type signinOffsetClock struct{ offset time.Duration }

func (c signinOffsetClock) Now() time.Time { return time.Now().Add(c.offset) }

func TestIdentifiedPasskeySigninPreservesPersistentOriginalChoice(t *testing.T) {
	f := newSigninFixture(t)
	r := f.request(t, session.PersistentSession)
	options, err := f.signin.AuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("missing ceremony")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	r.CommandID, _ = identity.NewCommandID()
	result, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.Remember.Choice() != session.PersistentSession || result.Session.Cookie.MaxAge <= 0 || result.Session.Cookie.Expires.IsZero() {
		t.Fatal("persistent original choice lost", err)
	}
}

func TestIdentifiedPasskeySigninRejectsExpiredOriginalFlow(t *testing.T) {
	f := newSigninFixture(t)
	completion, _ := f.pending(t)
	config := f.signin.config()
	config.Clock = signinClock{stamp: time.Now().UTC().Add(6 * time.Minute)}
	advanced, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := advanced.Signin(f.ctx, completion)
	if err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("expired original flow authenticated")
	}
	var n int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("expired flow created session", err, n)
	}
}

func TestIdentifiedPasskeySigninRechecksOriginalFlowAfterFinalEffectWait(t *testing.T) {
	f := newSigninFixture(t)
	// The real session issuer/native executor create an original five-minute
	// flow whose trusted test-clock timeline began earlier. No record, digest,
	// cookie, command journal or persisted state is rewritten by this fixture.
	config := f.signin.config()
	config.Clock = signinOffsetClock{offset: -5*time.Minute + time.Second}
	olderIssuer, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	f.signin = olderIssuer
	r := f.request(t, session.BrowserSession)
	config.Clock = clock.System{}
	f.signin, err = NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	options, err := f.signin.AuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("near-expiry real flow options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("missing ceremony")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	r.CommandID, _ = identity.NewCommandID()
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.delay_signin_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='session.created.v1' THEN PERFORM pg_sleep(2); END IF; RETURN NEW; END $$; CREATE TRIGGER delay_signin_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.delay_signin_effect()`); err != nil {
		t.Fatal(err)
	}
	result, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)})
	if err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("flow expired during final effect wait but session committed")
	}
	var n int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&n); err != nil || n != 0 {
		t.Fatal("expired original flow retained provisional effects", err, n)
	}
}
