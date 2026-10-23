//go:build integration

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestDiscoverablePasskeySigninRaceIssuesOneSession(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	r, _ := f.discoverablePending(t)
	var wg sync.WaitGroup
	results := make(chan SigninResult, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result, err := f.signin.DiscoverableSignin(f.ctx, r); err == nil {
				results <- result
			}
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for result := range results {
		winners++
		if result.Session.Token == (session.Token{}) || result.CSRF == (session.CSRFToken{}) {
			t.Fatal("winner lacks fresh credential custody")
		}
	}
	var sessions, effects, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&sessions, &effects, &consumed); err != nil || winners != 1 || sessions != 1 || effects != 1 || consumed != 1 {
		t.Fatal("resident race did not atomically choose one winner", err, winners, sessions, effects, consumed)
	}
}

func TestDiscoverablePasskeyRequiredEffectFailureRollsBack(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	r, _ := f.discoverablePending(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_discoverable_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='session.created.v1' THEN RAISE EXCEPTION 'controlled failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_discoverable_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_discoverable_outbox()`); err != nil {
		t.Fatal(err)
	}
	if result, err := f.signin.DiscoverableSignin(f.ctx, r); err == nil || result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) {
		t.Fatal("failed required effect disclosed authentication")
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("required effect failure left provisional state", err, effects)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_discoverable_outbox ON public.outbox_messages; DROP FUNCTION public.reject_discoverable_outbox()`); err != nil {
		t.Fatal(err)
	}
	r.CommandID, _ = identity.NewCommandID()
	if result, err := f.signin.DiscoverableSignin(f.ctx, r); err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("rollback consumed the original flow or ceremony", err)
	}
}

func TestDiscoverablePasskeyRecoversActualCommitDisconnect(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-commit", false: "after-commit"}[before], func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			r, _ := f.discoverablePending(t)
			fault := &enrollmentCommitFault{before: before, marker: "UPDATE identity_passkey.credentials SET last_used_at"}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal("fault pool unavailable")
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if pool.Close(ctx) != nil {
					t.Error("fault pool cleanup failed")
				}
			}()
			config := f.signin.config()
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			interrupted, err := NewSigninService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := interrupted.DiscoverableSignin(f.ctx, r)
			if err == nil || !fault.hit.Load() || result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) || result.Session.CommitOutcome != identity.CommitOutcomeUnknown {
				t.Fatal("unknown acknowledgement disclosed authentication or lost ambiguity", err, result.Session.CommitOutcome)
			}
			restarted, err := NewSigninService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorKind: authorization.SubjectUser, OperationID: signinOperation(true).OperationID, RecordID: string(r.CommandID)}
			caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-signin", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.UserID), Kind: authorization.SubjectUser}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
			want, count := identity.CommitOutcomeCommitted, 1
			if before {
				want, count = identity.CommitOutcomeNotCommitted, 0
			}
			ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				recovered, err := restarted.RecoverSignin(ctx, q, caller)
				if recovered.Outcome == want {
					if recovered.Binding.CommandID != q.CommandID || recovered.Validate() != nil || !before && err != nil {
						t.Fatal("recovery changed original metadata", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("resident command did not reconcile", err)
				case <-ticker.C:
				}
			}
			var sessions, effects, flows, audits, outbox int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.signin-verify' AND outcome=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='session.created.v1')`, audit.OutcomeSucceeded).Scan(&sessions, &effects, &flows, &audits, &outbox); err != nil || sessions != count || effects != count || flows != count || audits != count || outbox != count {
				t.Fatal("resident recovery split protected effects", err, sessions, effects, flows, audits, outbox)
			}
			if repeated, err := restarted.DiscoverableSignin(f.ctx, r); err == nil || repeated.Session.Token != (session.Token{}) || repeated.CSRF != (session.CSRFToken{}) {
				t.Fatal("recovery minted another credential")
			}
		})
	}
}
