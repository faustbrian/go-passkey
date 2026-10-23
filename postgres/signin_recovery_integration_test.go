//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestIdentifiedPasskeySigninRecoversActualCommitDisconnect(t *testing.T) {
	for _, before := range []bool{true, false} {
		name := "after-commit"
		if before {
			name = "before-commit"
		}
		t.Run(name, func(t *testing.T) {
			f := newSigninFixture(t)
			completion, _ := f.pending(t)
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
			result, err := interrupted.Signin(f.ctx, completion)
			if err == nil || !fault.hit.Load() || result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) || result.Session.CommitOutcome != identity.CommitOutcomeUnknown {
				t.Fatal("lost COMMIT acknowledgement disclosed authentication or lost ambiguity", err, result.Session.CommitOutcome)
			}
			restarted, err := NewSigninService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			q := identity.RecoveryQuery{CommandID: completion.CommandID, TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorKind: authorization.SubjectUser, OperationID: signinOperation(true).OperationID, RecordID: string(completion.CommandID)}
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
						t.Fatal("recovery changed original command", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("signin did not reconcile original command", err)
				case <-ticker.C:
				}
			}
			var sessions, effects, flows, audits, outbox int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.signin-verify' AND outcome=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='session.created.v1')`, audit.OutcomeSucceeded).Scan(&sessions, &effects, &flows, &audits, &outbox); err != nil || sessions != count || effects != count || flows != count || audits != count || outbox != count {
				t.Fatal("COMMIT recovery split protected owners", err, sessions, effects, flows, audits, outbox)
			}
			if repeated, err := restarted.Signin(f.ctx, completion); err == nil || repeated.Session.Token != (session.Token{}) || repeated.CSRF != (session.CSRFToken{}) {
				t.Fatal("historical recovery replay minted authentication")
			}
		})
	}
}
