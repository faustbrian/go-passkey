//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type removalReadHook struct {
	match string
	count atomic.Int32
	at    int32
	start func(context.Context) context.Context
	end   func()
}

type removalReadHookKey struct{}

func (h *removalReadHook) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	hit := strings.Contains(q.SQL, h.match) && h.count.Add(1) == h.at
	if hit && h.start != nil {
		ctx = h.start(ctx)
	}
	return context.WithValue(ctx, removalReadHookKey{}, hit)
}

func (h *removalReadHook) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if hit, _ := ctx.Value(removalReadHookKey{}).(bool); hit && h.end != nil {
		h.end()
	}
}

type removalReadClock struct{ advanced atomic.Bool }

func (c *removalReadClock) Now() time.Time {
	if c.advanced.Load() {
		return time.Now().Add(21 * time.Second)
	}
	return time.Now()
}

func tracedRemovalService(t *testing.T, f *sessionManagementTestFixture, original *SessionDeletionService, hook *removalReadHook, clock *removalReadClock) *SessionDeletionService {
	t.Helper()
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.Tracer = hook
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	c := original.owner.config()
	if clock != nil {
		c.Clock = clock
	}
	s, err := NewSessionDeletionService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPasskeySessionRemovalPreservesCredentialReadCancellation(t *testing.T) {
	f, original, intent, completion := pendingSessionDeletion(t, false)
	for _, finish := range []bool{false, true} {
		for _, at := range []int32{2, 3} {
			for _, deadline := range []bool{false, true} {
				// The first lookup belongs to genuine source-session admission;
				// subsequent reads admit the target and independent remaining key.
				name := map[bool]string{false: "options", true: "completion"}[finish] + "/" + map[int32]string{2: "target", 3: "remaining"}[at] + "/" + map[bool]string{false: "cancel", true: "deadline"}[deadline]
				t.Run(name, func(t *testing.T) {
					ctx, stop := context.WithCancel(f.ctx)
					defer stop()
					hook := &removalReadHook{match: "FROM identity.users u JOIN identity.credential_references c", at: at, start: func(read context.Context) context.Context {
						if deadline {
							// Inject an actual expired driver read context, not a sleep
							// or an unrelated fixture/setup deadline.
							expired, cancel := context.WithDeadline(read, time.Now().Add(-time.Second))
							cancel()
							return expired
						}
						stop()
						return read
					}}
					s := tracedRemovalService(t, f, original, hook, nil)
					var err error
					if finish {
						_, err = s.Delete(ctx, passkey.NewSessionDeleteCompletion(completion))
					} else {
						_, err = s.DeleteOptions(ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: optionsKey(t, "cancel-removal-options")})
					}
					want := context.Canceled
					if deadline {
						want = context.DeadlineExceeded
					}
					if hook.count.Load() != at || !errors.Is(err, want) {
						t.Fatal("credential read cancellation became an eligibility denial", err)
					}
					assertNoSessionDeletionEffect(t, f, completion.CeremonyID)
				})
			}
		}
	}
}

func TestPasskeySessionRemovalPreservesMappingReadCancellation(t *testing.T) {
	f, original, intent, completion := pendingSessionDeletion(t, false)
	for _, finish := range []bool{false, true} {
		t.Run(map[bool]string{false: "options", true: "completion"}[finish], func(t *testing.T) {
			ctx, stop := context.WithCancel(f.ctx)
			defer stop()
			hook := &removalReadHook{match: "SELECT c.credential_id,c.version::text,c.metadata_version::text", at: 1, start: func(read context.Context) context.Context {
				stop()
				return read
			}}
			s := tracedRemovalService(t, f, original, hook, nil)
			var err error
			if finish {
				_, err = s.Delete(ctx, passkey.NewSessionDeleteCompletion(completion))
			} else {
				_, err = s.DeleteOptions(ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: optionsKey(t, "cancel-removal-mapping")})
			}
			if hook.count.Load() != 1 || !errors.Is(err, context.Canceled) {
				t.Fatal("mapping read cancellation became an eligibility denial", err)
			}
			assertNoSessionDeletionEffect(t, f, completion.CeremonyID)
		})
	}
}

func TestPasskeySessionRemovalReplayDoesNotOutliveOriginalRead(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(map[bool]string{false: "options", true: "completion"}[finish], func(t *testing.T) {
			f, original, intent, completion := pendingSessionDeletion(t, false)
			if finish {
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.abort_removal_replay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='identity.passkey.remove_credential' THEN RAISE EXCEPTION 'controlled rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER abort_removal_replay BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.abort_removal_replay()`); err != nil {
					t.Fatal(err)
				}
				if _, err := original.Delete(f.ctx, passkey.NewSessionDeleteCompletion(completion)); err == nil {
					t.Fatal("controlled removal did not roll back")
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER abort_removal_replay ON public.outbox_messages`); err != nil {
					t.Fatal(err)
				}
				replayed, _ := original.Delete(f.ctx, passkey.NewSessionDeleteCompletion(completion))
				metadata, err := replayed.Bindings()
				if err != nil || !metadata.Replayed || metadata.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("original rolled-back command lacks terminal retry metadata", err)
				}
			}
			clock := &removalReadClock{}
			// Advance only at actual command-history IO after genuine current
			// session authentication. The original positive lease cannot renew.
			hook := &removalReadHook{match: "SELECT coalesce(c.tenant_id", at: 1, end: func() { clock.advanced.Store(true) }}
			s := tracedRemovalService(t, f, original, hook, clock)
			var metadata passkey.DeleteResult
			var err error
			if finish {
				result, callErr := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(completion))
				metadata, _ = result.Bindings()
				err = callErr
			} else {
				result, callErr := s.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: optionsKey(t, "session-delete-A")})
				metadata = passkey.DeleteResult{CommandID: result.CommandID, Receipt: result.Receipt, Replayed: result.Replayed}
				err = callErr
			}
			if !clock.advanced.Load() || err == nil || metadata.CommandID != "" || metadata.Receipt != (identity.CommandResult{}) || metadata.Replayed {
				t.Fatal("expired original source disclosed replay metadata", err)
			}
			assertNoSessionDeletionEffect(t, f, completion.CeremonyID)
		})
	}
}

func TestPasskeySessionRemovalRequiredEffectAndFinalFencesRollback(t *testing.T) {
	for _, mode := range []string{"required-effect", "session", "remaining-mapping", "passkey-generation", "kernel-successor"} {
		t.Run(mode, func(t *testing.T) {
			f, s, intent, r := pendingSessionDeletion(t, false)
			fault := `RAISE EXCEPTION 'controlled required effect unavailable';`
			switch mode {
			case "session":
				fault = `UPDATE session_store.sessions SET state='revoked';`
			case "remaining-mapping":
				fault = `UPDATE identity_passkey.credentials SET state='revoked' WHERE reference_id<>'` + string(intent.ReferenceID) + `';`
			case "passkey-generation":
				fault = `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1;`
			case "kernel-successor":
				fault = `UPDATE identity.credential_references SET enabled=true WHERE owner='passkey';`
			}
			// This fault runs at the actual required outbox, after native owner
			// writes. Final checks must reject replacement of this Work's exact
			// successor, not merely trust its earlier successful admission.
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.fail_session_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='identity.passkey.remove_credential' THEN `+fault+` END IF; RETURN NEW; END $$; CREATE TRIGGER fail_session_removal BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.fail_session_removal()`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(r)); err == nil {
				t.Fatal("required effect/final authority withdrawal reported success")
			}
			assertNoSessionDeletionEffect(t, f, r.CeremonyID)
			var active, enabled int
			var generation string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_passkey.credentials WHERE state='active'),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey' AND enabled),(SELECT authority_version::text FROM identity_passkey.user_handles)`).Scan(&active, &enabled, &generation); err != nil || active != 2 || enabled != 2 || generation != "1" {
				t.Fatal("aborted removal lost original mapping/reference/generation", err)
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_session_removal ON public.outbox_messages`); err != nil {
				t.Fatal(err)
			}
			// A known rolled-back command keeps its terminal outcome; only a
			// distinct request may use the genuinely unconsumed original UV.
			r.IdempotencyKey = optionsKey(t, "after-session-removal-rollback")
			out, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(r))
			metadata, projected := out.Bindings()
			if err != nil || projected != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("rollback consumed original proof or changed authority", err)
			}
		})
	}
}

func TestPasskeySessionRemovalContentionHasOneFreshWinner(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-key", false: "distinct-keys"}[sameKey], func(t *testing.T) {
			f, s, _, original := pendingSessionDeletion(t, false)
			start := make(chan struct{})
			fresh := make([]bool, 2)
			competingKey := optionsKey(t, "competing-session-removal")
			var joined sync.WaitGroup
			for i := range fresh {
				joined.Add(1)
				go func(i int) {
					defer joined.Done()
					<-start
					r := original
					if !sameKey && i == 1 {
						r.IdempotencyKey = competingKey
					}
					out, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(r))
					metadata, projected := out.Bindings()
					fresh[i] = err == nil && projected == nil && !metadata.Replayed && metadata.Outcome == identity.CommitOutcomeCommitted
				}(i)
			}
			close(start)
			joined.Wait()
			if fresh[0] == fresh[1] {
				t.Fatal("contention must have exactly one fresh removal")
			}
			var effects, events, erased int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.delete' AND after_credential IS NOT NULL),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM webauthn.credentials WHERE record->'PublicKey'='null'::jsonb)`).Scan(&effects, &events, &erased); err != nil || effects != 1 || events != 1 || erased != 1 {
				t.Fatal("contention duplicated removal or required effects", err)
			}
		})
	}
}

func TestPasskeySessionRemovalRecoversActualCommitDisconnect(t *testing.T) {
	for _, finish := range []bool{false, true} {
		for _, before := range []bool{true, false} {
			t.Run(map[bool]string{true: "completion/", false: "options/"}[finish]+map[bool]string{true: "before", false: "after"}[before], func(t *testing.T) {
				f, s, intent, completion, remaining := pendingSessionDeletionWithRecovery(t, false)
				marker := "INSERT INTO identity_passkey.signin_contexts"
				if finish {
					marker = "UPDATE identity_passkey.credentials SET state='revoked'"
				}
				fault := &enrollmentCommitFault{before: before, marker: marker}
				pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := pool.Close(cleanup); err != nil {
						t.Error(err)
					}
				}()
				var ownsDatabase bool
				if err := pool.Raw().QueryRow(f.ctx, `SELECT current_database()=$1`, f.pool.Raw().Config().ConnConfig.Database).Scan(&ownsDatabase); err != nil || !ownsDatabase {
					t.Fatal("fault pool did not reach this test's owned database", err)
				}
				c := s.owner.config()
				c.Coordinator.LeaseDuration = 500 * time.Millisecond
				interrupted, err := NewSessionDeletionService(pool, c)
				if err != nil {
					t.Fatal(err)
				}
				var out passkey.DeleteResult
				if finish {
					result, callErr := interrupted.Delete(f.ctx, passkey.NewSessionDeleteCompletion(completion))
					out, _ = result.Bindings()
					err = callErr
				} else {
					result, callErr := interrupted.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: optionsKey(t, "disconnected-removal-options")})
					if _, options := result.Options.Ceremony(); options {
						t.Fatal("lost acknowledgement disclosed options")
					}
					out = passkey.DeleteResult{CommandID: result.CommandID, Receipt: result.Receipt, Outcome: result.Receipt.Outcome, Replayed: result.Replayed}
					err = callErr
				}
				if !fault.hit.Load() || out.CommandID == "" || err == nil && !out.Replayed {
					t.Fatal("lost commit acknowledgement became fresh success", err)
				}
				restarted, err := NewSessionDeletionService(f.pool, c)
				if err != nil {
					t.Fatal(err)
				}
				spec, _ := f.issued.Session.Session.Bindings()
				q := identity.RecoveryQuery{CommandID: out.CommandID, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.passkey.delete", RecordID: string(intent.ReferenceID)}
				if !finish {
					q.RecordID = string(out.CommandID)
				}
				if finish && !before {
					// Successful removal deliberately invalidates the original source.
					// Obtain genuine new authority from the surviving key, not an old
					// lease or an invented recovery session, before metadata recovery.
					next := sessionDeletionSignin(t, remaining, 1)
					wire, err := next.Session.Token.Reveal()
					if err != nil {
						t.Fatal(err)
					}
					token, err := session.ParseToken(wire)
					if err != nil {
						t.Fatal(err)
					}
					intent.Credential, err = session.NewCredential(session.CredentialBearer, token)
					if err != nil {
						t.Fatal(err)
					}
				}
				want := identity.CommitOutcomeCommitted
				if before {
					want = identity.CommitOutcomeNotCommitted
				}
				ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
				defer stop()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					var recovered passkey.DeleteResult
					if finish {
						result, e := restarted.RecoverDelete(ctx, passkey.NewSessionDeleteRequest(intent), q)
						recovered, _ = result.Bindings()
						err = e
					} else {
						result, e := restarted.DeleteOptions(ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: optionsKey(t, "disconnected-removal-options")})
						recovered = passkey.DeleteResult{CommandID: result.CommandID, Receipt: result.Receipt, Outcome: result.Receipt.Outcome, Replayed: result.Replayed}
						err = e
						if _, options := result.Options.Ceremony(); options {
							t.Fatal("recovery renewed options")
						}
					}
					if recovered.Outcome == want {
						if recovered.CommandID != out.CommandID || !recovered.Replayed || recovered.Receipt.Validate() != nil || !before && err != nil {
							t.Fatal("recovery lost original metadata-only outcome", err)
						}
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("original removal did not reconcile", err)
					case <-ticker.C:
					}
				}
				if before || !finish {
					assertNoSessionDeletionEffect(t, f, completion.CeremonyID)
				}
			})
		}
	}
}
