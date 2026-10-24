//go:build integration

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
)

func TestPasskeySessionEnrollmentRequiredEffectsRollback(t *testing.T) {
	for _, stage := range []string{"A", "B", "C"} {
		t.Run(stage, func(t *testing.T) {
			var f *sessionManagementTestFixture
			var s *SessionEnrollmentService
			var intent passkey.SessionEnrollmentRequestSpec
			var b passkey.SessionEnrollmentAuthorizationSpec
			var c passkey.SessionEnrollmentCompletionSpec
			if stage == "C" {
				f, s, intent, c = pendingSessionEnrollmentCompletion(t, false)
			} else {
				f, s, intent, b = pendingSessionEnrollmentAuthorization(t, false)
			}
			event := map[string]string{"A": "passkey.reauthentication.started.v1", "B": "passkey.registration.started.v1", "C": "identity.passkey.create_credential"}[stage]
			// Install a fault at the actual required outbox owner, after native
			// protocol/mapping mutations, not a store returning a canned result.
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_additional_passkey() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='`+event+`' THEN RAISE EXCEPTION 'controlled required effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_additional_passkey BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_additional_passkey()`); err != nil {
				t.Fatal(err)
			}
			var err error
			parent := ""
			switch stage {
			case "A":
				_, err = s.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, "rollback-A")})
			case "B":
				parent = b.CeremonyID
				_, err = s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
			case "C":
				parent = c.CeremonyID
				_, err = s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c))
			}
			if err == nil {
				t.Fatal("required effect failure reported success")
			}
			assertSessionEnrollmentUnchanged(t, f)
			if parent != "" {
				var available int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=$1 AND consumed_by IS NULL`, parent).Scan(&available); err != nil || available != 1 {
					t.Fatal("rollback consumed original protocol ceremony", err)
				}
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_additional_passkey ON public.outbox_messages`); err != nil {
				t.Fatal(err)
			}
			// A known terminal failure is not an unknown retry. Start a new
			// command while retaining the actual unconsumed original proof.
			switch stage {
			case "A":
				_, err = s.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, "after-rollback-A")})
			case "B":
				b.IdempotencyKey = optionsKey(t, "after-rollback-B")
				_, err = s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
			case "C":
				c.CommandID, err = identity.NewCommandID()
				if err == nil {
					_, err = s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c))
				}
			}
			if err != nil {
				t.Fatal("rollback lost unchanged original authority or counter", err)
			}
		})
	}
}

func TestPasskeySessionEnrollmentContentionHasOneFreshWinner(t *testing.T) {
	for _, stage := range []string{"B", "C"} {
		t.Run(stage, func(t *testing.T) {
			var f *sessionManagementTestFixture
			var s *SessionEnrollmentService
			var b passkey.SessionEnrollmentAuthorizationSpec
			var c passkey.SessionEnrollmentCompletionSpec
			if stage == "B" {
				f, s, _, b = pendingSessionEnrollmentAuthorization(t, false)
			} else {
				f, s, _, c = pendingSessionEnrollmentCompletion(t, false)
			}
			var wg sync.WaitGroup
			fresh := make([]bool, 2)
			start := make(chan struct{})
			for i := range fresh {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					if stage == "B" {
						out, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
						_, options := out.Options.Ceremony()
						fresh[i] = err == nil && !out.Replayed && options && out.Receipt.Outcome == identity.CommitOutcomeCommitted
						return
					}
					out, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c))
					fields, e := out.Bindings()
					fresh[i] = err == nil && e == nil && !fields.Replayed && fields.Credential != nil && fields.Outcome == identity.CommitOutcomeCommitted
				}(i)
			}
			close(start)
			wg.Wait()
			if fresh[0] == fresh[1] {
				t.Fatal("expected exactly one fresh enrollment winner")
			}
			if stage == "B" {
				out, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
				if _, present := out.Options.Ceremony(); err != nil || !out.Replayed || present || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("B contention lost original metadata-only history", err)
				}
				assertSessionEnrollmentUnchanged(t, f)
			} else {
				out, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c))
				fields, e := out.Bindings()
				if err != nil || e != nil || !fields.Replayed || fields.Credential != nil || fields.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("C contention lost original metadata-only history", err)
				}
			}
		})
	}
}

func TestPasskeySessionEnrollmentRecoversActualCommitDisconnect(t *testing.T) {
	for _, stage := range []string{"A", "B", "C"} {
		for _, marker := range []string{"INSERT INTO identity.identity_command_id_claims", "INSERT INTO identity_passkey.signin_contexts"} {
			for _, before := range []bool{true, false} {
				t.Run(stage+"/"+marker+map[bool]string{true: "/before", false: "/after"}[before], func(t *testing.T) {
					var f *sessionManagementTestFixture
					var s *SessionEnrollmentService
					var intent passkey.SessionEnrollmentRequestSpec
					var b passkey.SessionEnrollmentAuthorizationSpec
					var c passkey.SessionEnrollmentCompletionSpec
					if stage == "C" {
						f, s, intent, c = pendingSessionEnrollmentCompletion(t, false)
					} else {
						f, s, intent, b = pendingSessionEnrollmentAuthorization(t, false)
					}
					call := func(service *SessionEnrollmentService, ctx context.Context) (passkey.SessionEnrollmentResultSpec, error) {
						switch stage {
						case "A":
							out, err := service.EnrollmentAssertionOptions(ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, "disconnect-A")})
							if _, revealed := out.Options.Ceremony(); revealed {
								t.Fatal("ambiguous assertion options disclosed ceremony")
							}
							return passkey.SessionEnrollmentResultSpec{CommandID: out.CommandID, Receipt: out.Receipt, Outcome: out.Receipt.Outcome, Replayed: out.Replayed}, err
						case "B":
							out, err := service.RegistrationOptions(ctx, passkey.NewSessionEnrollmentAuthorization(b))
							if _, revealed := out.Options.Ceremony(); revealed {
								t.Fatal("ambiguous registration options disclosed ceremony")
							}
							return passkey.SessionEnrollmentResultSpec{CommandID: out.CommandID, Receipt: out.Receipt, Outcome: out.Receipt.Outcome, Replayed: out.Replayed}, err
						default:
							out, err := service.Register(ctx, passkey.NewSessionEnrollmentCompletion(c))
							fields, _ := out.Bindings()
							return fields, err
						}
					}
					fault := &enrollmentCommitFault{before: before, marker: marker}
					pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(config *database.PoolConfig) error {
						config.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
						config.ConnConfig.DialFunc = fault.dial
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
					config := s.owner.config()
					config.Coordinator.LeaseDuration = 500 * time.Millisecond
					interrupted, err := NewSessionEnrollmentService(pool, config)
					if err != nil {
						t.Fatal(err)
					}
					out, err := call(interrupted, f.ctx)
					if !fault.hit.Load() || out.Credential != nil || err == nil && !out.Replayed {
						t.Fatal("actual COMMIT loss exposed fresh enrollment", err)
					}
					restarted, err := NewSessionEnrollmentService(f.pool, config)
					if err != nil {
						t.Fatal(err)
					}
					// A claim disconnected before acknowledgement is absent, so
					// retrying that same key may safely perform its first work.
					// This case is verified separately below, never as recovery of
					// an observed reserved mutation or renewed options.
					if marker == "INSERT INTO identity.identity_command_id_claims" && before {
						var first passkey.SessionEnrollmentResultSpec
						var err error
						switch stage {
						case "A":
							created, e := restarted.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, "disconnect-A")})
							_, options := created.Options.Ceremony()
							if !options {
								t.Fatal("unreserved A did not perform its first work", e)
							}
							first, err = passkey.SessionEnrollmentResultSpec{CommandID: created.CommandID, Outcome: created.Receipt.Outcome}, e
						case "B":
							created, e := restarted.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
							_, options := created.Options.Ceremony()
							if !options {
								t.Fatal("unreserved B did not perform its first work", e)
							}
							first, err = passkey.SessionEnrollmentResultSpec{CommandID: created.CommandID, Outcome: created.Receipt.Outcome}, e
						default:
							created, e := restarted.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c))
							first, _ = created.Bindings()
							err = e
						}
						if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.CommandID != out.CommandID {
							t.Fatal("retry of absent reservation changed original identity", err)
						}
						recovered, err := call(restarted, f.ctx)
						if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.CommandID != out.CommandID || recovered.Credential != nil {
							t.Fatal("first completed work did not become metadata only", err)
						}
						return
					}
					want := identity.CommitOutcomeCommitted
					if before || marker == "INSERT INTO identity.identity_command_id_claims" {
						want = identity.CommitOutcomeNotCommitted
					}
					bounded, stop := context.WithTimeout(f.ctx, 3*time.Second)
					defer stop()
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					for {
						recovered, err := call(restarted, bounded)
						if recovered.Outcome == want {
							if recovered.CommandID != out.CommandID || !recovered.Replayed || recovered.Credential != nil || recovered.Receipt.Validate() != nil || want == identity.CommitOutcomeCommitted && err != nil {
								t.Fatal("original enrollment outcome changed on recovery", err)
							}
							break
						}
						select {
						case <-bounded.Done():
							t.Fatal("original enrollment did not reconcile", err)
						case <-ticker.C:
						}
					}
					if stage != "C" || want != identity.CommitOutcomeCommitted {
						assertSessionEnrollmentUnchanged(t, f)
					}
				})
			}
		}
	}
}
