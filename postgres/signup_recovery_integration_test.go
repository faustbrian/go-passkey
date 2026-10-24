//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
)

func TestKeyedPasskeySignupOptionsRecoverRealCommitDisconnect(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-commit", false: "after-commit"}[before], func(t *testing.T) {
			f, s := newSignupFixture(t, true)
			r := signupBrowserRequest(t, f, s)
			r.CommandID = ""
			config := signupFixtureConfig(f, s)
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(config.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(config.Protocol.TenantID), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
			request := passkey.KeyedSignupOptionsRequest{SignupRequest: r, IdempotencyKey: optionsKey(t, "disconnected-signup-options"), Caller: caller}
			fault := &enrollmentCommitFault{before: before, marker: "INSERT INTO webauthn.ceremonies"}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := pool.Close(ctx); err != nil {
					t.Error("signup options fault pool cleanup", err)
				}
			}()
			interrupted, err := NewSignupService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			first, callErr := interrupted.KeyedRegistrationOptions(f.ctx, request)
			if !fault.hit.Load() || first.CommandID == "" {
				t.Fatal("actual signup options COMMIT disconnect not reached", callErr)
			}
			if _, present := first.Options.Ceremony(); present {
				t.Fatal("ambiguous signup options disclosed a challenge")
			}
			if callErr == nil && (!first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("ambiguous signup options returned empty success metadata")
			}
			if callErr != nil {
				var pending identity.InProgressError
				var unknown identity.UnknownCommitError
				var aborted identity.NotCommittedError
				if !errors.As(callErr, &pending) && !errors.As(callErr, &unknown) && !errors.As(callErr, &aborted) {
					t.Fatal("signup options ambiguity not classified", callErr)
				}
			}
			restarted, err := NewSignupService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			want, count := identity.CommitOutcomeCommitted, 1
			if before {
				want, count = identity.CommitOutcomeNotCommitted, 0
			}
			ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				out, err := restarted.KeyedRegistrationOptions(ctx, request)
				if out.CommandID != first.CommandID {
					t.Fatal("signup options retry allocated another command", err)
				}
				if _, present := out.Options.Ceremony(); present {
					t.Fatal("signup options recovery regenerated challenge")
				}
				if out.Receipt.Outcome == want {
					if !out.Replayed || out.Receipt.Validate() != nil || out.Receipt.Binding.AnonymousFlowID != string(r.FlowID) || out.Receipt.Binding.UserID != "" || !before && err != nil {
						t.Fatal("signup options reconciliation lost original metadata", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original signup options did not reconcile", err)
				case <-ticker.C:
				}
			}
			recovery := r
			recovery.CommandID = first.CommandID
			if result, err := restarted.RecoverRegistrationOptions(f.ctx, recovery, caller); result.Outcome != want || result.Binding.CommandID != first.CommandID || !before && err != nil {
				t.Fatal("explicit signup options recovery lost original command", err)
			}
			foreign := recovery
			foreign.Cookie, _ = session.NewToken(32)
			if result, err := restarted.RecoverRegistrationOptions(f.ctx, foreign, caller); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("foreign browser recovered signup options metadata", err)
			}
			var ceremonies, contexts, charges, snapshots int
			// The kernel ReserveCommand phase retains the protected attempt even
			// if the later domain COMMIT rolls back. Recovery must not charge again.
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM identity_passkey.signup_contexts),(SELECT count(*) FROM passkey_risk.counter_charges),(SELECT count(*) FROM passkey_risk.counter_snapshots)`).Scan(&ceremonies, &contexts, &charges, &snapshots); err != nil || ceremonies != count || contexts != count || charges != 1 || snapshots != 4 {
				t.Fatal("signup options recovery changed provisional effects", err, ceremonies, contexts, charges, snapshots)
			}
			assertSignupEffects(t, f, 0)
		})
	}
}

func signupFixtureConfig(f *signinFixture, s *SignupService) SignupConfig {
	c := s.core.config()
	return SignupConfig{Protocol: c.Protocol, Profile: c.Profile, Coordinator: c.Coordinator, Authorization: c.Authorization, Clock: c.Clock, Flow: c.Flow, Session: c.Session, CSRF: c.CSRF, Repository: c.Repository, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: s.evaluation, ConfigurationID: "signup-native", Keys: f.riskConfig.EvidenceKeys}, Counters: f.riskConfig, OptionsRequests: s.optionsRequests}
}

func TestPasskeySignupRecoversRealCommitDisconnectWithoutRedelivery(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-commit", false: "after-commit"}[before], func(t *testing.T) {
			f, s, request := pendingSignup(t)
			fault := &enrollmentCommitFault{before: before, marker: "INSERT INTO identity_passkey.credentials"}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := pool.Close(ctx); err != nil {
					t.Error("signup fault pool cleanup", err)
				}
			}()
			config := signupFixtureConfig(f, s)
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			interrupted, err := NewSignupService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			issued, err := interrupted.Signup(f.ctx, request)
			if err == nil || !fault.hit.Load() || issued.Session.Token != (session.Token{}) || issued.CSRF != (session.CSRFToken{}) {
				t.Fatal("lost signup COMMIT acknowledgement disclosed authentication", err, fault.hit.Load())
			}
			restarted, err := NewSignupService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(config.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(config.Protocol.TenantID), Action: "identity.passkey.register-verify", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(request.FlowID)}}}
			want, count := identity.CommitOutcomeCommitted, 1
			if before {
				want, count = identity.CommitOutcomeNotCommitted, 0
			}
			ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				result, err := restarted.RecoverSignup(ctx, request.SignupRequest, request.CeremonyID, caller)
				if result.Outcome == want {
					if result.Validate() != nil || result.Binding.CommandID != request.CommandID || result.Binding.AnonymousFlowID != string(request.FlowID) || result.Binding.UserID != "" || !before && err != nil {
						t.Fatal("signup recovery changed original command", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original signup did not reconcile", err)
				case <-ticker.C:
				}
			}
			assertSignupEffects(t, f, count)
			foreign := request.SignupRequest
			foreign.Cookie, _ = session.NewToken(32)
			if result, err := restarted.RecoverSignup(f.ctx, foreign, request.CeremonyID, caller); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("foreign signup browser disclosed original metadata", err)
			}
			if replay, err := restarted.Signup(f.ctx, request); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
				t.Fatal("signup reconciliation reconstructed authentication", err)
			}
			assertSignupEffects(t, f, count)
		})
	}
}
