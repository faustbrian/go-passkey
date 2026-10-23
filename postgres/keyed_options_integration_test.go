//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

func keyedFixtureConfig(t *testing.T, f *enrollmentFixture, policy kernel.CommandQueryPolicy) OptionsRequestConfig {
	t.Helper()
	history, err := (kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 1000}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.NewRequestKeyConfig("passkey-options-fixture", [32]byte{41}, policy)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewDigestKey(1, bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewOptionsRequestConfig(keys, token, csrf)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func optionsKey(t *testing.T, value string) identity.IdempotencyKey {
	t.Helper()
	k, err := identity.NewIdempotencyKey([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyedRegistrationOptionsRetainOriginalAndEnroll(t *testing.T) {
	f := newEnrollmentFixture(t)
	c := f.service.config()
	c.OptionsRequests = keyedFixtureConfig(t, f, *c.Coordinator.QueryPolicy)
	var err error
	f.service, err = NewEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, false)
	r.Primary.CommandID = ""
	request := KeyedRegistrationOptionsRequest{RegistrationRequest: r, IdempotencyKey: optionsKey(t, "original-register-options")}
	first, err := f.service.KeyedRegistrationOptions(f.ctx, request)
	if err != nil || first.CommandID == "" || first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("keyed registration did not commit", err)
	}
	ceremony, ok := first.Options.Ceremony()
	if !ok {
		t.Fatal("winner did not receive ceremony")
	}
	challenge := signinChallenge(t, f.ctx, first.Options.TransferJSON)
	second, err := f.service.KeyedRegistrationOptions(f.ctx, request)
	if err != nil || second.CommandID != first.CommandID || !second.Replayed || second.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("matching original request did not reconcile", err)
	}
	if _, ok := second.Options.Ceremony(); ok {
		t.Fatal("replay returned ceremony")
	}
	if err := second.Options.TransferJSON(f.ctx, func(context.Context, []byte) error { t.Fatal("replay exposed challenge"); return nil }); err == nil {
		t.Fatal("replay accepted transfer")
	}
	changed := request
	changed.Device = "changed-device"
	if out, err := f.service.KeyedRegistrationOptions(f.ctx, changed); err == nil || out.CommandID != "" {
		t.Fatal("same key accepted changed input")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response := residentRegistrationResponse(t, key, bytes.Repeat([]byte{77}, 32), challenge)
	completion := RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: response, Label: "Keyed enrollment"}
	verified, err := f.service.Register(f.ctx, completion)
	if _, ok := verified.Credential(); err != nil || !ok {
		t.Fatal("keyed ceremony could not enroll", err)
	}
	if replay, err := f.service.KeyedRegistrationOptions(f.ctx, request); err != nil || replay.CommandID != first.CommandID || !replay.Replayed {
		t.Fatal("consumed proof lost metadata reconciliation", err)
	}
}

func TestKeyedRegistrationOptionsContentionHasOneFreshReveal(t *testing.T) {
	f := newEnrollmentFixture(t)
	c := f.service.config()
	c.OptionsRequests = keyedFixtureConfig(t, f, *c.Coordinator.QueryPolicy)
	var err error
	f.service, err = NewEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, false)
	r.Primary.CommandID = ""
	request := KeyedRegistrationOptionsRequest{RegistrationRequest: r, IdempotencyKey: optionsKey(t, "contended-register-options")}
	var results [2]KeyedRegistrationOptionsResult
	var failures [2]error
	start := make(chan struct{})
	var done sync.WaitGroup
	for i := range results {
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			results[i], failures[i] = f.service.KeyedRegistrationOptions(f.ctx, request)
		}()
	}
	close(start)
	done.Wait()
	fresh := 0
	var original identity.CommandID
	for i, result := range results {
		if failures[i] != nil {
			var pending identity.InProgressError
			if !errors.As(failures[i], &pending) {
				t.Fatal("contender could not reconcile", failures[i])
			}
		}
		if original == "" {
			original = result.CommandID
		}
		if original == "" || result.CommandID != original {
			t.Fatal("contenders did not retain one original command")
		}
		if _, ok := result.Options.Ceremony(); ok {
			fresh++
			if result.Replayed || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("nonwinner received options")
			}
			_ = signinChallenge(t, f.ctx, result.Options.TransferJSON)
		} else if !result.Replayed {
			t.Fatal("loser was not metadata-only")
		}
	}
	if fresh != 1 {
		t.Fatal("expected exactly one fresh reveal", fresh)
	}
	var ceremonies, mappings, commands int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM identity.request_key_mappings),(SELECT count(*) FROM identity.commands WHERE purpose='identity.passkey.register-options')`).Scan(&ceremonies, &mappings, &commands); err != nil || ceremonies != 1 || mappings != 1 || commands != 1 {
		t.Fatal("contention duplicated durable options", err)
	}
}

type deniedOptionsPolicy struct{}

func (deniedOptionsPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}

func TestKeyedRegistrationOptionsDenyChangedInputAndCurrentPolicy(t *testing.T) {
	f := newEnrollmentFixture(t)
	c := f.service.config()
	c.OptionsRequests = keyedFixtureConfig(t, f, *c.Coordinator.QueryPolicy)
	var err error
	f.service, err = NewEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, false)
	r.Primary.CommandID = ""
	request := KeyedRegistrationOptionsRequest{RegistrationRequest: r, IdempotencyKey: optionsKey(t, "denied-register-options")}
	first, err := f.service.KeyedRegistrationOptions(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*KeyedRegistrationOptionsRequest){
		"origin":  func(q *KeyedRegistrationOptionsRequest) { q.Origin = "https://other.example" },
		"network": func(q *KeyedRegistrationOptionsRequest) { q.Network = "192.0.2.20" },
		"proof":   func(q *KeyedRegistrationOptionsRequest) { q.Primary.Proof.SessionVersion++ },
		"subject": func(q *KeyedRegistrationOptionsRequest) {
			q.Primary.Caller = q.Primary.Caller.Clone()
			q.Primary.Caller.Request.Subject.ID = "other-user"
		},
		"tenant": func(q *KeyedRegistrationOptionsRequest) { q.Primary.TenantID = "other-tenant" },
		"operation": func(q *KeyedRegistrationOptionsRequest) {
			q.Primary.Caller = q.Primary.Caller.Clone()
			q.Primary.Caller.Request.Action = "identity.passkey.register-verify"
		},
		"bearer": func(q *KeyedRegistrationOptionsRequest) {
			q.Primary.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		},
		"csrf": func(q *KeyedRegistrationOptionsRequest) { q.Primary.CSRFToken, _ = session.NewCSRFToken() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if out, err := f.service.KeyedRegistrationOptions(f.ctx, changed); err == nil || out.CommandID != "" {
				t.Fatal("changed input disclosed original metadata/options")
			}
		})
	}
	query := *c.Coordinator.QueryPolicy
	query.Authorization = deniedOptionsPolicy{}
	c.Coordinator.QueryPolicy = &query
	c.Coordinator.AdmissionPolicy = &query
	denied, err := NewEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := denied.KeyedRegistrationOptions(f.ctx, request); err == nil || out.Receipt.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("current policy denial disclosed history")
	}
	if _, ok := first.Options.Ceremony(); !ok {
		t.Fatal("original winner unexpectedly lost options")
	}
}

func TestKeyedOptionsRecoverActualCommitDisconnect(t *testing.T) {
	for _, before := range []bool{true, false} {
		name := "after-commit"
		if before {
			name = "before-commit"
		}
		t.Run(name, func(t *testing.T) {
			f := newEnrollmentFixture(t)
			c := f.service.config()
			c.OptionsRequests = keyedFixtureConfig(t, f, *c.Coordinator.QueryPolicy)
			c.Coordinator.LeaseDuration = 100 * time.Millisecond
			r := f.request(t, false)
			r.Primary.CommandID = ""
			request := KeyedRegistrationOptionsRequest{RegistrationRequest: r, IdempotencyKey: optionsKey(t, "disconnect-register-options")}
			fault := &enrollmentCommitFault{before: before, marker: "INSERT INTO webauthn.ceremonies"}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(p *database.PoolConfig) error {
				p.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				p.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if pool.Close(ctx) != nil {
					t.Error("fault pool cleanup failed")
				}
			}()
			interrupted, err := NewEnrollmentService(pool, c)
			if err != nil {
				t.Fatal(err)
			}
			first, callErr := interrupted.KeyedRegistrationOptions(f.ctx, request)
			if !fault.hit.Load() || first.CommandID == "" {
				t.Fatal("actual COMMIT disconnect was not exercised", callErr)
			}
			if _, ok := first.Options.Ceremony(); ok {
				t.Fatal("ambiguous command returned options")
			}
			if callErr == nil && (first.Receipt.Outcome != identity.CommitOutcomeCommitted || !first.Replayed) {
				t.Fatal("ambiguous options returned zero-success metadata")
			}
			if callErr != nil {
				var pending identity.InProgressError
				var unknown identity.UnknownCommitError
				var aborted identity.NotCommittedError
				if !errors.As(callErr, &pending) && !errors.As(callErr, &unknown) && !errors.As(callErr, &aborted) {
					t.Fatal("ambiguous options did not classify original command state", callErr)
				}
			}
			restarted, err := NewEnrollmentService(f.pool, c)
			if err != nil {
				t.Fatal(err)
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
				out, err := restarted.KeyedRegistrationOptions(ctx, request)
				if out.CommandID != first.CommandID {
					t.Fatal("unknown retry allocated another original command", err)
				}
				if _, ok := out.Options.Ceremony(); ok {
					t.Fatal("unknown retry regenerated challenge")
				}
				if out.Receipt.Outcome == want {
					if !out.Replayed || !before && err != nil {
						t.Fatal("reconciled command shape invalid", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original unknown options did not reconcile", err)
				case <-ticker.C:
				}
			}
			var ceremonies int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM webauthn.ceremonies`).Scan(&ceremonies); err != nil || before && ceremonies != 0 || !before && ceremonies != 1 {
				t.Fatal("unknown recovery changed ceremony effects", err)
			}
		})
	}
}

func TestKeyedSigninOptionsRetainOriginalAndIssueSession(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		name := "identified"
		if discoverable {
			name = "discoverable"
		}
		t.Run(name, func(t *testing.T) {
			f := newSigninFixtureFlagsProfile(t, 0x45, discoverable)
			c := f.signin.config()
			c.OptionsRequests = keyedFixtureConfig(t, f.enrollmentFixture, *c.Coordinator.QueryPolicy)
			var err error
			f.signin, err = NewSigninService(f.pool, c)
			if err != nil {
				t.Fatal(err)
			}
			r := f.request(t, session.BrowserSession)
			r.CommandID = ""
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(c.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: authorization.Action(signinOperation(false).OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
			request := KeyedSigninOptionsRequest{SigninRequest: r, IdempotencyKey: optionsKey(t, "original-signin-options"), Caller: caller}
			call := func(q KeyedSigninOptionsRequest) (KeyedAssertionOptionsResult, error) {
				if !discoverable {
					return f.signin.KeyedAuthenticationOptions(f.ctx, q)
				}
				return f.signin.KeyedDiscoverableAuthenticationOptions(f.ctx, KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discoverableRequest(q.SigninRequest), IdempotencyKey: q.IdempotencyKey, Caller: q.Caller})
			}
			if discoverable {
				request.Identifier = ""
			}
			first, err := call(request)
			if err != nil || first.CommandID == "" || first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("keyed signin options failed", err)
			}
			ceremony, ok := first.Options.Ceremony()
			if !ok {
				t.Fatal("winner ceremony absent")
			}
			challenge := signinChallenge(t, f.ctx, first.Options.TransferJSON)
			replay, err := call(request)
			if err != nil || replay.CommandID != first.CommandID || !replay.Replayed || replay.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("keyed signin replay did not retain command", err)
			}
			if _, ok := replay.Options.Ceremony(); ok {
				t.Fatal("replay returned assertion options")
			}
			for label, change := range map[string]func(*KeyedSigninOptionsRequest){
				"cookie": func(q *KeyedSigninOptionsRequest) {
					q.Cookie, _ = session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
				},
				"network": func(q *KeyedSigninOptionsRequest) { q.Network = "192.0.2.4" },
				"flow":    func(q *KeyedSigninOptionsRequest) { q.FlowID = "AQEBAQEBAQEBAQEBAQEBAQ" },
				"caller": func(q *KeyedSigninOptionsRequest) {
					q.Caller = q.Caller.Clone()
					q.Caller.Request.Subject.ID = "other-service"
				},
			} {
				t.Run(label, func(t *testing.T) {
					changed := request
					change(&changed)
					if out, err := call(changed); err == nil || out.CommandID != "" {
						t.Fatal("changed signin request disclosed original command")
					}
				})
			}
			if !discoverable {
				changed := request
				changed.Identifier = "different@example.test"
				if out, err := call(changed); err == nil || out.CommandID != "" {
					t.Fatal("same key accepted different identified target")
				}
				if out, err := f.signin.KeyedDiscoverableAuthenticationOptions(f.ctx, KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discoverableRequest(request.SigninRequest), IdempotencyKey: request.IdempotencyKey, Caller: request.Caller}); err == nil || out.CommandID != "" {
					t.Fatal("same operation/key changed authentication mode")
				}
			}
			r.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			response := f.assertion(t, challenge, 1)
			var issued SigninResult
			if discoverable {
				issued, err = f.signin.DiscoverableSignin(f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: discoverableRequest(r), CeremonyID: ceremony.ID, Response: response})
			} else {
				issued, err = f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: response})
			}
			if err != nil || issued.Session.Token == (session.Token{}) {
				t.Fatal("keyed options did not reach real session", err)
			}
			passkeyJourneyReadInventoryLogout(t, f, issued)
			// Historical options stay metadata-only after completion consumes the flow.
			after, err := call(request)
			if err != nil || after.CommandID != first.CommandID || !after.Replayed {
				t.Fatal("consumed original flow lost reconciliation", err)
			}
		})
	}
}

func TestKeyedDiscoverableOptionsContentionHasOneFreshReveal(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	c := f.signin.config()
	c.OptionsRequests = keyedFixtureConfig(t, f.enrollmentFixture, *c.Coordinator.QueryPolicy)
	var err error
	f.signin, err = NewSigninService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	r := discoverableRequest(f.request(t, session.BrowserSession))
	r.CommandID = ""
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(c.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: authorization.Action(signinOperation(false).OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
	request := KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: r, IdempotencyKey: optionsKey(t, "contended-discovery-options"), Caller: caller}
	var results [2]KeyedAssertionOptionsResult
	var failures [2]error
	start := make(chan struct{})
	var done sync.WaitGroup
	for i := range results {
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			results[i], failures[i] = f.signin.KeyedDiscoverableAuthenticationOptions(f.ctx, request)
		}()
	}
	close(start)
	done.Wait()
	fresh := 0
	for i, result := range results {
		if failures[i] != nil {
			var pending identity.InProgressError
			if !errors.As(failures[i], &pending) {
				t.Fatal("discovery contender failed reconciliation", failures[i])
			}
		}
		if result.CommandID == "" || result.CommandID != results[0].CommandID {
			t.Fatal("discovery contention allocated two original commands")
		}
		if _, ok := result.Options.Ceremony(); ok {
			fresh++
			if result.Replayed {
				t.Fatal("discovery replay had challenge")
			}
			_ = signinChallenge(t, f.ctx, result.Options.TransferJSON)
		} else if !result.Replayed {
			t.Fatal("discovery loser was not metadata-only")
		}
	}
	if fresh != 1 {
		t.Fatal("discovery contention did not have one fresh reveal", fresh)
	}
}

func TestKeyedSigninOptionsReplayAfterOriginalFlowExpiry(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		name := "identified"
		if discoverable {
			name = "discoverable"
		}
		t.Run(name, func(t *testing.T) {
			f := newSigninFixtureFlagsProfile(t, 0x45, discoverable)
			config := f.signin.config()
			config.OptionsRequests = keyedFixtureConfig(t, f.enrollmentFixture, *config.Coordinator.QueryPolicy)
			var err error
			f.signin, err = NewSigninService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			r := f.request(t, session.BrowserSession)
			r.CommandID = ""
			if discoverable {
				r.Identifier = ""
			}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(config.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(config.Protocol.TenantID), Action: authorization.Action(signinOperation(false).OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
			request := KeyedSigninOptionsRequest{SigninRequest: r, IdempotencyKey: optionsKey(t, "expiry-signin-options"), Caller: caller}
			call := func(q KeyedSigninOptionsRequest) (KeyedAssertionOptionsResult, error) {
				if !discoverable {
					return f.signin.KeyedAuthenticationOptions(f.ctx, q)
				}
				return f.signin.KeyedDiscoverableAuthenticationOptions(f.ctx, KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discoverableRequest(q.SigninRequest), IdempotencyKey: q.IdempotencyKey, Caller: q.Caller})
			}
			first, err := call(request)
			if err != nil || first.Receipt.Outcome != identity.CommitOutcomeCommitted || first.Replayed {
				t.Fatal("original options did not commit", err)
			}
			if _, ok := first.Options.Ceremony(); !ok {
				t.Fatal("fresh options absent")
			}
			flow, err := sessionpg.ReadPreAuth(f.ctx, f.pool.Raw(), config.Repository, config.Protocol.TenantID, r.FlowID)
			if err != nil {
				t.Fatal(err)
			}
			original, err := flow.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			// Advance the existing native test-clock seam to the exact immutable
			// owner-issued expiry. Do not rewrite the flow, digest or journal.
			config.Clock = signinClock{stamp: original.Binding.ExpiresAt}
			f.signin, err = NewSigninService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			cookie, err := r.Cookie.PreAuthDigest(config.Flow.LookupKey, original.Binding)
			if err != nil || !errors.Is(flow.Check(config.Clock.Now(), original.Binding, cookie), session.ErrPreAuthDenied) {
				t.Fatal("fixture did not actually expire original native flow", err)
			}
			replay, err := call(request)
			if err != nil || replay.CommandID != first.CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted || !replay.Replayed {
				t.Fatal("expired original flow lost exact committed metadata", err)
			}
			if _, ok := replay.Options.Ceremony(); ok {
				t.Fatal("expired original replay regenerated options")
			}
			if err := replay.Options.TransferJSON(f.ctx, func(context.Context, []byte) error {
				t.Fatal("expired original replay transferred challenge")
				return nil
			}); err == nil {
				t.Fatal("expired original replay accepted transfer")
			}
			fresh := request
			fresh.IdempotencyKey = optionsKey(t, "expired-fresh-signin-options")
			denied, err := call(fresh)
			if err == nil || denied.CommandID == first.CommandID {
				t.Fatal("fresh key bypassed native original-flow expiry")
			}
			if _, ok := denied.Options.Ceremony(); ok {
				t.Fatal("fresh expired flow received options")
			}
			if err := denied.Options.TransferJSON(f.ctx, func(context.Context, []byte) error { t.Fatal("fresh expired flow transferred challenge"); return nil }); err == nil {
				t.Fatal("fresh expired flow accepted transfer")
			}
			var ceremonies, commands int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies WHERE kind='get-discoverable'),(SELECT count(*) FROM identity.commands WHERE purpose='identity.passkey.signin-options')`).Scan(&ceremonies, &commands); err != nil || ceremonies != 1 || commands != 1 {
				t.Fatal("expiry replay/denial created another native ceremony", err)
			}
		})
	}
}

func TestKeyedRegistrationOptionsReplayAfterOriginalProofExpiry(t *testing.T) {
	var advanced time.Time
	nativeNow := func() time.Time {
		if !advanced.IsZero() {
			return advanced
		}
		return time.Now()
	}
	f := newEnrollmentFixture(t, nativeNow)
	config := f.service.config()
	config.OptionsRequests = keyedFixtureConfig(t, f, *config.Coordinator.QueryPolicy)
	var err error
	f.service, err = NewEnrollmentService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, false)
	r.Primary.CommandID = ""
	request := KeyedRegistrationOptionsRequest{RegistrationRequest: r, IdempotencyKey: optionsKey(t, "expiry-register-options")}
	first, err := f.service.KeyedRegistrationOptions(f.ctx, request)
	if err != nil || first.Receipt.Outcome != identity.CommitOutcomeCommitted || first.Replayed {
		t.Fatal("original registration options did not commit", err)
	}
	if _, ok := first.Options.Ceremony(); !ok {
		t.Fatal("fresh registration options absent")
	}
	// Keep a distinct, genuinely issued but unconsumed proof. Otherwise a
	// fresh-key denial could be explained by one-use consumption, not expiry.
	unconsumed := f.request(t, false)
	unconsumed.Primary.RecordID = string(unconsumed.Primary.CommandID)
	if _, err := config.OptionsSource.Prepare(f.ctx, unconsumed.Primary); err != nil {
		t.Fatal("unconsumed original proof was not genuinely admissible", err)
	}
	advanced = unconsumed.Primary.Proof.Proof.ExpiresAt
	if advanced.Before(r.Primary.Proof.Proof.ExpiresAt) {
		advanced = r.Primary.Proof.Proof.ExpiresAt
	}
	// The real password owner and its validator share this injected clock.
	// Advance beyond both exact signed expiries; no signed bytes or rows change.
	advanced = advanced.Add(time.Microsecond)
	if _, err := config.OptionsSource.Prepare(f.ctx, unconsumed.Primary); err == nil {
		t.Fatal("fixture did not actually expire the native unconsumed proof")
	}
	replay, err := f.service.KeyedRegistrationOptions(f.ctx, request)
	if err != nil || replay.CommandID != first.CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted || !replay.Replayed {
		t.Fatal("expired original proof lost exact committed metadata", err)
	}
	if _, ok := replay.Options.Ceremony(); ok {
		t.Fatal("expired proof replay regenerated options")
	}
	if err := replay.Options.TransferJSON(f.ctx, func(context.Context, []byte) error { t.Fatal("expired proof replay transferred challenge"); return nil }); err == nil {
		t.Fatal("expired proof replay accepted transfer")
	}
	for name, expired := range map[string]RegistrationRequest{"original-consumed": request.RegistrationRequest, "unconsumed": unconsumed} {
		t.Run(name, func(t *testing.T) {
			expired.Primary.CommandID, expired.Primary.RecordID = "", ""
			fresh := KeyedRegistrationOptionsRequest{RegistrationRequest: expired, IdempotencyKey: optionsKey(t, "expired-fresh-register-"+name)}
			denied, err := f.service.KeyedRegistrationOptions(f.ctx, fresh)
			if err == nil || denied.CommandID == first.CommandID {
				t.Fatal("fresh key bypassed native original-proof expiry")
			}
			if _, ok := denied.Options.Ceremony(); ok {
				t.Fatal("fresh expired proof received options")
			}
			if err := denied.Options.TransferJSON(f.ctx, func(context.Context, []byte) error { t.Fatal("fresh expired proof transferred challenge"); return nil }); err == nil {
				t.Fatal("fresh expired proof accepted transfer")
			}
		})
	}
	var ceremonies, commands int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM identity.commands WHERE purpose='identity.passkey.register-options')`).Scan(&ceremonies, &commands); err != nil || ceremonies != 1 || commands != 1 {
		t.Fatal("expiry replay/denial created another registration ceremony", err)
	}
}
