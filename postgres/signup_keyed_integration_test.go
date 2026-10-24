//go:build integration

package postgres

import (
	"errors"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
)

func TestKeyedPasskeySignupOptionsRetainOriginalBrowserAndCommand(t *testing.T) {
	f, s := newSignupFixture(t, true)
	r := signupBrowserRequest(t, f, s)
	r.CommandID = ""
	c := s.core.config()
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "signup-keyed", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(c.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
	request := passkey.KeyedSignupOptionsRequest{SignupRequest: r, IdempotencyKey: optionsKey(t, "original-signup-options"), Caller: caller}
	first, err := s.KeyedRegistrationOptions(f.ctx, request)
	if err != nil || first.CommandID == "" || first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted {
		var commands, ceremonies int
		if readErr := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE purpose='identity.passkey.register-options'),(SELECT count(*) FROM webauthn.ceremonies)`).Scan(&commands, &ceremonies); readErr != nil {
			t.Fatal("keyed signup diagnostic unavailable", readErr)
		}
		t.Fatal("keyed signup options did not commit", err, first.CommandID != "", first.Receipt.Outcome, first.Replayed, commands, ceremonies)
	}
	ceremony, ok := first.Options.Ceremony()
	if !ok || ceremony.Intent.Context.UserID == "" {
		t.Fatal("fresh signup options absent")
	}
	for i := 0; i < 2; i++ {
		replay, err := s.KeyedRegistrationOptions(f.ctx, request)
		if err != nil || !replay.Replayed || replay.CommandID != first.CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("keyed signup replay lost original metadata", err)
		}
		if _, ok := replay.Options.Ceremony(); ok {
			t.Fatal("signup retry disclosed another challenge")
		}
	}
	flow, err := sessionpg.ReadPreAuth(f.ctx, f.pool.Raw(), c.Repository, c.Protocol.TenantID, r.FlowID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	config := signupFixtureConfig(f, s)
	config.Clock = signinClock{stamp: original.Binding.ExpiresAt}
	advanced, err := NewSignupService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := r.Cookie.PreAuthDigest(c.Flow.LookupKey, original.Binding)
	if err != nil || !errors.Is(flow.Check(config.Clock.Now(), original.Binding, digest), session.ErrPreAuthDenied) {
		t.Fatal("original signup flow was not actually expired", err)
	}
	if replay, err := advanced.KeyedRegistrationOptions(f.ctx, request); err != nil || !replay.Replayed || replay.CommandID != first.CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("expiry lost historical signup options metadata", err)
	}
	recovery := r
	recovery.CommandID = first.CommandID
	if receipt, err := advanced.RecoverRegistrationOptions(f.ctx, recovery, caller); err != nil || receipt.Binding.CommandID != first.CommandID || receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original cookie could not recover expired options metadata", err)
	}
	unseen := request
	unseen.IdempotencyKey = optionsKey(t, "expired-new-signup-options")
	if result, err := advanced.KeyedRegistrationOptions(f.ctx, unseen); err == nil {
		t.Fatal("new key bypassed original signup expiry", result.Receipt.Outcome)
	}
	for _, change := range []string{"cookie", "flow", "network", "device", "origin", "caller", "resource"} {
		foreign := request
		switch change {
		case "cookie":
			foreign.Cookie, _ = session.NewToken(32)
		case "flow":
			foreign.FlowID = "AQEBAQEBAQEBAQEBAQEBAQ"
		case "network":
			foreign.Network = "192.0.2.4"
		case "device":
			foreign.Device = "other-browser"
		case "origin":
			foreign.Origin = "https://foreign.example"
		case "caller":
			foreign.Caller.Request.Subject.ID = "other-service"
		case "resource":
			foreign.Caller.Request.Resource.Type = "identity.preauth"
		}
		if out, err := s.KeyedRegistrationOptions(f.ctx, foreign); err == nil || out.CommandID != "" {
			t.Fatal("changed keyed signup disclosed original metadata", change, err)
		}
	}
	var ceremonies, charges, snapshots, users, handles int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM passkey_risk.counter_charges),(SELECT count(*) FROM passkey_risk.counter_snapshots),(SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity_passkey.user_handles)`).Scan(&ceremonies, &charges, &snapshots, &users, &handles); err != nil || ceremonies != 1 || charges != 1 || snapshots != 4 || users != 1 || handles != 0 {
		t.Fatal("keyed options repeated protected effects or created identity", err, ceremonies, charges, snapshots, users, handles)
	}
}

func TestKeyedPasskeySignupOptionsContentionDisclosesOneChallenge(t *testing.T) {
	f, s := newSignupFixture(t, true)
	r := signupBrowserRequest(t, f, s)
	r.CommandID = ""
	c := s.core.config()
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(c.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
	request := passkey.KeyedSignupOptionsRequest{SignupRequest: r, IdempotencyKey: optionsKey(t, "contended-signup-options"), Caller: caller}
	var results [2]KeyedRegistrationOptionsResult
	var failures [2]error
	var group sync.WaitGroup
	group.Add(2)
	for i := range results {
		go func() {
			defer group.Done()
			results[i], failures[i] = s.KeyedRegistrationOptions(f.ctx, request)
		}()
	}
	group.Wait()
	winners := 0
	for i := range results {
		_, present := results[i].Options.Ceremony()
		if failures[i] == nil && !results[i].Replayed {
			if !present || results[i].Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("fresh keyed signup options winner missing")
			}
			winners++
		} else if present {
			t.Fatal("losing signup request disclosed a challenge")
		}
	}
	if winners != 1 || results[0].CommandID == "" || results[0].CommandID != results[1].CommandID {
		t.Fatal("keyed signup contention allocated another original command", winners)
	}
	replay, err := s.KeyedRegistrationOptions(f.ctx, request)
	if err != nil || !replay.Replayed || replay.CommandID != results[0].CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("contended signup did not settle on original metadata", err)
	}
	var ceremonies, charges, snapshots int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM passkey_risk.counter_charges),(SELECT count(*) FROM passkey_risk.counter_snapshots)`).Scan(&ceremonies, &charges, &snapshots); err != nil || ceremonies != 1 || charges != 1 || snapshots != 4 {
		t.Fatal("contended options repeated protected effects", err, ceremonies, charges, snapshots)
	}
	assertSignupEffects(t, f, 0)
}
