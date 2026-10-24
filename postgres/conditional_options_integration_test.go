//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func conditionalChallenge(t *testing.T, ctx context.Context, options passkey.ConditionalAssertionOptions) string {
	t.Helper()
	var challenge string
	if err := options.TransferJSON(ctx, func(_ context.Context, wire []byte) error {
		var doc struct {
			Mediation string                     `json:"mediation"`
			PublicKey map[string]json.RawMessage `json:"publicKey"`
		}
		if err := json.Unmarshal(wire, &doc); err != nil {
			return err
		}
		if doc.Mediation != "conditional" || string(doc.PublicKey["userVerification"]) != `"required"` {
			t.Fatal("conditional presentation weakened native UV policy")
		}
		if _, present := doc.PublicKey["allowCredentials"]; present {
			t.Fatal("conditional options selected an account")
		}
		return json.Unmarshal(doc.PublicKey["challenge"], &challenge)
	}); err != nil || challenge == "" {
		t.Fatal("conditional challenge unavailable", err)
	}
	return challenge
}

func conditionalKeyedRequest(t *testing.T, f *signinFixture, r DiscoverableSigninRequest) KeyedDiscoverableOptionsRequest {
	t.Helper()
	c := f.signin.config()
	return KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: r, IdempotencyKey: optionsKey(t, "original-conditional-options"), Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(c.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: authorization.Action(signinOperation(false).OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}}
}

func TestConditionalPasskeyOptionsReachNativeSessionReadAndLogout(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "browser-keyless", true: "persistent-keyed"}[persistent], func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			choice := session.BrowserSession
			if persistent {
				choice = session.PersistentSession
			}
			r := discoverableRequest(f.request(t, choice))
			var options passkey.ConditionalAssertionOptions
			var request KeyedDiscoverableOptionsRequest
			var command identity.CommandID
			var err error
			if persistent {
				c := f.signin.config()
				c.OptionsRequests = keyedFixtureConfig(t, f.enrollmentFixture, *c.Coordinator.QueryPolicy)
				f.signin, err = NewSigninService(f.pool, c)
				if err != nil {
					t.Fatal(err)
				}
				r.CommandID = ""
				request = conditionalKeyedRequest(t, f, r)
				first, err := f.signin.KeyedConditionalAuthenticationOptions(f.ctx, request)
				if err != nil || first.CommandID == "" || first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("conditional options did not commit", err)
				}
				command, options = first.CommandID, first.Options
				// There is no distinct conditional assertion protocol/key namespace.
				// Both presentations recover the same discoverable original command.
				replayed, err := f.signin.KeyedDiscoverableAuthenticationOptions(f.ctx, request)
				if err != nil || replayed.CommandID != command || !replayed.Replayed {
					t.Fatal("presentation invented a second key owner", err)
				}
				identified := KeyedSigninOptionsRequest{SigninRequest: SigninRequest{FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, Identifier: "passkey@example.test"}, IdempotencyKey: request.IdempotencyKey, Caller: request.Caller}
				if out, err := f.signin.KeyedAuthenticationOptions(f.ctx, identified); err == nil || out.CommandID != "" {
					t.Fatal("conditional discovery key became identified admission")
				}
			} else {
				options, err = f.signin.ConditionalAuthenticationOptions(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
			}
			ceremony, ok := options.Ceremony()
			if !ok || ceremony.Intent.Context.UserID != "" || ceremony.Intent.Context.AnonymousFlowID != string(r.FlowID) {
				t.Fatal("conditional options selected a principal")
			}
			if persistent {
				// Source reads need a valid current attempt ID, not the options key.
				r.CommandID = command
			}
			source, err := f.signin.DiscoverableSigninRateSource(f.ctx, passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID})
			if err != nil || source.AnonymousFlowID != r.FlowID || source.UserID != "" || source.Identifier != "" || source.Lifetime != 5*time.Minute {
				t.Fatal("conditional presentation changed original anonymous rate metadata", err)
			}
			challenge := conditionalChallenge(t, f.ctx, options)
			if err := options.TransferJSON(f.ctx, func(context.Context, []byte) error { t.Fatal("conditional options disclosed twice"); return nil }); err == nil {
				t.Fatal("conditional projection repeated challenge")
			}
			r.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			completion := DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)}
			issued, err := f.signin.DiscoverableSignin(f.ctx, completion)
			if err != nil || issued.Session.Token == (session.Token{}) || issued.CSRF == (session.CSRFToken{}) {
				t.Fatal("conditional options did not reach genuine native session", err)
			}
			binding, err := issued.Session.Session.Bindings()
			if err != nil || binding.Remember.Choice() != choice || persistent != (issued.Session.Cookie.MaxAge > 0) {
				t.Fatal("conditional presentation changed original remember choice", err)
			}
			if replay, err := f.signin.DiscoverableSignin(f.ctx, completion); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
				t.Fatal("conditional assertion replay returned authentication")
			}
			passkeyJourneyReadInventoryLogout(t, f, issued)
			if persistent {
				after, err := f.signin.KeyedConditionalAuthenticationOptions(f.ctx, request)
				if err != nil || after.CommandID != command || !after.Replayed || after.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("conditional retry lost metadata after flow consumption", err)
				}
				if _, ok := after.Options.Ceremony(); ok {
					t.Fatal("conditional replay reconstructed options")
				}
			}
		})
	}
}

func TestConditionalPasskeyOptionsRequireDiscoveryPolicy(t *testing.T) {
	f := newSigninFixture(t)
	r := discoverableRequest(f.request(t, session.BrowserSession))
	if _, err := f.signin.ConditionalAuthenticationOptions(f.ctx, r); err == nil {
		t.Fatal("conditional presentation bypassed discovery risk policy")
	}
	var ceremonies int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE kind='get-discoverable'`).Scan(&ceremonies); err != nil || ceremonies != 0 {
		t.Fatal("denial persisted options", err)
	}
}

func TestConditionalPasskeyOptionsRetainExpiryAndVerification(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "UV-required", true: "original-expiry"}[expired], func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			r := discoverableRequest(f.request(t, session.BrowserSession))
			options, err := f.signin.ConditionalAuthenticationOptions(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			ceremony, _ := options.Ceremony()
			challenge := conditionalChallenge(t, f.ctx, options)
			if expired {
				c := f.signin.config()
				c.Clock = signinClock{stamp: time.Now().UTC().Add(6 * time.Minute)}
				f.signin, err = NewSigninService(f.pool, c)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				f.assertionFlags = 0x01
			}
			r.CommandID, _ = identity.NewCommandID()
			issued, err := f.signin.DiscoverableSignin(f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)})
			if err == nil || issued.Session.Token != (session.Token{}) || issued.CSRF != (session.CSRFToken{}) {
				t.Fatal("conditional UI lifetime or response bypassed native verification")
			}
		})
	}
}
