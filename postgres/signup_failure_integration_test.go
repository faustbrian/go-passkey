//go:build integration

package postgres

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func pendingSignup(t *testing.T, choices ...session.RememberChoice) (*signinFixture, *SignupService, passkey.SignupCompletion) {
	t.Helper()
	f, s := newSignupFixture(t)
	r := signupBrowserRequest(t, f, s, choices...)
	options, err := s.RegistrationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("pending signup options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("pending signup ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return f, s, passkey.SignupCompletion{SignupRequest: r, CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge), Label: "Signup key"}
}

func TestPasskeySignupPreservesOriginalPersistentChoice(t *testing.T) {
	f, s, request := pendingSignup(t, session.PersistentSession)
	result, err := s.Signup(f.ctx, request)
	if err != nil {
		t.Fatal("persistent signup", err)
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.Remember.Choice() != session.PersistentSession || result.Session.Cookie.MaxAge <= 0 || result.Session.Cookie.Expires.IsZero() {
		t.Fatal("signup changed the original remember choice", err)
	}
	assertSignupEffects(t, f, 1)
}

func assertSignupEffects(t *testing.T, f *signinFixture, want int) {
	t.Helper()
	var users, handles, credentials, mappings, sessions, factors, consumed, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*)-1 FROM identity.users),(SELECT count(*) FROM identity_passkey.user_handles),(SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM identity_passkey.credentials),(SELECT count(*)-1 FROM session_store.sessions),(SELECT count(*)-1 FROM identity_mfa.factor_authorities),(SELECT count(*) FROM webauthn.ceremonies WHERE consumed_by IS NOT NULL),(SELECT count(*) FROM public.outbox_messages WHERE topic IN('identity.passkey.create_credential','user.created.v1','session.created.v1'))`).Scan(&users, &handles, &credentials, &mappings, &sessions, &factors, &consumed, &events); err != nil || users != want || handles != want || credentials != want || mappings != want || sessions != want || factors != want || consumed != want || events != 3*want {
		t.Fatal("signup owners/effects split", err, users, handles, credentials, mappings, sessions, factors, consumed, events)
	}
}

func TestPasskeySignupDeniesForeignInputAndWithdrawnAuthority(t *testing.T) {
	for _, mode := range []string{"cookie", "origin", "flow", "attestation", "global", "tenant", "context", "audit", "outbox"} {
		t.Run(mode, func(t *testing.T) {
			f, s, request := pendingSignup(t)
			sql := ""
			switch mode {
			case "cookie":
				request.Cookie, _ = session.NewToken(32)
			case "origin":
				request.Origin = "https://foreign.example"
			case "flow":
				other := signupBrowserRequest(t, f, s)
				request.FlowID, request.Cookie = other.FlowID, other.Cookie
			case "attestation":
				request.Response = bytes.Replace(request.Response, []byte(`"attestationObject":"`), []byte(`"attestationObject":"A`), 1)
			case "global":
				sql = `UPDATE identity.global_authorities SET version=version+1`
			case "tenant":
				sql = `UPDATE identity.tenant_authorities SET version=version+1`
			case "context":
				sql = `DELETE FROM identity_passkey.signup_contexts`
			case "audit":
				sql = `ALTER TABLE audit.records ADD CONSTRAINT test_signup_audit_rejection CHECK(action<>'identity.passkey.create_credential') NOT VALID`
			case "outbox":
				sql = `ALTER TABLE public.outbox_messages ADD CONSTRAINT test_signup_event_rejection CHECK(topic<>'session.created.v1') NOT VALID`
			}
			if sql != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
					t.Fatal("withdrawal/failure fixture", err)
				}
			}
			result, err := s.Signup(f.ctx, request)
			if err == nil || result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid signup authenticated or committed", err)
			}
			assertSignupEffects(t, f, 0)
		})
	}
}

func TestPasskeySignupOptionsDenySixthProtectedAttempt(t *testing.T) {
	f, s := newSignupFixture(t)
	r := signupBrowserRequest(t, f, s)
	for attempt := 1; attempt <= 6; attempt++ {
		r.CommandID, _ = identity.NewCommandID()
		options, err := s.RegistrationOptions(f.ctx, r)
		_, present := options.Ceremony()
		if attempt <= 5 && (err != nil || !present) || attempt == 6 && (err == nil || present) {
			t.Fatal("protected signup options limit changed", attempt, err)
		}
	}
	var ceremonies, charges, snapshots int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM passkey_risk.counter_charges),(SELECT count(*) FROM passkey_risk.counter_snapshots)`).Scan(&ceremonies, &charges, &snapshots); err != nil || ceremonies != 5 || charges != 6 || snapshots != 24 {
		t.Fatal("protected denial did not retain exact attempt/effects", err, ceremonies, charges, snapshots)
	}
	assertSignupEffects(t, f, 0)
}

func TestPasskeySignupReplayAndContentionRevealOneSession(t *testing.T) {
	for _, sameCommand := range []bool{false, true} {
		t.Run(map[bool]string{false: "different-command", true: "same-command"}[sameCommand], func(t *testing.T) {
			f, s, request := pendingSignup(t)
			requests := []passkey.SignupCompletion{request, request}
			if !sameCommand {
				requests[1].CommandID, _ = identity.NewCommandID()
			}
			var results [2]passkey.SignupResult
			var failures [2]error
			var group sync.WaitGroup
			group.Add(2)
			for i := range requests {
				go func() {
					defer group.Done()
					results[i], failures[i] = s.Signup(f.ctx, requests[i])
				}()
			}
			group.Wait()
			winners := 0
			for i := range results {
				if failures[i] == nil {
					if results[i].Session.Token == (session.Token{}) || results[i].CSRF == (session.CSRFToken{}) || results[i].Session.CommitOutcome != identity.CommitOutcomeCommitted || results[i].Session.Replayed {
						t.Fatal("fresh signup winner lost delivery")
					}
					winners++
				} else if results[i].Session.Token != (session.Token{}) || results[i].CSRF != (session.CSRFToken{}) {
					t.Fatal("losing signup disclosed authentication")
				}
			}
			if winners != 1 {
				t.Fatal("signup contention did not yield exactly one delivery", winners)
			}
			assertSignupEffects(t, f, 1)
			if replay, err := s.Signup(f.ctx, request); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
				t.Fatal("signup replay disclosed authentication", err)
			}
			assertSignupEffects(t, f, 1)
		})
	}
}
