//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestDiscoverablePasskeyPreservesAcceptedCallbackBounds(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	config := f.signin.config()
	// This valid callback is within the session owner's accepted URL/storage
	// bounds but exceeds the passkey admission column after JSON HTML escaping.
	config.Flow.CallbackURL = "https://identity.example/callback?x=" + strings.Repeat("&", 1000)
	service, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal("accepted callback rejected", err)
	}
	f.signin = service
	r, _ := f.discoverablePending(t)
	issued, err := service.DiscoverableSignin(f.ctx, r)
	if err != nil || issued.Session.Token == (session.Token{}) {
		t.Fatal("accepted callback broke resident signin", err)
	}
	passkeyJourneyReadInventoryLogout(t, f, issued)
}

func discoverableRequest(r SigninRequest) DiscoverableSigninRequest {
	return DiscoverableSigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID}
}

func (f *signinFixture) discoverablePending(t *testing.T) (DiscoverableSigninCompletion, webauthn.AssertionOptions) {
	t.Helper()
	r := discoverableRequest(f.request(t, session.BrowserSession))
	options, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("native identifier-free options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok || ceremony.Intent.Context.UserID != "" || ceremony.Intent.Context.AnonymousFlowID != string(r.FlowID) || len(ceremony.Intent.UserHandle) != 0 || len(ceremony.Intent.AllowedCredentials) != 0 {
		t.Fatal("identifier-free ceremony selected an account")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)}, options
}

func TestDiscoverablePasskeySigninInventoryReadAndCookieLogout(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	// No email, username or other identifier may be required to select this
	// enrolled identity. The authenticator returns the stable resident handle.
	if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity.identifiers WHERE identifier_id='signin-email'`); err != nil {
		t.Fatal(err)
	}
	r, options := f.discoverablePending(t)
	if err := options.TransferJSON(f.ctx, func(context.Context, []byte) error { return nil }); err == nil {
		t.Fatal("anonymous challenge disclosed twice")
	}
	result, err := f.signin.DiscoverableSignin(f.ctx, r)
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
		t.Fatal("genuine identifier-free signin", err, result.Session.CommitOutcome)
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.UserID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" || spec.Authentication.Proof.Subject != string(spec.UserID) || spec.Authentication.Proof.Method != "passkey" {
		t.Fatal("verified resident target not the actual session subject", err)
	}
	remember, err := spec.Remember.Bindings()
	if err != nil || remember.Choice != session.BrowserSession || result.Session.Cookie.MaxAge != 0 || !result.Session.Cookie.Expires.IsZero() {
		t.Fatal("original browser-only choice changed", err)
	}
	if replay, err := f.signin.DiscoverableSignin(f.ctx, r); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
		t.Fatal("resident assertion replay disclosed authentication")
	}
	passkeyJourneyReadInventoryLogout(t, f, result)
}

func TestDiscoverablePasskeyOptionsAreActuallyAccountIndependent(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity_passkey.enrollment_contexts; DELETE FROM identity_passkey.credentials; DELETE FROM identity_passkey.user_handles; DELETE FROM identity.identifiers WHERE identifier_id='signin-email'`); err != nil {
		t.Fatal(err)
	}
	r := discoverableRequest(f.request(t, session.BrowserSession))
	options, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("anonymous options require an account", err)
	}
	if err := options.TransferJSON(f.ctx, func(_ context.Context, wire []byte) error {
		var response struct {
			PublicKey map[string]any `json:"publicKey"`
		}
		if err := json.Unmarshal(wire, &response); err != nil {
			return err
		}
		if _, present := response.PublicKey["allowCredentials"]; present || response.PublicKey["userVerification"] != "required" {
			t.Error("account descriptors disclosed or UV weakened")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverablePasskeyRequiresActualRiskOptIn(t *testing.T) {
	f := newSigninFixture(t)
	r := discoverableRequest(f.request(t, session.BrowserSession))
	if _, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, r); err == nil {
		t.Fatal("identifier-free options substituted a fabricated identifier or weaker risk lane")
	}
	var ceremonies int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE kind='get-discoverable'`).Scan(&ceremonies); err != nil || ceremonies != 0 {
		t.Fatal("missing risk opt-in persisted anonymous assertion options", err, ceremonies)
	}
}

func TestDiscoverablePasskeyCannotPromoteIdentifiedAdmission(t *testing.T) {
	for _, suppressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "suppressed-identified"}[suppressed], func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			r := f.request(t, session.BrowserSession)
			if suppressed {
				r.Identifier = "absent@example.test"
			}
			options, err := f.signin.AuthenticationOptions(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			ceremony, _ := options.Ceremony()
			challenge := signinChallenge(t, f.ctx, options.TransferJSON)
			r.CommandID, _ = identity.NewCommandID()
			input := DiscoverableSigninCompletion{DiscoverableSigninRequest: discoverableRequest(r), CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)}
			if result, err := f.signin.DiscoverableSignin(f.ctx, input); err == nil || result.Session.Token != (session.Token{}) {
				t.Fatal("identified admission switched modes")
			}
		})
	}
}

func TestDiscoverablePasskeyDeniesForeignAndWithdrawnAuthority(t *testing.T) {
	for _, mode := range []string{"cookie", "origin", "other-flow", "signature", "handle", "UV", "foreign-tenant", "foreign-RP", "global-epoch", "tenant-epoch", "blocked-user", "credential-disabled", "mapping-revoked", "factor-enrolled", "missing-context"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			r, _ := f.discoverablePending(t)
			service := f.signin
			sql := ""
			switch mode {
			case "cookie":
				r.Cookie, _ = session.NewToken(32)
			case "origin":
				r.Origin = "https://foreign.example"
			case "other-flow":
				other := discoverableRequest(f.request(t, session.BrowserSession))
				r.FlowID, r.Cookie = other.FlowID, other.Cookie
			case "signature":
				r.Response = bytes.Replace(r.Response, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			case "handle":
				var body map[string]any
				if err := json.Unmarshal(r.Response, &body); err != nil {
					t.Fatal(err)
				}
				body["response"].(map[string]any)["userHandle"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{91}, 32))
				r.Response, _ = json.Marshal(body)
			case "UV":
				var body map[string]any
				if err := json.Unmarshal(r.Response, &body); err != nil {
					t.Fatal(err)
				}
				client, _ := base64.RawURLEncoding.DecodeString(body["response"].(map[string]any)["clientDataJSON"].(string))
				var data map[string]any
				if err := json.Unmarshal(client, &data); err != nil {
					t.Fatal(err)
				}
				f.assertionFlags = 0x01
				r.Response = f.assertion(t, data["challenge"].(string), 1)
			case "foreign-tenant":
				config := service.config()
				config.Protocol.TenantID = "foreign-tenant"
				var err error
				service, err = NewSigninService(f.pool, config)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign-RP":
				config := service.config()
				config.Profile.RPNamespace = "foreign-rp"
				var err error
				service, err = NewSigninService(f.pool, config)
				if err != nil {
					t.Fatal(err)
				}
			case "blocked-user":
				sql = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "global-epoch":
				sql = `UPDATE identity.global_authorities SET version=version+1`
			case "tenant-epoch":
				sql = `UPDATE identity.tenant_authorities SET version=version+1`
			case "credential-disabled":
				sql = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey'`
			case "mapping-revoked":
				sql = `UPDATE identity_passkey.credentials SET state='revoked'`
			case "factor-enrolled":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "missing-context":
				sql = `DELETE FROM identity_passkey.signin_contexts`
			}
			if sql != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			result, err := service.DiscoverableSignin(f.ctx, r)
			var denied identity.ForbiddenError
			if !errors.As(err, &denied) || result.Session.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) {
				t.Fatal("unverified or ineligible resident assertion disclosed authentication or account state", err)
			}
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("denial retained authentication effects", err, effects)
			}
		})
	}
}

func TestDiscoverablePasskeyCannotReplaceIdentifiedCompletion(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	r, _ := f.discoverablePending(t)
	identified := SigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID, Identifier: "passkey@example.test"}
	if result, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: identified, CeremonyID: r.CeremonyID, Response: r.Response}); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("discoverable ceremony accepted identified completion")
	}
}

type discoverableSigninPolicy func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f discoverableSigninPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, c)
}

func TestDiscoverablePasskeyFencesVerifiedTargetEpochs(t *testing.T) {
	for _, sql := range []string{
		`UPDATE identity.users SET authority_version=authority_version+1`,
		`UPDATE identity.users SET identifier_version=identifier_version+1`,
		`UPDATE identity.users SET credential_version=credential_version+1`,
		`UPDATE identity_mfa.factor_authorities SET version=version+1`,
		`UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`,
		`UPDATE authorization_subject_authorities SET version=version+1`,
	} {
		t.Run(sql, func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			r, _ := f.discoverablePending(t)
			config := f.signin.config()
			called := false
			config.Authorization = discoverableSigninPolicy(func(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
				if c.Request.Action == "identity.passkey.signin-verify" && c.Request.Subject.Kind == authorization.SubjectUser {
					called = true
					if _, err := f.pool.Raw().Exec(ctx, sql); err != nil {
						return authorization.Decision{}, err
					}
				}
				return (signinPolicy{}).Decide(ctx, c)
			})
			service, err := NewSigninService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.DiscoverableSignin(f.ctx, r)
			if err == nil || !called || result.Session.Token != (session.Token{}) {
				t.Fatal("target epochs refreshed after verified selection", err, called)
			}
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("changed target epoch retained effects", err, effects)
			}
		})
	}
}

func TestDiscoverablePasskeyPreservesRememberAndOriginalExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "persistent", true: "expired"}[expired], func(t *testing.T) {
			f := newDiscoverableSigninFixture(t)
			r := discoverableRequest(f.request(t, session.PersistentSession))
			options, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			ceremony, _ := options.Ceremony()
			challenge := signinChallenge(t, f.ctx, options.TransferJSON)
			r.CommandID, _ = identity.NewCommandID()
			service := f.signin
			if expired {
				config := service.config()
				config.Clock = signinClock{stamp: time.Now().UTC().Add(6 * time.Minute)}
				service, err = NewSigninService(f.pool, config)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := service.DiscoverableSignin(f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)})
			if expired {
				if err == nil || result.Session.Token != (session.Token{}) {
					t.Fatal("original expired flow authenticated")
				}
				return
			}
			spec, bindingErr := result.Session.Session.Bindings()
			if err != nil || bindingErr != nil || spec.Remember.Choice() != session.PersistentSession || result.Session.Cookie.MaxAge <= 0 || result.Session.Cookie.Expires.IsZero() {
				t.Fatal("original persistent choice changed", err, bindingErr)
			}
		})
	}
}
