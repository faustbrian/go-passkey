//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// A browser flow proves possession of that browser, not of the supplied email.
// Options therefore cannot disclose account existence, eligibility or key IDs.
func TestIdentifiedPasskeyOptionsDoNotEnumerateAccounts(t *testing.T) {
	f := newSigninFixture(t)
	var baseline map[string]any
	for _, scenario := range []string{"eligible", "absent", "unverified", "no-passkey"} {
		t.Run(scenario, func(t *testing.T) {
			r := f.request(t, session.BrowserSession)
			switch scenario {
			case "absent":
				r.Identifier = "absent@example.test"
			case "unverified":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE identifier_id='signin-email'`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.identifiers SET verified=true,is_primary=true,verification_state=2,verified_at=clock_timestamp() WHERE identifier_id='signin-email'`); err != nil {
						t.Error(err)
					}
				})
			case "no-passkey":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.credentials SET state='revoked'`); err != nil {
					t.Fatal(err)
				}
			}
			options, err := f.signin.AuthenticationOptions(f.ctx, r)
			if err != nil {
				t.Fatal("anonymous options disclose account eligibility through denial", err)
			}
			ceremony, ok := options.Ceremony()
			if !ok || ceremony.Intent.Context.UserID != "" || ceremony.Intent.Context.AnonymousFlowID != string(r.FlowID) || len(ceremony.Intent.UserHandle) != 0 || len(ceremony.Intent.AllowedCredentials) != 0 {
				t.Fatal("anonymous ceremony metadata discloses account admission")
			}
			if err := options.TransferJSON(f.ctx, func(_ context.Context, wire []byte) error {
				var doc struct {
					PublicKey map[string]any `json:"publicKey"`
				}
				if err := json.Unmarshal(wire, &doc); err != nil {
					return err
				}
				if _, present := doc.PublicKey["allowCredentials"]; present {
					t.Error("anonymous options disclose account credential descriptors")
				}
				challenge, ok := doc.PublicKey["challenge"].(string)
				if !ok || len(challenge) != 43 || doc.PublicKey["userVerification"] != "required" {
					t.Error("real bounded UV challenge absent")
				}
				delete(doc.PublicKey, "challenge")
				if baseline == nil {
					baseline = doc.PublicKey
				} else if !reflect.DeepEqual(baseline, doc.PublicKey) {
					t.Error("anonymous options differ by account eligibility")
				}
				return nil
			}); err != nil {
				t.Fatal("anonymous options unavailable", err)
			}
		})
	}
}

func TestIdentifiedPasskeySuppressedAdmissionCannotPromoteToAuthentication(t *testing.T) {
	f := newSigninFixture(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.credentials SET state='revoked'`); err != nil {
		t.Fatal(err)
	}
	r := f.request(t, session.BrowserSession)
	options, err := f.signin.AuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("suppressed anonymous options", err)
	}
	ceremony, _ := options.Ceremony()
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.credentials SET state='active'`); err != nil {
		t.Fatal(err)
	}
	r.CommandID, _ = identity.NewCommandID()
	if result, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)}); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("suppressed original admission became authenticating")
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("suppressed admission retained authentication effects", err, effects)
	}
}

func TestIdentifiedPasskeyCannotSubstituteIdentifierOnOriginalFlow(t *testing.T) {
	f := newSigninFixture(t)
	r, _ := f.pending(t)
	// A second eligible email deliberately names the same user and key. The
	// original identifier binding must still reject this genuinely signed reply.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW','alternate-email','email','alternate@example.test',true,false,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	r.Identifier = "alternate@example.test"
	if result, err := f.signin.Signin(f.ctx, r); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("changed original identifier authenticated")
	}
}

func TestIdentifiedPasskeyInvalidAssertionDoesNotEnumerateAccounts(t *testing.T) {
	f := newSigninFixture(t)
	for _, identifier := range []string{"passkey@example.test", "absent@example.test"} {
		r := f.request(t, session.BrowserSession)
		r.Identifier = identifier
		options, err := f.signin.AuthenticationOptions(f.ctx, r)
		if err != nil {
			t.Fatal("account-independent options", err)
		}
		ceremony, _ := options.Ceremony()
		challenge := signinChallenge(t, f.ctx, options.TransferJSON)
		wire := f.assertion(t, challenge, 1)
		var body map[string]any
		if err := json.Unmarshal(wire, &body); err != nil {
			t.Fatal(err)
		}
		body["response"].(map[string]any)["signature"] = "AA"
		wire, _ = json.Marshal(body)
		r.CommandID, _ = identity.NewCommandID()
		result, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: wire})
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || result.Session.Token != (session.Token{}) {
			t.Fatal("unverified assertion discloses identifier eligibility through its error type", err)
		}
	}
}
