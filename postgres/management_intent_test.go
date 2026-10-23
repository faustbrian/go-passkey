package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
)

// The expected fieldset is the pre-extraction ac3373f requestIntent contract,
// not the new shared helper. Retained request keys cannot silently change input
// identity when a binary adds deletion alongside existing rename.
func TestManagementIntentRetainsHistoricalCanonicalFields(t *testing.T) {
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(2, bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := token.Reveal()
	c := ManagementConfig{TenantID: "tenant", RPNamespace: "namespace", RPID: "identity.example", PolicyID: "policy", PolicyVersion: 3, RequestTokenKey: key, RequestCSRFKey: csrfKey, Password: sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store"}, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "global", PolicyNamespace: "users", Audience: "browser"}}}
	owner := ManagementService{config: func() ManagementConfig { return c }}
	issued := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	r := passkey.UpdateRequest{Primary: password.ActionPrimaryRequest{Session: auth.NewBearerCredential(wire), Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "proof", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "management", IssuedAt: issued, ExpiresAt: issued.Add(time.Minute)}, SessionID: "session", SessionVersion: 7, Action: "identity.passkey.update"}}, ReferenceID: "reference", ExpectedVersion: 11, Name: "Original name", Network: "192.0.2.1"}
	for _, cookie := range []bool{false, true} {
		if cookie {
			r.Primary.CSRFToken, err = session.NewCSRFToken()
			if err != nil {
				t.Fatal(err)
			}
		}
		actual, err := owner.requestIntent(r)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := token.Digest(key, "tenant")
		if err != nil {
			t.Fatal(err)
		}
		p := r.Primary.Proof
		fields := []identity.FeatureField{optionsText("management.rp-namespace", "namespace"), optionsText("management.rp-id", "identity.example"), optionsText("management.policy", "policy"), optionsUint("management.policy-version", 3), optionsText("management.reference", "reference"), optionsUint("management.expected", 11), optionsText("management.name", "Original name"), optionsText("management.network", "192.0.2.1"), optionsBytes("management.session", digest.Sum[:]), optionsUint("management.session-key", 1), optionsText("management.proof.id", "proof"), optionsText("management.proof.tenant", "tenant"), optionsText("management.proof.subject", "user"), optionsText("management.proof.method", "password"), optionsUint("management.proof.assurance", uint64(auth.AssuranceSingleFactor)), optionsText("management.proof.purpose", "identity.password.verify"), optionsText("management.proof.audience", "management"), optionsText("management.proof.session", "session"), optionsUint("management.proof.version", 7), optionsText("management.proof.action", "identity.passkey.update"), {Name: "management.proof.issued", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: issued}}, {Name: "management.proof.expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: issued.Add(time.Minute)}}, optionsText("management.reader.global", "global"), optionsText("management.reader.policy", "users"), optionsText("management.reader.audience", "browser"), optionsText("management.reader.schema", "session_store")}
		if cookie {
			csrf, err := r.Primary.CSRFToken.Digest(csrfKey, session.CSRFBinding{TenantID: c.TenantID, SessionID: p.SessionID, SessionVersion: p.SessionVersion})
			if err != nil {
				t.Fatal(err)
			}
			binding, _ := csrf.Bindings()
			fields = append(fields, optionsBytes("management.csrf", binding.Digest[:]), optionsUint("management.csrf-key", 2))
		}
		historical, err := identity.NewRequestIntent(fields)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := actual.Fields()
		want, _ := historical.Fields()
		gotBytes, _ := json.Marshal(got)
		wantBytes, _ := json.Marshal(want)
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Fatal("shared extraction changed retained rename request identity")
		}
	}
}
