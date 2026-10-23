//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func inventoryFixture(t *testing.T) (*enrollmentFixture, *InventoryService, InventoryRequest) {
	t.Helper()
	f, completion := pendingEnrollment(t)
	if _, err := f.service.Register(f.ctx, completion); err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	password := sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "passkey-fixture", PolicyNamespace: "users", Audience: "passkey-fixture", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "passkey-fixture", Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}}
	c := f.service.config()
	s, err := NewInventoryService(f.pool, InventoryConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.RPNamespace, RPID: c.Protocol.RelyingParty.ID, Password: &password, Protocol: webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion}, Authorization: c.Authorization, PolicyVersion: c.PolicyVersion, Rate: &f.counters, MaximumDuration: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(f.bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	caller := completion.Primary.Caller.Clone()
	caller.Request.Action = "identity.passkey.list"
	return f, s, InventoryRequest{Credential: credential, Caller: caller, AttemptID: id, Limit: 10}
}

func TestPasskeyInventoryReturnsOnlyOwnedSafeMetadata(t *testing.T) {
	f, s, r := inventoryFixture(t)
	if got, err := s.sessions.Get(f.ctx, session.GetRequest{TenantID: s.config().TenantID, Credential: r.Credential}); err != nil || !got.Authenticated {
		t.Fatal("inventory original native session admission", err)
	}
	if _, _, err := s.admit(f.ctx, r); err != nil {
		t.Fatal("inventory original self-user authorization", err)
	}
	page, err := s.List(f.ctx, r)
	if err != nil || len(page.Credentials) != 1 || page.Next != "" {
		t.Fatal("native credential inventory", err, len(page.Credentials))
	}
	c := page.Credentials[0]
	if c.ReferenceID == "" || c.Version != 1 || c.State != "active" || c.Label != "My key" || c.CreatedAt.IsZero() || c.LastUsedAt != nil {
		t.Fatal("safe mapping metadata missing")
	}
	wire, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PublicKey", "UserHandle", "Challenge", "Cookie", "Counter", "CredentialID"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatal("protocol or authentication payload escaped safe inventory")
		}
	}
	r.After = c.ReferenceID
	r.AttemptID, _ = identity.NewCommandID()
	page, err = s.List(f.ctx, r)
	if err != nil || len(page.Credentials) != 0 {
		t.Fatal("keyset boundary repeated existing credential", err)
	}
}

func TestPasskeyInventoryDeniesForeignOrWithdrawnAuthority(t *testing.T) {
	f, s, valid := inventoryFixture(t)
	if page, err := s.List(f.ctx, valid); err != nil || len(page.Credentials) != 1 {
		t.Fatal("valid inventory control", err)
	}
	for _, mode := range []string{"caller", "tenant", "action", "resource", "credential", "limit", "cursor"} {
		t.Run(mode, func(t *testing.T) {
			r := valid
			r.Caller = valid.Caller.Clone()
			switch mode {
			case "caller":
				r.Caller.Request.Subject.ID = "another-user"
			case "tenant":
				r.Caller.Request.Tenant = "another-tenant"
			case "action":
				r.Caller.Request.Action = "identity.passkey.delete"
			case "resource":
				r.Caller.Request.Resource.ID = "another-user"
			case "credential":
				r.Credential = session.Credential{}
			case "limit":
				r.Limit = 101
			case "cursor":
				r.After = strings.Repeat("x", 129)
			}
			page, err := s.List(f.ctx, r)
			if err == nil || len(page.Credentials) != 0 || page.Next != "" {
				t.Fatal("foreign or malformed inventory disclosed metadata")
			}
		})
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='banned',authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(valid.Caller.Request.Tenant), string(valid.Caller.Request.Subject.ID)); err != nil {
		t.Fatal(err)
	}
	if page, err := s.List(f.ctx, valid); err == nil || len(page.Credentials) != 0 {
		t.Fatal("banned session disclosed passkeys")
	}
}

func TestPasskeyInventoryDoesNotReturnPartialProtocolMetadata(t *testing.T) {
	f, s, r := inventoryFixture(t)
	if page, err := s.List(f.ctx, r); err != nil || len(page.Credentials) != 1 {
		t.Fatal("valid protocol control", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE webauthn.credentials SET record='{}'::jsonb`); err != nil {
		t.Fatal(err)
	}
	if page, err := s.List(f.ctx, r); err == nil || len(page.Credentials) != 0 || page.Next != "" {
		t.Fatal("corrupt protocol metadata returned a partial inventory")
	}
}

func TestPasskeyInventoryKeysetAndCancellation(t *testing.T) {
	f, s, r := inventoryFixture(t)
	options, err := f.service.RegistrationOptions(f.ctx, f.request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("missing original second ceremony")
	}
	var challenge string
	if err := options.TransferJSON(f.ctx, func(_ context.Context, wire []byte) error {
		var v struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(wire, &v); err != nil {
			return err
		}
		challenge = v.PublicKey.Challenge
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Register(f.ctx, RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge), Label: "Second key"}); err != nil {
		t.Fatal(err)
	}
	r.Limit = 1
	first, err := s.List(f.ctx, r)
	if err != nil || len(first.Credentials) != 1 || first.Next != first.Credentials[0].ReferenceID {
		t.Fatal("first bounded page", err)
	}
	r.After = first.Next
	r.AttemptID, _ = identity.NewCommandID()
	second, err := s.List(f.ctx, r)
	if err != nil || len(second.Credentials) != 1 || second.Next != "" || second.Credentials[0].ReferenceID <= first.Credentials[0].ReferenceID {
		t.Fatal("stable exclusive next page", err)
	}
	cancelled, stop := context.WithCancel(f.ctx)
	stop()
	if page, err := s.List(cancelled, r); !errors.Is(err, context.Canceled) || len(page.Credentials) != 0 {
		t.Fatal("cancelled inventory did not preserve cancellation", err)
	}
}
