//go:build integration

package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestIdentifiedPasskeySigninSurvivesGenuine101stEnrollment(t *testing.T) {
	f := newSigninFixture(t)
	originalKey, originalID := f.key, f.id
	// Additional pre-existing mapping state is explicit fixture input, not
	// evidence of earlier registration or usable keys. Both assertions below
	// use only credentials genuinely enrolled through the public owners.
	for range 99 {
		reference, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW',$1,$2,'passkey',1,true)`, string(reference), int(identity.CredentialPasskey)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_passkey.credentials(rp_namespace,tenant_id,user_id,reference_id,credential_id,version,state,created_at) VALUES($1,'01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW',$2,$3,1,'active',clock_timestamp())`, f.signin.config().Profile.RPNamespace, string(reference), id); err != nil {
			t.Fatal(err)
		}
	}
	options, err := f.service.RegistrationOptions(f.ctx, f.enrollmentFixture.request(t, false))
	if err != nil {
		t.Fatal("options with 100 existing exclusions", err)
	}
	ceremony, _ := options.Ceremony()
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Register(f.ctx, RegistrationCompletion{RegistrationRequest: f.enrollmentFixture.request(t, true), CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge), Label: "Key 101"}); err != nil {
		t.Fatal("genuine 101st enrollment", err)
	}
	var active int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_passkey.credentials WHERE state='active'`).Scan(&active); err != nil || active != 101 {
		t.Fatal("101st enrollment not committed", err, active)
	}
	for _, which := range []string{"original", "new"} {
		t.Run(which, func(t *testing.T) {
			f.key, f.id = originalKey, originalID
			if which == "new" {
				f.key, f.id = key, id
			}
			completion, _ := f.pending(t)
			result, err := f.signin.Signin(f.ctx, completion)
			if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("successful enrollment disabled a genuinely enrolled passkey", err)
			}
		})
	}
}
