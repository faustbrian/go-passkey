//go:build integration

package postgres

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func pendingSessionDeletion(t *testing.T, cookie bool) (*sessionManagementTestFixture, *SessionDeletionService, passkey.SessionDeleteRequestSpec, passkey.SessionDeleteCompletionSpec) {
	t.Helper()
	f, s, intent, completion, _ := pendingSessionDeletionWithRecovery(t, cookie)
	return f, s, intent, completion
}

func pendingSessionDeletionWithRecovery(t *testing.T, cookie bool) (*sessionManagementTestFixture, *SessionDeletionService, passkey.SessionDeleteRequestSpec, passkey.SessionDeleteCompletionSpec, *signinFixture) {
	t.Helper()
	f, key, id, _ := sessionDeletionTwoKeys(t)
	c := f.manager.config()
	caller := f.request.Caller.Clone()
	caller.Request.Action = "identity.passkey.delete"
	r := passkey.SessionDeleteRequestSpec{Credential: f.request.Credential, Caller: caller, ReferenceID: f.request.ReferenceID, ExpectedVersion: f.request.ExpectedVersion, Origin: f.request.Origin, Network: f.request.Network}
	if cookie {
		c.Transport, c.CSRFKeys = session.CredentialCookie, []session.CSRFKey{f.csrf}
		var err error
		r.Credential, err = session.NewCredential(session.CredentialCookie, f.issued.Session.Token)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := f.issued.CSRF.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		r.CSRFToken, err = session.ParseCSRFToken(wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewSessionDeletionService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	options, err := s.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "session-delete-A")})
	if err != nil {
		t.Fatal("original deletion assertion options", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("genuine deletion ceremony withheld")
	}
	challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
	completion := passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "session-delete-B"), CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 3)}
	remaining := *f.signinFixture
	remaining.key, remaining.id = key, id
	return f, s, r, completion, &remaining
}

func assertNoSessionDeletionEffect(t *testing.T, f *sessionManagementTestFixture, ceremony string) {
	t.Helper()
	var mutations, events, succeeded, consumed int
	var protocolVersion string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.delete' AND after_credential IS NOT NULL),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.remove_credential' AND outcome=$3),(SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=$1 AND consumed_by IS NOT NULL),(SELECT version::text FROM webauthn.credentials WHERE credential_id=$2)`, ceremony, f.id, int64(audit.OutcomeSucceeded)).Scan(&mutations, &events, &succeeded, &consumed, &protocolVersion); err != nil || mutations != 0 || events != 0 || succeeded != 0 || consumed != 0 || protocolVersion != "3" {
		t.Fatal("denied removal consumed original UV or committed partial protocol/effects", err)
	}
}

func TestPasskeySessionRemovalRejectsChangedIntentAndCustody(t *testing.T) {
	for _, mode := range []string{"target", "version", "origin", "network", "actor", "tenant", "resource", "action", "session", "csrf", "ceremony", "signature", "response", "options-key"} {
		t.Run(mode, func(t *testing.T) {
			f, s, intent, original := pendingSessionDeletion(t, false)
			r := original
			r.IdempotencyKey = optionsKey(t, "changed-removal-"+mode)
			intent.Caller = intent.Caller.Clone()
			switch mode {
			case "target":
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT reference_id FROM identity_passkey.credentials WHERE reference_id<>$1`, string(intent.ReferenceID)).Scan(&intent.ReferenceID); err != nil {
					t.Fatal(err)
				}
			case "version":
				intent.ExpectedVersion++
			case "origin":
				intent.Origin = "https://foreign.example"
			case "network":
				intent.Network = "192.0.2.99"
			case "actor":
				intent.Caller.Request.Subject.ID = "another-user"
			case "tenant":
				intent.Caller.Request.Tenant = "another-tenant"
			case "resource":
				intent.Caller.Request.Resource.ID = "another-user"
			case "action":
				intent.Caller.Request.Action = "identity.passkey.update"
			case "session":
				token, err := session.NewToken(32)
				if err != nil {
					t.Fatal(err)
				}
				intent.Credential, err = session.NewCredential(session.CredentialBearer, token)
				if err != nil {
					t.Fatal(err)
				}
			case "csrf":
				var err error
				intent.CSRFToken, err = session.NewCSRFToken()
				if err != nil {
					t.Fatal(err)
				}
			case "ceremony":
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				r.CeremonyID = string(id)
			case "signature":
				r.Response = bytes.Replace(r.Response, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			case "response":
				r.Response = nil
			case "options-key":
				r.IdempotencyKey = optionsKey(t, "session-delete-A")
			}
			r.SessionDeleteRequest = passkey.NewSessionDeleteRequest(intent)
			if _, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(r)); err == nil {
				t.Fatal("changed original intention or custody removed a key")
			}
			assertNoSessionDeletionEffect(t, f, original.CeremonyID)
			out, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(original))
			metadata, projected := out.Bindings()
			if err != nil || projected != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("denial consumed original valid action", err)
			}
		})
	}
}

func TestPasskeySessionRemovalCookieRequiresOriginalCSRF(t *testing.T) {
	f, s, intent, original := pendingSessionDeletion(t, true)
	for _, absent := range []bool{true, false} {
		bad := intent
		bad.CSRFToken = session.CSRFToken{}
		if !absent {
			var err error
			bad.CSRFToken, err = session.NewCSRFToken()
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(bad), IdempotencyKey: optionsKey(t, "invalid-cookie-options")}); err == nil {
			t.Fatal("missing/foreign synchronizer disclosed options")
		}
		r := original
		r.SessionDeleteRequest = passkey.NewSessionDeleteRequest(bad)
		if _, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(r)); err == nil {
			t.Fatal("missing/foreign synchronizer removed a credential")
		}
		assertNoSessionDeletionEffect(t, f, original.CeremonyID)
	}
	out, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(original))
	metadata, projected := out.Bindings()
	if err != nil || projected != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original genuine cookie/CSRF UV denied", err)
	}
}

func TestPasskeySessionRemovalRejectsWithdrawnAuthorityAndUnusableRecovery(t *testing.T) {
	for _, mode := range []string{"session", "user", "target-kernel", "target-mapping", "factor", "passkey-generation", "policy", "context", "expired", "uv", "counter", "remaining-kernel", "remaining-mapping", "remaining-erased", "remaining-provenance"} {
		t.Run(mode, func(t *testing.T) {
			f, s, intent, r := pendingSessionDeletion(t, false)
			sql := ""
			switch mode {
			case "session":
				sql = `UPDATE session_store.sessions SET state='revoked'`
			case "user":
				sql = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "target-kernel":
				sql = `UPDATE identity.credential_references SET enabled=false WHERE credential_id=$1`
			case "target-mapping":
				sql = `UPDATE identity_passkey.credentials SET state='revoked' WHERE reference_id=$1`
			case "factor":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "passkey-generation":
				sql = `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`
			case "policy":
				sql = `UPDATE authorization_subject_authorities SET version=version+1`
			case "context":
				sql = `DELETE FROM identity_passkey.signin_contexts`
			case "expired":
				sql = `WITH expired AS(SELECT date_trunc('microseconds',clock_timestamp()-interval '1 second') AS t) UPDATE webauthn.ceremonies SET expires_at=expired.t,record=jsonb_set(record,'{ExpiresAt}',to_jsonb(expired.t)) FROM expired WHERE ceremony_id=$1`
			case "uv", "counter":
				count := uint32(1)
				if mode == "uv" {
					f.assertionFlags, count = 0x01, 3
				}
				r.Response = f.assertion(t, assertionResponseChallenge(t, r.Response), count)
			case "remaining-kernel":
				sql = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey' AND credential_id<>$1`
			case "remaining-mapping":
				sql = `UPDATE identity_passkey.credentials SET state='revoked' WHERE reference_id<>$1`
			case "remaining-erased":
				sql = `UPDATE webauthn.credentials SET record=jsonb_set(record,'{PublicKey}','null'::jsonb) WHERE credential_id<>(SELECT credential_id FROM identity_passkey.credentials WHERE reference_id=$1)`
			case "remaining-provenance":
				sql = `DELETE FROM webauthn.effects WHERE purpose='identity.passkey.register-verify' AND after_credential->>'ID' IN(SELECT encode(credential_id,'base64') FROM identity_passkey.credentials WHERE reference_id<>$1)`
			}
			if sql != "" {
				var args []any
				if bytes.Contains([]byte(sql), []byte("$1")) {
					args = []any{string(intent.ReferenceID)}
					if mode == "expired" {
						args[0] = r.CeremonyID
					}
				}
				if _, err := f.pool.Raw().Exec(f.ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Delete(f.ctx, passkey.NewSessionDeleteCompletion(r)); err == nil {
				t.Fatal("withdrawn current authority or unusable recovery removed a key")
			}
			assertNoSessionDeletionEffect(t, f, r.CeremonyID)
		})
	}
}
