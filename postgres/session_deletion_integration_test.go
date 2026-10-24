//go:build integration

package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// All credentials and sessions below come from actual native registration,
// assertion and issuance. Controlled authenticators replace only browser crypto.
func sessionDeletionTwoKeys(t *testing.T) (*sessionManagementTestFixture, *ecdsa.PrivateKey, []byte, passkey.CredentialMetadata) {
	t.Helper()
	f, enrollment, intent, authorization := pendingSessionEnrollmentAuthorization(t, false)
	options, err := enrollment.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(authorization))
	if err != nil {
		t.Fatal("genuine authorization for independent recovery key", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("independent registration ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	intent.Caller = intent.Caller.Clone()
	intent.Caller.Request.Action = "identity.passkey.register-verify"
	registered, err := enrollment.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge)}))
	if err != nil {
		t.Fatal("independent recovery key registration", err)
	}
	result, err := registered.Bindings()
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Credential == nil {
		t.Fatal("independent key not committed", err)
	}
	return f, key, id, *result.Credential
}

func sessionDeletionSignin(t *testing.T, f *signinFixture, count uint32) SigninResult {
	t.Helper()
	r := f.request(t, session.BrowserSession)
	options, err := f.signin.AuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("remaining-key signin options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("remaining-key signin options absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, count)})
	if err != nil {
		t.Fatal("remaining independently usable key no longer signs in", err)
	}
	return issued
}

func TestPasskeySessionRemovalPreservesIndependentKeyAndRevokesSessions(t *testing.T) {
	for _, self := range []bool{true, false} {
		t.Run(map[bool]string{true: "authenticating-target", false: "sibling-target"}[self], func(t *testing.T) {
			f, key, id, additional := sessionDeletionTwoKeys(t)
			sibling := *f.signinFixture
			sibling.key, sibling.id = key, id
			second := sessionDeletionSignin(t, &sibling, 1)
			wire, err := second.Session.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			token, err := session.ParseToken(wire)
			if err != nil {
				t.Fatal(err)
			}
			secondCredential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewSessionDeletionService(f.pool, SessionDeletionConfig(f.manager.config()))
			if err != nil {
				t.Fatal("native current-session removal", err)
			}
			caller := f.request.Caller.Clone()
			caller.Request.Action = "identity.passkey.delete"
			r := passkey.SessionDeleteRequestSpec{Credential: f.request.Credential, Caller: caller, ReferenceID: f.request.ReferenceID, ExpectedVersion: f.request.ExpectedVersion, Origin: f.request.Origin, Network: f.request.Network}
			remaining, remainingCount, label := &sibling, uint32(2), additional.Label
			if !self {
				r.ReferenceID, r.ExpectedVersion = identity.CredentialID(additional.ReferenceID), additional.Version
				remaining, remainingCount, label = f.signinFixture, 4, "Signin key"
			}
			request := passkey.NewSessionDeleteRequest(r)
			options, err := service.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: request, IdempotencyKey: optionsKey(t, "session-delete-options")})
			if err != nil {
				t.Fatal("original removal UV options", err)
			}
			ceremony, ok := options.Options.Ceremony()
			if !ok {
				t.Fatal("genuine removal ceremony withheld")
			}
			challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
			completion := passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: request, IdempotencyKey: optionsKey(t, "session-delete-complete"), CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 3)})
			result, err := service.Delete(f.ctx, completion)
			if err != nil {
				t.Fatal("genuine action-bound removal", err)
			}
			out, err := result.Bindings()
			if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed {
				t.Fatal("removal acknowledgement lost original outcome", err)
			}
			for _, credential := range []session.Credential{r.Credential, secondCredential} {
				got, err := f.manager.sessions.Get(f.ctx, session.GetRequest{TenantID: f.manager.config().Protocol.TenantID, Credential: credential})
				if err == nil && got.Authenticated {
					t.Fatal("affected original passkey session remains usable")
				}
			}
			if _, err := service.Delete(f.ctx, completion); err == nil {
				t.Fatal("invalidated source session obtained a new acknowledgement")
			}
			var erased, disabled, revoked, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.credentials WHERE record->'PublicKey'='null'::jsonb),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey' AND NOT enabled),(SELECT count(*) FROM identity_passkey.credentials WHERE state='revoked'),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential')`).Scan(&erased, &disabled, &revoked, &events); err != nil || erased != 1 || disabled != 1 || revoked != 1 || events != 1 {
				t.Fatal("removal lost atomic protocol/reference/mapping/lifecycle effects", err)
			}
			next := sessionDeletionSignin(t, remaining, remainingCount)
			nextWire, err := next.Session.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			nextToken, err := session.ParseToken(nextWire)
			if err != nil {
				t.Fatal(err)
			}
			next.Session.Token = nextToken
			current, err := session.NewCredential(session.CredentialBearer, nextToken)
			if err != nil {
				t.Fatal(err)
			}
			recovery := r
			recovery.Credential = current
			b := out.Receipt.Binding
			query := identity.RecoveryQuery{CommandID: out.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			recovered, err := service.RecoverDelete(f.ctx, passkey.NewSessionDeleteRequest(recovery), query)
			metadata, projection := recovered.Bindings()
			if err != nil || projection != nil || metadata.CommandID != out.CommandID || !metadata.Replayed || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.Receipt.Validate() != nil {
				t.Fatal("new genuine remaining-key session cannot recover original metadata", err)
			}
			if _, err := service.RecoverDelete(f.ctx, request, query); err == nil {
				t.Fatal("revoked original source obtained standalone recovery metadata")
			}
			passkeyJourneyReadInventoryLogout(t, remaining, next, label)
		})
	}
}

func TestPasskeySessionRemovalDeniesLastUsableKey(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	s, err := NewSessionDeletionService(f.pool, SessionDeletionConfig(f.manager.config()))
	if err != nil {
		t.Fatal(err)
	}
	caller := f.request.Caller.Clone()
	caller.Request.Action = "identity.passkey.delete"
	r := passkey.NewSessionDeleteRequest(passkey.SessionDeleteRequestSpec{Credential: f.request.Credential, Caller: caller, ReferenceID: f.request.ReferenceID, ExpectedVersion: f.request.ExpectedVersion, Origin: f.request.Origin, Network: f.request.Network})
	options, err := s.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: r, IdempotencyKey: optionsKey(t, "last-key-options")})
	if err != nil {
		// Early recovery denial is permitted; it must preserve all authority.
		passkeyJourneyReadInventoryLogout(t, f.signinFixture, f.issued, "Signin key")
		return
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("last-key options omitted without denial")
	}
	challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
	completion := passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: r, IdempotencyKey: optionsKey(t, "last-key-complete"), CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 2)})
	if out, err := s.Delete(f.ctx, completion); err == nil {
		metadata, _ := out.Bindings()
		if metadata.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("last usable key was removed")
		}
		t.Fatal("last-key denial returned no error")
	}
	passkeyJourneyReadInventoryLogout(t, f.signinFixture, f.issued, "Signin key")
}
