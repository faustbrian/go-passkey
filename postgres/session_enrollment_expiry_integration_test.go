//go:build integration

package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	identity "github.com/faustbrian/go-identity"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestSessionEnrollmentRegistrationOptionsRetainOriginalAuthorizationExpiry(t *testing.T) {
	f, s, intent, b := pendingSessionEnrollmentAuthorization(t, true)
	options, expiry, err := s.RegistrationOptionsForDelivery(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
	if err != nil || options.Replayed || options.Receipt.Outcome != identity.CommitOutcomeCommitted || expiry.IsZero() {
		t.Fatal("fresh compound options lost original authorization expiry", err)
	}
	registration, ok := options.Options.Ceremony()
	if !ok || !registration.ExpiresAt.After(expiry) {
		t.Fatal("fixture does not distinguish later registration TTL from original authorization")
	}
	record, err := f.issued.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.owner.protocol.LoadCeremony(f.ctx, webauthn.Lookup{Context: webauthn.CeremonyContext{CommandID: options.CommandID, TenantID: record.TenantID, UserID: record.UserID, ActorID: identity.ActorID(record.UserID), CorrelationID: string(options.CommandID)}, RPID: s.owner.config().Protocol.RelyingParty.ID, CeremonyID: b.CeremonyID})
	if err != nil || !expiry.Equal(original.ExpiresAt) {
		t.Fatal("returned expiry was not genuine original A expiry", err)
	}
	challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
	retry, renewed, err := s.RegistrationOptionsForDelivery(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
	if err != nil || !retry.Replayed || retry.CommandID != options.CommandID || !renewed.IsZero() {
		t.Fatal("metadata-only retry renewed or fabricated authorization validity", err)
	}
	if _, present := retry.Options.Ceremony(); present {
		t.Fatal("retry revealed another registration challenge")
	}
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
	out, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: registration.ID, Response: residentRegistrationResponse(t, key, id, challenge)}))
	if err != nil {
		t.Fatal("explicit original expiry changed genuine registration", err)
	}
	fields, err := out.Bindings()
	if err != nil || fields.Outcome != identity.CommitOutcomeCommitted || fields.Credential == nil {
		t.Fatal("genuine credential did not commit", err)
	}
}
