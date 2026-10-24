//go:build integration

package postgres

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func pendingSessionEnrollmentAuthorization(t *testing.T, cookie bool, labels ...string) (*sessionManagementTestFixture, *SessionEnrollmentService, passkey.SessionEnrollmentRequestSpec, passkey.SessionEnrollmentAuthorizationSpec) {
	t.Helper()
	f := newSessionManagementTestFixture(t)
	c := f.manager.config()
	caller := f.request.Caller.Clone()
	caller.Request.Action = "identity.passkey.register-options"
	intent := passkey.SessionEnrollmentRequestSpec{Credential: f.request.Credential, Caller: caller, Label: "Additional resident key", Origin: f.request.Origin, Network: f.request.Network}
	if len(labels) > 1 {
		t.Fatal("invalid label fixture")
	}
	if len(labels) == 1 {
		intent.Label = labels[0]
	}
	if cookie {
		c.Transport, c.CSRFKeys = session.CredentialCookie, []session.CSRFKey{f.csrf}
		var err error
		intent.Credential, err = session.NewCredential(session.CredentialCookie, f.issued.Session.Token)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := f.issued.CSRF.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		intent.CSRFToken, err = session.ParseCSRFToken(wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewSessionEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	r := passkey.NewSessionEnrollmentRequest(intent)
	options, err := s.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: r, IdempotencyKey: optionsKey(t, "enrollment-A")})
	if err != nil {
		t.Fatal("original genuine enrollment assertion options", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("original assertion absent")
	}
	challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
	b := passkey.SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: r, IdempotencyKey: optionsKey(t, "enrollment-B"), CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 2)}
	return f, s, intent, b
}

func pendingSessionEnrollmentCompletion(t *testing.T, cookie bool, labels ...string) (*sessionManagementTestFixture, *SessionEnrollmentService, passkey.SessionEnrollmentRequestSpec, passkey.SessionEnrollmentCompletionSpec) {
	t.Helper()
	f, s, intent, b := pendingSessionEnrollmentAuthorization(t, cookie, labels...)
	options, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b))
	if err != nil {
		t.Fatal("genuine compound enrollment authorization", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("original registration absent")
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
	c := passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge)}
	return f, s, intent, c
}

func assertSessionEnrollmentUnchanged(t *testing.T, f *sessionManagementTestFixture) {
	t.Helper()
	var protocol, refs, mappings, lifecycle int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey'),(SELECT count(*) FROM identity_passkey.credentials),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.create_credential')`).Scan(&protocol, &refs, &mappings, &lifecycle); err != nil || protocol != 1 || refs != 1 || mappings != 1 || lifecycle != 1 {
		t.Fatal("denied additional enrollment leaked durable effects", err)
	}
}

func TestPasskeySessionEnrollmentRejectsChangedAuthorizationIntent(t *testing.T) {
	for _, mode := range []string{"label", "network", "origin", "actor", "tenant", "resource", "action", "session", "csrf", "ceremony", "signature", "uv", "counter", "A-key-as-B"} {
		t.Run(mode, func(t *testing.T) {
			f, s, intent, original := pendingSessionEnrollmentAuthorization(t, false)
			r := original
			r.IdempotencyKey = optionsKey(t, "substituted-B-"+mode)
			intent.Caller = intent.Caller.Clone()
			switch mode {
			case "label":
				intent.Label = "Changed label"
			case "network":
				intent.Network = "192.0.2.1"
			case "origin":
				intent.Origin = "https://foreign.example"
			case "actor":
				intent.Caller.Request.Subject.ID = "foreign"
			case "tenant":
				intent.Caller.Request.Tenant = "foreign"
			case "resource":
				intent.Caller.Request.Resource.ID = "foreign"
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
			case "uv", "counter":
				count := uint32(1)
				if mode == "uv" {
					f.assertionFlags, count = 0x01, 2
				}
				r.Response = f.assertion(t, assertionResponseChallenge(t, original.Response), count)
			case "A-key-as-B":
				r.IdempotencyKey = optionsKey(t, "enrollment-A")
			}
			r.SessionEnrollmentRequest = passkey.NewSessionEnrollmentRequest(intent)
			out, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(r))
			if _, revealed := out.Options.Ceremony(); err == nil || revealed {
				t.Fatal("changed authority or invalid assertion disclosed registration", err)
			}
			assertSessionEnrollmentUnchanged(t, f)
			if out, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(original)); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("rejected assertion consumed genuine original", err)
			}
		})
	}
}

func TestPasskeySessionEnrollmentRejectsChangedCompletionBeforeAndAfterCommit(t *testing.T) {
	for _, mode := range []string{"label", "network", "signature", "command", "ceremony"} {
		t.Run(mode, func(t *testing.T) {
			f, s, intent, original := pendingSessionEnrollmentCompletion(t, false)
			changed := original
			switch mode {
			case "label":
				intent.Label = "Changed authorized intent"
			case "network":
				intent.Network = "192.0.2.1"
			case "signature":
				changed.Response = bytes.Replace(changed.Response, []byte(`"attestationObject":"`), []byte(`"attestationObject":"A`), 1)
			case "command":
				changed.CommandID = identity.CommandID(original.CeremonyID)
			case "ceremony":
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				changed.CeremonyID = string(id)
			}
			changed.SessionEnrollmentRequest = passkey.NewSessionEnrollmentRequest(intent)
			if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(changed)); err == nil {
				t.Fatal("changed completion enrolled credential")
			}
			assertSessionEnrollmentUnchanged(t, f)
			out, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(original))
			if err != nil {
				t.Fatal("denial consumed original authorized registration", err)
			}
			fields, err := out.Bindings()
			if err != nil || fields.Outcome != identity.CommitOutcomeCommitted || fields.Credential == nil {
				t.Fatal("original authorized credential not committed", err)
			}
			if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(changed)); err == nil {
				t.Fatal("committed command accepted changed original intent")
			}
		})
	}
}

// The initial fixture's first key was genuinely enrolled and signed in. All
// additional enrollment phases below use that actual passkey session and UV,
// never the fixture's password reauthentication source or a fabricated proof.
func TestPasskeySessionEnrollsAdditionalCredentialWithoutPassword(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	service, err := NewSessionEnrollmentService(f.pool, SessionEnrollmentConfig(f.manager.config()))
	if err != nil {
		t.Fatal("native session enrollment construction", err)
	}
	caller := f.request.Caller.Clone()
	caller.Request.Action = "identity.passkey.register-options"
	intent := passkey.SessionEnrollmentRequestSpec{Credential: f.request.Credential, Caller: caller, Label: "Additional resident key", Origin: f.request.Origin, Network: f.request.Network}
	request := passkey.NewSessionEnrollmentRequest(intent)
	a := passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: request, IdempotencyKey: optionsKey(t, "additional-assertion-options")}
	assertion, err := service.EnrollmentAssertionOptions(f.ctx, a)
	if err != nil || assertion.Replayed || assertion.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original enrollment assertion options", err)
	}
	assertionCeremony, ok := assertion.Options.Ceremony()
	if !ok {
		t.Fatal("assertion options withheld")
	}
	assertionChallenge := signinChallenge(t, f.ctx, assertion.Options.TransferJSON)
	aRetry, err := service.EnrollmentAssertionOptions(f.ctx, a)
	if _, disclosed := aRetry.Options.Ceremony(); err != nil || !aRetry.Replayed || aRetry.CommandID != assertion.CommandID || disclosed {
		t.Fatal("assertion retry was not original metadata only", err)
	}
	b := passkey.NewSessionEnrollmentAuthorization(passkey.SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: request, IdempotencyKey: optionsKey(t, "additional-registration-options"), CeremonyID: assertionCeremony.ID, Response: f.assertion(t, assertionChallenge, 2)})
	registration, err := service.RegistrationOptions(f.ctx, b)
	if err != nil || registration.Replayed || registration.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine assertion did not atomically authorize registration", err)
	}
	registrationCeremony, ok := registration.Options.Ceremony()
	if !ok {
		t.Fatal("registration options withheld")
	}
	registrationChallenge := signinChallenge(t, f.ctx, registration.Options.TransferJSON)
	bRetry, err := service.RegistrationOptions(f.ctx, b)
	if _, disclosed := bRetry.Options.Ceremony(); err != nil || !bRetry.Replayed || bRetry.CommandID != registration.CommandID || disclosed {
		t.Fatal("authorization retry repeated proof or options", err)
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
	intent.Caller = caller.Clone()
	intent.Caller.Request.Action = "identity.passkey.register-verify"
	c := passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: registrationCeremony.ID, Response: residentRegistrationResponse(t, key, id, registrationChallenge)})
	result, err := service.Register(f.ctx, c)
	if err != nil {
		t.Fatal("genuine additional enrollment", err)
	}
	complete, err := result.Bindings()
	if err != nil || complete.Outcome != identity.CommitOutcomeCommitted || complete.Replayed || complete.Credential == nil || complete.Credential.Label != intent.Label || complete.Credential.Version != 1 {
		t.Fatal("enrollment did not return committed safe metadata", err)
	}
	retryResult, err := service.Register(f.ctx, c)
	if err != nil {
		t.Fatal("original completion recovery", err)
	}
	retry, err := retryResult.Bindings()
	if err != nil || !retry.Replayed || retry.CommandID != command || retry.Outcome != identity.CommitOutcomeCommitted || retry.Credential != nil {
		t.Fatal("completion replay repeated credential or lost outcome", err)
	}
	f.listing.AttemptID, _ = identity.NewCommandID()
	page, err := f.inventory.List(f.ctx, f.listing)
	if err != nil || len(page.Credentials) != 2 {
		t.Fatal("original session cannot list both enrolled credentials", err)
	}
	var protocol, references, mappings, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey'),(SELECT count(*) FROM identity_passkey.credentials),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.create_credential')`).Scan(&protocol, &references, &mappings, &effects); err != nil || protocol != 2 || references != 2 || mappings != 2 || effects != 2 {
		t.Fatal("native protocol/kernel/mapping/lifecycle did not commit once", err)
	}
	passkeyJourneyReadInventoryLogout(t, f.signinFixture, f.issued, "Signin key", intent.Label)
	for _, credential := range []struct {
		name  string
		key   *ecdsa.PrivateKey
		id    []byte
		count uint32
	}{{"original", f.key, f.id, 3}, {"additional", key, id, 1}} {
		t.Run(credential.name, func(t *testing.T) {
			signer := *f.signinFixture
			signer.key, signer.id = credential.key, credential.id
			r := signer.request(t, session.BrowserSession)
			options, err := signer.signin.AuthenticationOptions(f.ctx, r)
			if err != nil {
				t.Fatal("fresh credential signin options", err)
			}
			ceremony, ok := options.Ceremony()
			if !ok {
				t.Fatal("fresh credential signin options absent")
			}
			challenge := signinChallenge(t, f.ctx, options.TransferJSON)
			r.CommandID, _ = identity.NewCommandID()
			issued, err := signer.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: signer.assertion(t, challenge, credential.count)})
			if err != nil {
				t.Fatal("either resident key must sign in", err)
			}
			passkeyJourneyReadInventoryLogout(t, &signer, issued, "Signin key", intent.Label)
		})
	}
	// Retrying under a revoked source cannot resurrect its old authority.
	if _, err := service.Register(f.ctx, c); err == nil {
		t.Fatal("revoked source session recovered enrollment")
	}
}
