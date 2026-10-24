//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

// This controls only an authenticator. The real public WebAuthn verifier owns
// signature, COSE, RP/origin, UV, backup and counter decisions in every test.
type algorithmAuthenticator struct {
	es         *ecdsa.PrivateKey
	ed         ed25519.PrivateKey
	id, handle []byte
	count      uint32
}

func newAlgorithmAuthenticator(t *testing.T, algorithm webauthn.Algorithm) *algorithmAuthenticator {
	t.Helper()
	a := &algorithmAuthenticator{id: make([]byte, 32)}
	var err error
	if algorithm == webauthn.EdDSA {
		_, a.ed, err = ed25519.GenerateKey(rand.Reader)
	} else {
		a.es, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(a.id); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *algorithmAuthenticator) registration(t *testing.T, challenge string) []byte {
	t.Helper()
	if a.es != nil {
		return residentRegistrationResponse(t, a.es, a.id, challenge)
	}
	cose := append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, a.ed.Public().(ed25519.PublicKey)...)
	rp := sha256.Sum256([]byte("identity.example"))
	auth := binary.BigEndian.AppendUint32(append(bytes.Clone(rp[:]), 0x45), 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.id)))
	auth = append(append(auth, a.id...), cose...)
	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'}
	att = append(append(att, 0x58, byte(len(auth))), auth...)
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "attestationObject": b64(att)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (a *algorithmAuthenticator) assertion(t *testing.T, challenge string) []byte {
	t.Helper()
	a.count++
	if a.es != nil {
		return enrollmentSignupAssertion(t, a.es, a.id, a.handle, challenge, a.count)
	}
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("identity.example"))
	auth := binary.BigEndian.AppendUint32(append(bytes.Clone(rp[:]), 0x05), a.count)
	hash := sha256.Sum256(client)
	signed := append(bytes.Clone(auth), hash[:]...)
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(ed25519.Sign(a.ed, signed)), "userHandle": b64(a.handle)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

type algorithmJourneyPolicy struct{ user identity.UserID }

func (p algorithmJourneyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if p.user != "" && c.PolicyRevision == 1 && c.Request.Tenant == "01ARZ3NDEKTSV4RRFFQ69G5FAV" && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == authorization.SubjectID(p.user) && (c.Request.Action == "identity.passkey.update" || c.Request.Action == "identity.passkey.delete") && (c.Request.Resource.Type == "identity.user" && c.Request.Resource.ID == authorization.ResourceID(p.user) || c.Request.Resource.Type == "identity.request-admission" && (c.Request.Resource.ID == "identity.passkey.update" || c.Request.Resource.ID == "identity.passkey.delete")) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (enrollmentSignupPolicy{user: p.user}).Decide(ctx, c)
}

type algorithmJourney struct {
	f                             *signinFixture
	manager                       *SessionManagementService
	first, second                 *algorithmAuthenticator
	issued, signup                SigninResult
	credential                    session.Credential
	caller                        authorization.DecisionContext
	firstMetadata, secondMetadata passkey.CredentialMetadata
}

func (j *algorithmJourney) signin(t *testing.T, a *algorithmAuthenticator) SigninResult {
	t.Helper()
	r := discoverableRequest(j.f.request(t, session.BrowserSession))
	options, err := j.f.signin.DiscoverableAuthenticationOptions(j.f.ctx, r)
	if err != nil {
		t.Fatal("genuine discoverable options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("discoverable ceremony absent")
	}
	challenge := signinChallenge(t, j.f.ctx, options.TransferJSON)
	r.CommandID, _ = identity.NewCommandID()
	issued, err := j.f.signin.DiscoverableSignin(j.f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: a.assertion(t, challenge)})
	if err != nil || issued.Session.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual selected authenticator cannot sign in", err)
	}
	return issued
}

func algorithmCredential(t *testing.T, issued *SigninResult) session.Credential {
	t.Helper()
	wire, err := issued.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	issued.Session.Token = token
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func newAlgorithmJourney(t *testing.T, algorithms []webauthn.Algorithm, first, second webauthn.Algorithm) *algorithmJourney {
	t.Helper()
	f, signup := newSignupFixtureAlgorithms(t, algorithms)
	j := &algorithmJourney{f: f, first: newAlgorithmAuthenticator(t, first), second: newAlgorithmAuthenticator(t, second)}
	r := signupBrowserRequest(t, f, signup)
	options, err := signup.RegistrationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("prospective selected signup options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("prospective signup ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	j.first.handle = bytes.Clone(ceremony.Intent.UserHandle)
	j.second.handle = bytes.Clone(ceremony.Intent.UserHandle)
	r.CommandID, _ = identity.NewCommandID()
	created, err := signup.Signup(f.ctx, passkey.SignupCompletion{SignupRequest: r, CeremonyID: ceremony.ID, Response: j.first.registration(t, challenge), Label: "Original selected key"})
	if err != nil {
		t.Fatal("genuine selected passkey-only signup", err)
	}
	j.signup = SigninResult{Session: created.Session, CSRF: created.CSRF}
	record, err := created.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	policy := algorithmJourneyPolicy{user: record.UserID}
	c := f.signin.config()
	c.Protocol.Algorithms, c.Authorization = algorithms, policy
	query := *c.Coordinator.QueryPolicy
	query.Authorization = policy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &query
	f.signin, err = NewSigninService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	j.issued = j.signin(t, j.first)
	j.credential = algorithmCredential(t, &j.issued)
	j.caller = authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "selected-algorithm-journey", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(record.UserID), Kind: authorization.SubjectUser}, Tenant: authorization.TenantID(record.TenantID), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
	config := SessionManagementConfig{Protocol: c.Protocol, Profile: c.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: c.Profile.Audience, Clock: c.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.lookup}}, SessionRepository: c.Repository, OptionsRequests: keyedFixtureConfig(t, f.enrollmentFixture, query), Coordinator: c.Coordinator, Authorization: policy, Clock: c.Clock, Transport: session.CredentialBearer, Risk: f.service.config().Risk, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion}
	j.manager, err = NewSessionManagementService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	// Read the actual signup session before any authenticated management; no
	// seeded identity or directly assembled protocol authority is used here.
	signupCredential := algorithmCredential(t, &j.signup)
	if got, err := j.manager.sessions.Get(f.ctx, session.GetRequest{TenantID: record.TenantID, Credential: signupCredential}); err != nil || !got.Authenticated {
		t.Fatal("new selected signup session unusable", err)
	}
	j.secondMetadata = j.enroll(t, j.second, "Additional selected key", "algorithm", "")
	var version uint64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT reference_id,metadata_version FROM identity_passkey.credentials WHERE credential_id=$1`, j.first.id).Scan(&j.firstMetadata.ReferenceID, &version); err != nil {
		t.Fatal(err)
	}
	j.firstMetadata.Version, j.firstMetadata.Label = version, "Original selected key"
	var passwords, identifiers int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_password.credentials WHERE user_id=$1),(SELECT count(*) FROM identity.identifiers WHERE user_id=$1)`, string(record.UserID)).Scan(&passwords, &identifiers); err != nil || passwords != 0 || identifiers != 0 {
		t.Fatal("selected signup invented recovery", err)
	}
	return j
}

func (j *algorithmJourney) enroll(t *testing.T, authenticator *algorithmAuthenticator, label, keys string, command identity.CommandID) passkey.CredentialMetadata {
	t.Helper()
	f := j.f
	enrollment, err := NewSessionEnrollmentService(f.pool, j.manager.config())
	if err != nil {
		t.Fatal(err)
	}
	intent := passkey.SessionEnrollmentRequestSpec{Credential: j.credential, Caller: j.caller, Label: label, Origin: "https://identity.example", Network: "127.0.0.1"}
	a, err := enrollment.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, keys+"-A")})
	if err != nil {
		t.Fatal("selected current-key UV options", err)
	}
	aCeremony, ok := a.Options.Ceremony()
	if !ok {
		t.Fatal("selected current-key UV absent")
	}
	aChallenge := signinChallenge(t, f.ctx, a.Options.TransferJSON)
	b, err := enrollment.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(passkey.SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, keys+"-B"), CeremonyID: aCeremony.ID, Response: j.first.assertion(t, aChallenge)}))
	if err != nil {
		t.Fatal("genuine selected enrollment authorization", err)
	}
	bCeremony, ok := b.Options.Ceremony()
	if !ok {
		t.Fatal("additional selected registration absent")
	}
	bChallenge := signinChallenge(t, f.ctx, b.Options.TransferJSON)
	intent.Caller = intent.Caller.Clone()
	intent.Caller.Request.Action = "identity.passkey.register-verify"
	if command == "" {
		command, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
	}
	authenticator.handle = bytes.Clone(j.first.handle)
	added, err := enrollment.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: bCeremony.ID, Response: authenticator.registration(t, bChallenge)}))
	if err != nil {
		t.Fatal("genuine additional selected key", err)
	}
	out, err := added.Bindings()
	if err != nil || out.Credential == nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("additional selected metadata absent", err)
	}
	return *out.Credential
}

func TestPasskeyRemovalFindsSelectedRecoveryAfterUnselectedKey(t *testing.T) {
	j := newAlgorithmJourney(t, []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}, webauthn.EdDSA, webauthn.ES256)
	third := newAlgorithmAuthenticator(t, webauthn.EdDSA)
	// A valid original public command fixes the native reference ID before real
	// registration, so the selected recovery key sorts after the ES256 mapping.
	command, err := identity.ParseCommandID("zzzzzzzzzzzzzzzzzzzzzw")
	if err != nil || string(command) <= j.secondMetadata.ReferenceID {
		t.Fatal("ordered native command fixture", err)
	}
	thirdMetadata := j.enroll(t, third, "Later selected recovery key", "third-algorithm", command)
	c := j.manager.config()
	c.Protocol.Algorithms = []webauthn.Algorithm{webauthn.EdDSA}
	s, err := NewSessionDeletionService(j.f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	r := j.deleteRequest(j.firstMetadata, j.credential)
	options, err := s.DeleteOptions(j.f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "later-selected-A")})
	if err != nil {
		t.Fatal("later selected key should admit removal options", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("later-selected removal UV absent")
	}
	challenge := signinChallenge(t, j.f.ctx, options.Options.TransferJSON)
	out, err := s.Delete(j.f.ctx, passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "later-selected-B"), CeremonyID: ceremony.ID, Response: j.first.assertion(t, challenge)}))
	metadata, projection := out.Bindings()
	if err != nil || projection != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("earlier unselected key hid later genuine usable recovery", err)
	}
	config := j.f.signin.config()
	config.Protocol.Algorithms = []webauthn.Algorithm{webauthn.EdDSA}
	j.f.signin, err = NewSigninService(j.f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	issued := j.signin(t, third)
	passkeyJourneyReadInventoryLogout(t, j.f, issued, j.secondMetadata.Label, thirdMetadata.Label)
}

func (j *algorithmJourney) deleteRequest(metadata passkey.CredentialMetadata, credential session.Credential) passkey.SessionDeleteRequestSpec {
	caller := j.caller.Clone()
	caller.Request.Action = "identity.passkey.delete"
	return passkey.SessionDeleteRequestSpec{Credential: credential, Caller: caller, ReferenceID: identity.CredentialID(metadata.ReferenceID), ExpectedVersion: metadata.Version, Origin: "https://identity.example", Network: "127.0.0.1"}
}

func TestPasskeySelectedAlgorithmSignupManagementAndRecovery(t *testing.T) {
	for _, profile := range []struct {
		name          string
		algorithms    []webauthn.Algorithm
		first, second webauthn.Algorithm
	}{
		{"Ed25519", []webauthn.Algorithm{webauthn.EdDSA}, webauthn.EdDSA, webauthn.EdDSA},
		{"mixed-Ed-first", []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}, webauthn.EdDSA, webauthn.ES256},
		{"mixed-ES-first", []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}, webauthn.ES256, webauthn.EdDSA},
	} {
		t.Run(profile.name, func(t *testing.T) {
			j := newAlgorithmJourney(t, profile.algorithms, profile.first, profile.second)
			f := j.f
			caller := j.caller.Clone()
			caller.Request.Action = "identity.passkey.update"
			rename := passkey.SessionUpdateRequest{Credential: j.credential, Caller: caller, ReferenceID: identity.CredentialID(j.firstMetadata.ReferenceID), ExpectedVersion: j.firstMetadata.Version, Name: "Renamed selected key", Origin: "https://identity.example", Network: "127.0.0.1"}
			options, err := j.manager.UpdateOptions(f.ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: rename, IdempotencyKey: optionsKey(t, "algorithm-rename-A")})
			if err != nil {
				t.Fatal("selected rename UV", err)
			}
			ceremony, ok := options.Options.Ceremony()
			if !ok {
				t.Fatal("rename ceremony absent")
			}
			challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
			renamed, err := j.manager.Update(f.ctx, passkey.SessionUpdateCompletion{SessionUpdateRequest: rename, IdempotencyKey: optionsKey(t, "algorithm-rename-B"), CeremonyID: ceremony.ID, Response: j.first.assertion(t, challenge)})
			if err != nil || renamed.Credential == nil || renamed.Credential.Label != rename.Name {
				t.Fatal("selected rename", err)
			}
			j.firstMetadata = *renamed.Credential
			secondSession := j.signin(t, j.second)
			secondCredential := algorithmCredential(t, &secondSession)
			service, err := NewSessionDeletionService(f.pool, j.manager.config())
			if err != nil {
				t.Fatal(err)
			}
			r := j.deleteRequest(j.firstMetadata, j.credential)
			optionsDelete, err := service.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "algorithm-delete-A")})
			if err != nil {
				t.Fatal("selected deletion UV options", err)
			}
			d, ok := optionsDelete.Options.Ceremony()
			if !ok {
				t.Fatal("selected deletion ceremony absent")
			}
			dChallenge := signinChallenge(t, f.ctx, optionsDelete.Options.TransferJSON)
			completion := passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "algorithm-delete-B"), CeremonyID: d.ID, Response: j.first.assertion(t, dChallenge)})
			removed, err := service.Delete(f.ctx, completion)
			metadata, projection := removed.Bindings()
			if err != nil || projection != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.Replayed {
				t.Fatal("selected removal", err)
			}
			signupCredential, _ := session.NewCredential(session.CredentialBearer, j.signup.Session.Token)
			for _, credential := range []session.Credential{j.credential, secondCredential, signupCredential} {
				got, err := j.manager.sessions.Get(f.ctx, session.GetRequest{TenantID: j.manager.config().Protocol.TenantID, Credential: credential})
				if err == nil && got.Authenticated {
					t.Fatal("old selected session retained removed generation")
				}
			}
			if _, err := service.Delete(f.ctx, completion); err == nil {
				t.Fatal("invalidated original session replayed removal")
			}
			removedRequest := discoverableRequest(f.request(t, session.BrowserSession))
			removedOptions, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, removedRequest)
			if err != nil {
				t.Fatal("non-enumerating options after removal", err)
			}
			removedCeremony, ok := removedOptions.Ceremony()
			if !ok {
				t.Fatal("fresh removed-key challenge absent")
			}
			removedChallenge := signinChallenge(t, f.ctx, removedOptions.TransferJSON)
			removedRequest.CommandID, _ = identity.NewCommandID()
			if result, err := f.signin.DiscoverableSignin(f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: removedRequest, CeremonyID: removedCeremony.ID, Response: j.first.assertion(t, removedChallenge)}); err == nil || result.Session.Token != (session.Token{}) {
				t.Fatal("removed authenticator issued fresh authentication")
			}
			next := j.signin(t, j.second)
			current := algorithmCredential(t, &next)
			recovery := r
			recovery.Credential = current
			binding := metadata.Receipt.Binding
			query := identity.RecoveryQuery{CommandID: metadata.CommandID, TenantID: binding.TenantID, UserID: binding.UserID, ActorID: binding.ActorID, ActorKind: binding.ActorKind, OperationID: binding.OperationID, RecordID: binding.RecordID}
			recovered, err := service.RecoverDelete(f.ctx, passkey.NewSessionDeleteRequest(recovery), query)
			ack, projection := recovered.Bindings()
			if err != nil || projection != nil || !ack.Replayed || ack.CommandID != metadata.CommandID || ack.Outcome != identity.CommitOutcomeCommitted || ack.Receipt.Validate() != nil {
				t.Fatal("surviving selected session lost original removal metadata", err)
			}
			last := j.deleteRequest(j.secondMetadata, current)
			if _, err := service.DeleteOptions(f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(last), IdempotencyKey: optionsKey(t, "algorithm-last")}); err == nil {
				t.Fatal("last selected usable key admitted removal")
			}
			passkeyJourneyReadInventoryLogout(t, f, next, "Additional selected key")
		})
	}
}

func TestPasskeyRemovalCannotCountAnUnselectedAlgorithmAsRecovery(t *testing.T) {
	for _, profile := range []struct {
		name          string
		selected      []webauthn.Algorithm
		first, second webauthn.Algorithm
	}{
		{"Ed25519-cannot-count-ES256", []webauthn.Algorithm{webauthn.EdDSA}, webauthn.EdDSA, webauthn.ES256},
		{"default-ES256-cannot-count-Ed25519", nil, webauthn.ES256, webauthn.EdDSA},
		{"explicit-ES256-cannot-count-Ed25519", []webauthn.Algorithm{webauthn.ES256}, webauthn.ES256, webauthn.EdDSA},
	} {
		t.Run(profile.name, func(t *testing.T) {
			j := newAlgorithmJourney(t, []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}, profile.first, profile.second)
			c := j.manager.config()
			c.Protocol.Algorithms = profile.selected
			s, err := NewSessionDeletionService(j.f.pool, c)
			if err != nil {
				t.Fatal(err)
			}
			r := j.deleteRequest(j.firstMetadata, j.credential)
			options, err := s.DeleteOptions(j.f.ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "unselected-recovery-A")})
			ceremonyID := ""
			if err == nil {
				ceremony, ok := options.Options.Ceremony()
				if !ok {
					t.Fatal("selected removal UV absent")
				}
				ceremonyID = ceremony.ID
				challenge := signinChallenge(t, j.f.ctx, options.Options.TransferJSON)
				if _, err := s.Delete(j.f.ctx, passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: passkey.NewSessionDeleteRequest(r), IdempotencyKey: optionsKey(t, "unselected-recovery-B"), CeremonyID: ceremony.ID, Response: j.first.assertion(t, challenge)})); err == nil {
					t.Fatal("an unselected stored key permitted removal of the last usable selected key")
				}
			} else if !errors.As(err, new(identity.ForbiddenError)) {
				t.Fatal("unselected recovery did not produce an eligibility denial", err)
			}
			var active, consumed, events int
			if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT (SELECT count(*) FROM identity_passkey.credentials WHERE state='active'),(SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=$1 AND consumed_by IS NOT NULL),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential')`, ceremonyID).Scan(&active, &consumed, &events); err != nil || active != 2 || consumed != 0 || events != 0 {
				t.Fatal("unselected recovery denial committed partial effects", err)
			}
			if got, err := j.manager.sessions.Get(j.f.ctx, session.GetRequest{TenantID: c.Protocol.TenantID, Credential: j.credential}); err != nil || !got.Authenticated {
				t.Fatal("unselected recovery denial revoked original authority", err)
			}
		})
	}
}

func TestPasskeyEnrollmentWithPasswordProofSupportsEd25519(t *testing.T) {
	f := newEnrollmentFixture(t)
	c := f.service.config()
	c.Protocol.Algorithms = []webauthn.Algorithm{webauthn.EdDSA}
	var err error
	f.service, err = NewEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	options, err := f.service.RegistrationOptions(f.ctx, f.request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("genuine Ed25519 password-proof registration absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	a := newAlgorithmAuthenticator(t, webauthn.EdDSA)
	a.handle = bytes.Clone(ceremony.Intent.UserHandle)
	if _, err := f.service.Register(f.ctx, RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: a.registration(t, challenge), Label: "Signin key"}); err != nil {
		t.Fatal("genuine password-proof Ed25519 enrollment", err)
	}
	login := newSigninFixtureForEnrolledAccountProfile(t, f, true)
	j := &algorithmJourney{f: login}
	issued := j.signin(t, a)
	passkeyJourneyReadInventoryLogout(t, login, issued)
}

func TestPasskeySessionRenameRetainsExactOriginalAlgorithmProfile(t *testing.T) {
	j := newAlgorithmJourney(t, []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}, webauthn.EdDSA, webauthn.ES256)
	caller := j.caller.Clone()
	caller.Request.Action = "identity.passkey.update"
	r := passkey.SessionUpdateRequest{Credential: j.credential, Caller: caller, ReferenceID: identity.CredentialID(j.firstMetadata.ReferenceID), ExpectedVersion: j.firstMetadata.Version, Name: "Original profile rename", Origin: "https://identity.example", Network: "127.0.0.1"}
	options, err := j.manager.UpdateOptions(j.f.ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: r, IdempotencyKey: optionsKey(t, "retained-profile-A")})
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("original ordered-profile ceremony absent")
	}
	challenge := signinChallenge(t, j.f.ctx, options.Options.TransferJSON)
	response := j.first.assertion(t, challenge)
	c := j.manager.config()
	c.Protocol.Algorithms = []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}
	changed, err := NewSessionManagementService(j.f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Update(j.f.ctx, passkey.SessionUpdateCompletion{SessionUpdateRequest: r, IdempotencyKey: optionsKey(t, "retained-profile-changed"), CeremonyID: ceremony.ID, Response: response}); err == nil {
		t.Fatal("changed algorithm order adopted original ceremony")
	}
	if result, err := j.manager.Update(j.f.ctx, passkey.SessionUpdateCompletion{SessionUpdateRequest: r, IdempotencyKey: optionsKey(t, "retained-profile-original"), CeremonyID: ceremony.ID, Response: response}); err != nil || result.Credential == nil || result.Credential.Label != r.Name {
		t.Fatal("changed-profile denial consumed original selected authority", err)
	}
}
