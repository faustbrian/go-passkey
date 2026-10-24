//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// This is the documented application policy seam, not a domain store or proof.
// It grants only the genuinely created user's selected self-user operations.
type enrollmentSignupPolicy struct{ user identity.UserID }

func (p enrollmentSignupPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	self := c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == authorization.SubjectID(p.user) && c.Request.Tenant == "01ARZ3NDEKTSV4RRFFQ69G5FAV" && c.PolicyRevision == 1
	resource := c.Request.Resource.Type == "identity.user" && c.Request.Resource.ID == authorization.ResourceID(p.user) || c.Request.Resource.Type == "identity.request-admission" && (c.Request.Resource.ID == "identity.passkey.register-options" || c.Request.Resource.ID == "identity.passkey.register-verify")
	action := c.Request.Action == "identity.passkey.register-options" || c.Request.Action == "identity.passkey.register-verify" || c.Request.Action == "identity.passkey.list" || c.Request.Action == "identity.passkey.signin-verify" || c.Request.Action == authorization.Action(session.RevokeOneOperation().OperationID)
	if self && resource && action {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (signinPolicy{}).Decide(ctx, c)
}

// Only the external authenticator is controlled: standard-library ES256 signs
// real server options, and every protocol/domain/session owner remains genuine.
func enrollmentSignupAssertion(t *testing.T, key *ecdsa.PrivateKey, id, handle []byte, challenge string, count uint32) []byte {
	t.Helper()
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("identity.example"))
	authenticator := binary.BigEndian.AppendUint32(append(bytes.Clone(rp[:]), 0x05), count)
	clientHash := sha256.Sum256(client)
	message := sha256.Sum256(append(bytes.Clone(authenticator), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, message[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(authenticator), "signature": b64(signature), "userHandle": b64(handle)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestPasskeyOnlySignupEnrollsSecondKeyAndBothCredentialsSignIn(t *testing.T) {
	f, signup := newSignupFixture(t)
	r := signupBrowserRequest(t, f, signup)
	options, err := signup.RegistrationOptions(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("actual signup ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	r.CommandID, _ = identity.NewCommandID()
	created, err := signup.Signup(f.ctx, passkey.SignupCompletion{SignupRequest: r, CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge), Label: "Original signup key"})
	if err != nil {
		t.Fatal("actual password-free account/signup session", err)
	}
	record, err := created.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	config := f.signin.config()
	policy := enrollmentSignupPolicy{user: record.UserID}
	config.Authorization = policy
	query := *config.Coordinator.QueryPolicy
	query.Authorization = policy
	config.Coordinator.QueryPolicy, config.Coordinator.AdmissionPolicy = &query, &query
	f.signin, err = NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSessionEnrollmentService(f.pool, SessionEnrollmentConfig{Protocol: config.Protocol, Profile: config.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, Clock: config.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.lookup}}, SessionRepository: config.Repository, OptionsRequests: keyedFixtureConfig(t, f.enrollmentFixture, query), Coordinator: config.Coordinator, Authorization: policy, Clock: config.Clock, Transport: session.CredentialBearer, Risk: f.service.config().Risk, PolicyID: config.Flow.PolicyID, PolicyVersion: config.Flow.PolicyVersion})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, created.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-only-enrollment", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(record.UserID), Kind: authorization.SubjectUser}, Tenant: authorization.TenantID(record.TenantID), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
	intent := passkey.SessionEnrollmentRequestSpec{Credential: credential, Caller: caller, Label: "Additional signup key", Origin: r.Origin, Network: r.Network}
	a, err := service.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, "signup-add-A")})
	if err != nil {
		t.Fatal("passkey-only account could not request enrollment UV", err)
	}
	aCeremony, ok := a.Options.Ceremony()
	if !ok {
		t.Fatal("enrollment assertion absent")
	}
	aChallenge := signinChallenge(t, f.ctx, a.Options.TransferJSON)
	b, err := service.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(passkey.SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: optionsKey(t, "signup-add-B"), CeremonyID: aCeremony.ID, Response: enrollmentSignupAssertion(t, key, id, ceremony.Intent.UserHandle, aChallenge, 1)}))
	if err != nil {
		t.Fatal("passkey-only UV could not authorize enrollment", err)
	}
	bCeremony, ok := b.Options.Ceremony()
	if !ok {
		t.Fatal("additional registration absent")
	}
	bChallenge := signinChallenge(t, f.ctx, b.Options.TransferJSON)
	secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondID := make([]byte, 32)
	if _, err := rand.Read(secondID); err != nil {
		t.Fatal(err)
	}
	intent.Caller = intent.Caller.Clone()
	intent.Caller.Request.Action = "identity.passkey.register-verify"
	command, _ := identity.NewCommandID()
	out, err := service.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: bCeremony.ID, Response: residentRegistrationResponse(t, secondKey, secondID, bChallenge)}))
	if err != nil {
		t.Fatal("passkey-only additional key did not commit", err)
	}
	fields, err := out.Bindings()
	if err != nil || fields.Credential == nil || fields.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("passkey-only additional key lost committed metadata", err)
	}
	var passwords, identifiers int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_password.credentials WHERE user_id=$1),(SELECT count(*) FROM identity.identifiers WHERE user_id=$1)`, string(record.UserID)).Scan(&passwords, &identifiers); err != nil || passwords != 0 || identifiers != 0 {
		t.Fatal("passkey-only enrollment invented a fallback", err)
	}
	for _, authenticator := range []struct {
		key   *ecdsa.PrivateKey
		id    []byte
		count uint32
	}{{key, id, 2}, {secondKey, secondID, 1}} {
		request := discoverableRequest(f.request(t, session.BrowserSession))
		begin, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		ceremony, ok := begin.Ceremony()
		if !ok {
			t.Fatal("actual identifier-free assertion absent")
		}
		challenge := signinChallenge(t, f.ctx, begin.TransferJSON)
		request.CommandID, _ = identity.NewCommandID()
		issued, err := f.signin.DiscoverableSignin(f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: request, CeremonyID: ceremony.ID, Response: enrollmentSignupAssertion(t, authenticator.key, authenticator.id, bCeremony.Intent.UserHandle, challenge, authenticator.count)})
		if err != nil {
			t.Fatal("either genuine key could not sign into passkey-only account", err)
		}
		passkeyJourneyReadInventoryLogout(t, f, issued, "Original signup key", intent.Label)
	}
	passkeyJourneyReadInventoryLogout(t, f, SigninResult{Session: created.Session, CSRF: created.CSRF}, "Original signup key", intent.Label)
}
