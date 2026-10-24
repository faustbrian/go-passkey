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
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	passkey "github.com/faustbrian/go-passkey"
)

// The existing account belongs to an unrelated fixture tenant member. No row
// for the prospective signup user may exist until genuine registration succeeds.
func newSignupFixture(t *testing.T, keyed ...bool) (*signinFixture, *SignupService) {
	t.Helper()
	f := newSigninFixtureForEnrolledAccountProfile(t, newEnrollmentFixture(t), true)
	c := f.signin.config()
	c.Flow.Action = "identity.passkey.register-verify"
	apply := func(source migrations.Source, min migrations.Version) {
		t.Helper()
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if step.Version() > min {
				if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
					t.Fatal(step.Name(), err)
				}
			}
		}
	}
	apply(kernel.PasskeyRegistrationMigrationSource{Base: kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.PasswordRegistrationMigrationSource{Base: kernel.MigrationSource{}, Version: 16}, Version: 17}, Version: 18}, 15)
	apply(mfapg.PasskeySignupMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, 1)
	apply(sessionpg.PasskeySignupMigrationSource{Schema: "session_store", Version: 8, PreviousConstraint: "session_issuances_purpose_passkey_v1"}, 0)
	apply(SignupMigrationSource{Version: 4}, 0)
	apply(riskpg.PasskeySignupCounterMigrationSource{Schema: "passkey_risk", Version: 6}, 0)
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: f.riskConfig.CommandCounters.Policy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "velocity", Version: "transaction-owned-v1", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
		t.Fatal("protected signup invoked nontransactional velocity")
		return risk.Signal{}, identity.ForbiddenError{}
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	config := SignupConfig{
		Protocol: c.Protocol, Profile: c.Profile, Coordinator: c.Coordinator,
		Authorization: c.Authorization, Clock: c.Clock, Flow: c.Flow, Session: c.Session,
		CSRF: c.CSRF, Repository: c.Repository, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "signup-native", Keys: f.riskConfig.EvidenceKeys}, Counters: f.riskConfig,
	}
	if len(keyed) == 1 && keyed[0] {
		config.OptionsRequests = keyedFixtureConfig(t, f.enrollmentFixture, *c.Coordinator.QueryPolicy)
	}
	s, err := NewSignupService(f.pool, config)
	if err != nil {
		t.Fatal("native prospective signup composition", err)
	}
	return f, s
}

func signupBrowserRequest(t *testing.T, f *signinFixture, s *SignupService, choices ...session.RememberChoice) passkey.SignupRequest {
	t.Helper()
	c := s.core.config()
	choice := session.BrowserSession
	if len(choices) > 1 {
		t.Fatal("invalid signup remember fixture")
	}
	if len(choices) == 1 {
		choice = choices[0]
	}
	remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PrepareFlow(session.PreAuthPrepareInput{CommandID: id, TenantID: c.Protocol.TenantID, CorrelationID: "passkey-signup", Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := s.IssueFlow(f.ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := flow.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	id, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return passkey.SignupRequest{CommandID: id, FlowID: b.Binding.ID, Cookie: flow.Token, Origin: c.Flow.Origin, Network: "127.0.0.1", Device: "signup-browser", CorrelationID: "passkey-signup"}
}

func TestPasskeySignupCommitsAccountCredentialSessionAndLifecycles(t *testing.T) {
	f, s := newSignupFixture(t, true)
	c := s.core.config()
	r := signupBrowserRequest(t, f, s)
	r.CommandID = ""
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(c.Flow.ActorID), Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.FlowID)}}}
	keyed := passkey.KeyedSignupOptionsRequest{SignupRequest: r, IdempotencyKey: optionsKey(t, "signup-journey-options"), Caller: caller}
	begin, err := s.KeyedRegistrationOptions(f.ctx, keyed)
	if err != nil {
		t.Fatal("genuine signup options", err)
	}
	options := begin.Options
	r.CorrelationID = string(begin.CommandID)
	var users, handles, credentials, sessions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity_passkey.user_handles),(SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM session_store.sessions)`).Scan(&users, &handles, &credentials, &sessions); err != nil || users != 1 || handles != 0 || credentials != 0 || sessions != 1 {
		t.Fatal("options created account or stable authenticator state", err, users, handles, credentials, sessions)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := make([]byte, 32)
	if _, err := rand.Read(credential); err != nil {
		t.Fatal(err)
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("no original signup ceremony")
	}
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Signup(f.ctx, passkey.SignupCompletion{SignupRequest: r, CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, credential, challenge), Label: "Signup key"})
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
		t.Fatal("genuine registration did not create usable account session", err)
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.UserID == "" || spec.UserID == "01ARZ3NDEKTSV4RRFFQ69G5FAW" {
		t.Fatal("signup reused existing identity", err)
	}
	wire, err := result.Session.Token.Reveal()
	if err != nil || wire == "" {
		t.Fatal("new committed signup bearer withheld", err)
	}
	csrfWire, err := result.CSRF.Reveal()
	if err != nil {
		t.Fatal("signup CSRF withheld", err)
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(f.lookup, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := sessionpg.NewRepository(f.pool, c.Repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Lookup(f.ctx, spec.TenantID, digest); err != nil {
		t.Fatal("created session not readable", err)
	}
	var events, ids, passwords int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1 AND topic IN('identity.passkey.create_credential','user.created.v1','session.created.v1')),(SELECT count(*) FROM identity.identifiers WHERE user_id=$2),(SELECT count(*) FROM identity_password.credentials WHERE user_id=$2)`, string(r.CommandID), string(spec.UserID)).Scan(&events, &ids, &passwords); err != nil || events != 3 || ids != 0 || passwords != 0 {
		t.Fatal("signup missing effects or fabricated fallback", err, events, ids, passwords)
	}
	var charges, snapshots int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM passkey_risk.counter_charges),(SELECT count(*) FROM passkey_risk.counter_snapshots)`).Scan(&charges, &snapshots); err != nil || charges != 2 || snapshots != 8 {
		t.Fatal("genuine signup did not charge both original protected phases", err, charges, snapshots)
	}
	if retry, err := s.KeyedRegistrationOptions(f.ctx, keyed); err != nil || !retry.Replayed || retry.CommandID != begin.CommandID || retry.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("consumed signup flow lost original options metadata", err)
	} else if _, present := retry.Options.Ceremony(); present {
		t.Fatal("consumed signup flow disclosed options again")
	}
	passkeySignupReadLogoutAndFreshSignin(t, f, spec, token, csrfWire, key, credential, ceremony.Intent.UserHandle)
}

// The retained fixture policy admits only its seeded user. This ordinary
// consumer callback also permits the actual new user's signin and self-logout;
// the real session owner still verifies possession, CSRF and current authority.
type signupSessionPolicy struct{ user identity.UserID }

func (p signupSessionPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == "01ARZ3NDEKTSV4RRFFQ69G5FAV" && p.user != "" && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == authorization.SubjectID(p.user) && (c.Request.Action == authorization.Action(session.RevokeOneOperation().OperationID) || c.Request.Action == "identity.passkey.signin-verify") && c.Request.Resource.Type == "identity.user" && c.Request.Resource.ID == authorization.ResourceID(p.user) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (signinPolicy{}).Decide(ctx, c)
}

func passkeySignupReadLogoutAndFreshSignin(t *testing.T, f *signinFixture, spec session.SessionSpec, token session.Token, csrfWire string, key *ecdsa.PrivateKey, credential, handle []byte) {
	t.Helper()
	c := f.signin.config()
	policy := signupSessionPolicy{user: spec.UserID}
	c.Authorization = policy
	query := *c.Coordinator.QueryPolicy
	query.Authorization = policy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &query
	signin, err := NewSigninService(f.pool, c)
	if err != nil {
		t.Fatal("new account consumer signin policy", err)
	}
	f.signin = signin
	authority, err := NewSessionAuthority(f.pool, SessionAuthorityConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewPasskeySessionService(f.pool, sessionpg.PasskeySessionServiceConfig{Repository: c.Repository, Profile: c.Profile, Authority: authority, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: c.Profile.Audience, Clock: c.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.lookup}}})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	input := session.GetRequest{TenantID: spec.TenantID, Credential: cookie}
	accepted, err := reader.Get(f.ctx, input)
	if err != nil || !accepted.Authenticated {
		t.Fatal("actual signup session admission", err)
	}
	steps, err := (sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "session_store", Version: 1}, Version: 2}, Version: 9}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, steps[len(steps)-1].UpSQL()); err != nil {
		t.Fatal("signup logout history", err)
	}
	coordinator := c.Coordinator
	executor, err := sessionpg.NewCookieRevokeOneExecutor(f.pool, sessionpg.RevokeOneExecutorConfig{Execution: sessionpg.IssueExecutorConfig{Repository: c.Repository, Profile: sessionpg.IssueAdmissionConfig{GlobalAuthorityID: c.Profile.GlobalAuthorityID, PolicyNamespace: c.Profile.PolicyNamespace, Audience: c.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Coordinator: coordinator, Authorization: policy, Clock: c.Clock, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion, AuditRetentionVersion: 1}, Sessions: reader, Passkey: &sessionpg.PasskeySessionAdmission{Profile: c.Profile, Authority: authority}}, []session.CSRFKey{f.csrf})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := session.RevokeOneOperation()
	b := identity.CommandBinding{CommandID: id, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: spec.SessionID, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion, CorrelationID: "passkey-signup-logout"}
	command, err := session.NewRevokeOneCommand(b, accepted.Session)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	request, err := reader.PrepareRevokeOneWithCSRF(accepted, command, csrf, f.csrf)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := executor.ExecuteRevokeOneWithCSRF(f.ctx, request); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual signup cookie logout", err)
	}
	if got, err := reader.Get(f.ctx, input); err != nil || got.Authenticated {
		t.Fatal("signup session survived logout", err)
	}
	r := discoverableRequest(f.request(t, session.BrowserSession))
	options, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("fresh identifier-free options after signup", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("fresh identifier-free ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": c.Flow.Origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(c.Protocol.RelyingParty.ID))
	authenticator := binary.BigEndian.AppendUint32(append(bytes.Clone(rp[:]), 0x05), 1)
	clientHash := sha256.Sum256(client)
	message := sha256.Sum256(append(bytes.Clone(authenticator), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, message[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	response, _ := json.Marshal(map[string]any{"id": b64(credential), "rawId": b64(credential), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(authenticator), "signature": b64(signature), "userHandle": b64(handle)}, "clientExtensionResults": map[string]any{}})
	issued, err := f.signin.DiscoverableSignin(f.ctx, DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: response})
	if err != nil || issued.Session.CommitOutcome != identity.CommitOutcomeCommitted || issued.Session.Replayed {
		t.Fatal("fresh identifier-free signin after signup logout", err)
	}
	fresh, err := issued.Session.Session.Bindings()
	if err != nil || fresh.UserID != spec.UserID || fresh.SessionID == spec.SessionID {
		t.Fatal("fresh signin lost original passkey-only identity", err)
	}
	newReader, _, _, newInput := passkeyJourneyReader(t, f, issued)
	if got, err := newReader.Get(f.ctx, newInput); err != nil || !got.Authenticated {
		t.Fatal("fresh passkey-only signin session unreadable", err)
	}
}
