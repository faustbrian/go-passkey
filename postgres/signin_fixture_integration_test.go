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
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	webauthn "github.com/faustbrian/go-webauthn"
)

type signinPolicy struct{}

func (signinPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	allowed := c.PolicyRevision == 1 && c.Request.Tenant == "01ARZ3NDEKTSV4RRFFQ69G5FAV" && ((c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "signin-service") || (c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == "01ARZ3NDEKTSV4RRFFQ69G5FAW"))
	decision := authorization.Deny
	if allowed {
		decision = authorization.Allow
	}
	return authorization.Decision{Outcome: decision, Revision: 1}, nil
}

type signinFixture struct {
	*enrollmentFixture
	signin         *SigninService
	key            *ecdsa.PrivateKey
	id             []byte
	lookup         session.DigestKey
	csrf           session.CSRFKey
	assertionFlags byte
}

func newSigninFixture(t *testing.T) *signinFixture {
	return newSigninFixtureFlags(t, 0x45)
}

func newSigninFixtureFlags(t *testing.T, registrationFlags byte) *signinFixture {
	t.Helper()
	f := newEnrollmentFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	options, err := f.service.RegistrationOptions(f.ctx, f.request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("registration ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	registration := residentRegistrationResponse(t, key, id, challenge)
	if registrationFlags != 0x45 {
		// This is the controlled raw none-attestation authenticator seam, not
		// a stored/verified-credential edit. The actual root verifies flags.
		var raw struct {
			ID         string            `json:"id"`
			RawID      string            `json:"rawId"`
			Type       string            `json:"type"`
			Response   map[string]string `json:"response"`
			Extensions map[string]any    `json:"clientExtensionResults"`
		}
		if err := json.Unmarshal(registration, &raw); err != nil {
			t.Fatal(err)
		}
		att, err := base64.RawURLEncoding.DecodeString(raw.Response["attestationObject"])
		if err != nil {
			t.Fatal(err)
		}
		rp := sha256.Sum256([]byte("identity.example"))
		if bytes.Count(att, rp[:]) != 1 {
			t.Fatal("authenticator data boundary absent")
		}
		offset := bytes.Index(att, rp[:]) + len(rp)
		att[offset] = registrationFlags
		raw.Response["attestationObject"] = base64.RawURLEncoding.EncodeToString(att)
		registration, err = json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.service.Register(f.ctx, RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: registration, Label: "Signin key"}); err != nil {
		t.Fatal("real native registration", err)
	}
	signin := newSigninFixtureForEnrolledAccount(t, f)
	signin.key, signin.id, signin.assertionFlags = key, id, registrationFlags&0x18|0x05
	return signin
}

// newSigninFixtureForEnrolledAccount composes the same native owners after
// genuine enrollment. Browser callers retain their authenticator privately;
// this helper neither generates a key nor fabricates registration or proof.
func newSigninFixtureForEnrolledAccount(t *testing.T, f *enrollmentFixture) *signinFixture {
	t.Helper()
	config := f.service.config()
	apply := func(source migrations.Source) {
		t.Helper()
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
				t.Fatal(step.Name(), err)
			}
		}
	}
	issue := sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "session_store", Version: 1}, Version: 2}, Version: 3}
	steps, err := issue.Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps[1:] {
		if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	apply(sessionpg.PreAuthMigrationSource{Schema: "session_store", Version: 4})
	apply(sessionpg.PreAuthIssueMigrationSource{Schema: "session_store", Version: 5})
	apply(sessionpg.CSRFMigrationSource{Schema: "session_store", Version: 6})
	apply(sessionpg.PasskeySigninMigrationSource{Schema: "session_store", Version: 7, PreviousConstraint: "session_issuances_purpose_check"})
	apply(SigninMigrationSource{Version: 2})
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW','signin-email','email','passkey@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, EvidenceTTL: 5 * time.Minute, ThresholdAction: risk.Throttle, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	counterKey, err := risk.NewCounterDigestKey(2, bytes.Repeat([]byte{61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: f.pool, Schema: "passkey_admission", Namespace: "signin", Policy: policy, Keys: []risk.CounterDigestKey{counterKey}, ReplayKey: bytes.Repeat([]byte{62}, 32), Tenants: []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV"}, MaximumRecords: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{counterKey}, Store: store, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(f.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(pid), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, lost.Record())
		return err
	}}})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(2, bytes.Repeat([]byte{63}, 32), bytes.Repeat([]byte{64}, 32))
	if err != nil {
		t.Fatal(err)
	}
	flowKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{65}, 32))
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{66}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{67}, 32))
	if err != nil {
		t.Fatal(err)
	}
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	query := *config.Coordinator.QueryPolicy
	query.Authorization = signinPolicy{}
	config.Coordinator.QueryPolicy, config.Coordinator.AdmissionPolicy = &query, &query
	signin, err := NewSigninService(f.pool, SigninConfig{Protocol: config.Protocol, Profile: sessionpg.PasskeyAdmissionConfig{GlobalAuthorityID: "passkey-fixture", PolicyNamespace: "users", Audience: "passkey-fixture", RPNamespace: config.RPNamespace}, Coordinator: config.Coordinator, Authorization: signinPolicy{}, Clock: clock.System{}, Flow: session.PreAuthIssuerConfig{ActorID: "signin-service", Action: "identity.passkey.signin-verify", Origin: config.Protocol.RelyingParty.Origins[0], PolicyID: config.PolicyID, PolicyVersion: 1, MaximumDuration: 5 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: flowKey, TokenSize: 32, Cookie: flowCookie}, Session: session.IssuerConfig{MaximumDuration: 5 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, CSRF: csrf, Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "passkey-signin", Keys: []risk.EvidenceKey{evidence}}, IdentifierKey: bytes.Repeat([]byte{68}, 32)})
	if err != nil {
		t.Fatal("native signin composition", err)
	}
	return &signinFixture{enrollmentFixture: f, signin: signin, lookup: lookup, csrf: csrf}
}

func signinChallenge(t *testing.T, ctx context.Context, transfer func(context.Context, func(context.Context, []byte) error) error) string {
	t.Helper()
	var challenge string
	if err := transfer(ctx, func(_ context.Context, wire []byte) error {
		var response struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(wire, &response); err != nil {
			return err
		}
		challenge = response.PublicKey.Challenge
		return nil
	}); err != nil || challenge == "" {
		t.Fatal("challenge transfer", err)
	}
	return challenge
}

func (f *signinFixture) request(t *testing.T, choice session.RememberChoice) SigninRequest {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.signin.PrepareFlow(session.PreAuthPrepareInput{CommandID: id, TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CorrelationID: "passkey-signin", Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.signin.IssueFlow(f.ctx, p)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("real preauth flow", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	id, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return SigninRequest{CommandID: id, FlowID: flow.Binding.ID, Cookie: issued.Token, Identifier: "passkey@example.test", Origin: f.signin.config().Flow.Origin, Network: "127.0.0.1", Device: "passkey-browser", CorrelationID: "passkey-signin"}
}

func (f *signinFixture) pending(t *testing.T) (SigninCompletion, webauthn.AssertionOptions) {
	t.Helper()
	r := f.request(t, session.BrowserSession)
	options, err := f.signin.AuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("native signin options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("assertion ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 1)}, options
}

func (f *signinFixture) assertion(t *testing.T, challenge string, count uint32) []byte {
	t.Helper()
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": f.signin.config().Flow.Origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte(f.signin.config().Protocol.RelyingParty.ID))
	data := append(bytes.Clone(rp[:]), f.assertionFlags)
	data = binary.BigEndian.AppendUint32(data, count)
	clientHash := sha256.Sum256(client)
	message := sha256.Sum256(append(bytes.Clone(data), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, f.key, message[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	var handle []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_handle FROM identity_passkey.user_handles WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3`, f.signin.config().Profile.RPNamespace, string(f.signin.config().Protocol.TenantID), "01ARZ3NDEKTSV4RRFFQ69G5FAW").Scan(&handle); err != nil {
		t.Fatal("authenticator resident handle", err)
	}
	wire, err := json.Marshal(map[string]any{"id": b64(f.id), "rawId": b64(f.id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(signature), "userHandle": b64(handle)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
