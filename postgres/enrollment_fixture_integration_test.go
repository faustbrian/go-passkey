//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

const fixturePassword = "synthetic passkey enrollment password"

type enrollmentPolicy struct{}

func (enrollmentPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == "01ARZ3NDEKTSV4RRFFQ69G5FAV" && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == "01ARZ3NDEKTSV4RRFFQ69G5FAW" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}

type enrollmentFixture struct {
	ctx      context.Context
	pool     *database.Pool
	service  *EnrollmentService
	proofs   *passwordpg.ReauthenticationService
	bearer   auth.BearerCredential
	counters risk.CounterCoordinator
}

// Existing active password/session state is deliberate fixture input. Every
// reauthentication, signed proof, admission, protocol verification and mutation
// in the selected enrollment operation uses its real public native owner.
// This is not registration/signin-baseline or complete passkey-session proof.
func newEnrollmentFixture(t *testing.T, reauthenticationClock ...func() time.Time) *enrollmentFixture {
	proofNow := time.Now
	if len(reauthenticationClock) > 1 || len(reauthenticationClock) == 1 && reauthenticationClock[0] == nil {
		t.Fatal("invalid native proof fixture clock")
	}
	if len(reauthenticationClock) == 1 {
		proofNow = reauthenticationClock[0]
	}
	ctx, db := mappingDatabase(t)
	pool, err := database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	apply := func(source migrations.Source) {
		t.Helper()
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, err := db.Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("owned history", step.Name(), err)
			}
		}
	}
	base := kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "passkey-fixture", TenantIDs: []identity.TenantID{"01ARZ3NDEKTSV4RRFFQ69G5FAV"}}
	apply(base)
	apply(sessionpg.MigrationSource{Schema: "session_store", Version: 1})
	apply(passwordpg.PasskeyManagementReauthenticationMigrationSource{Base: passwordpg.PasskeyReauthenticationMigrationSource{Base: passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 10}, Version: 11}, Version: 12})
	apply(mfapg.MigrationSource{Version: 1})
	apply(MigrationSource{})
	apply(SigninMigrationSource{Version: 2})
	apply(MetadataVersionMigrationSource{Version: 3})
	apply(webauthnpg.MigrationSource{})
	apply(riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "passkey_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5})
	apply(riskpg.DurableCounterMigrationSource{Schema: "passkey_admission", Version: 1})
	policystep, err := policy.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, policystep.Up); err != nil {
		t.Fatal(err)
	}
	install, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer install.Rollback(ctx)
	if _, err := install.Exec(ctx, `SET LOCAL search_path=public,pg_catalog`); err != nil {
		t.Fatal(err)
	}
	if _, err := install.Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	for _, files := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), identityoutbox.Migrations()} {
		entries, err := fs.ReadDir(files, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			wire, err := fs.ReadFile(files, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := install.Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := install.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := db.Exec(cleanup, `DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention`); err != nil {
			t.Error("owned audit role cleanup", err)
		}
	})
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW','active',1);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW','password',1,'identity/password',1,true);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'01ARZ3NDEKTSV4RRFFQ69G5FAV','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'01ARZ3NDEKTSV4RRFFQ69G5FAV','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');`); err != nil {
		t.Fatal(err)
	}
	scope := policy.AuthorityScope{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", PolicyNamespace: "users", SubjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "passkey-fixture", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}, "01ARZ3NDEKTSV4RRFFQ69G5FAW")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := sessionpg.SessionAuthorityKeys("01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", "family-a", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := scope.Key()
	if err != nil {
		t.Fatal(err)
	}
	a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	v := session.AuthoritySnapshotSpec{Global: a(k.Global), Tenant: a(k.Tenant), User: a(k.User), Identifier: a(k.Identifier), Credential: a(k.Credential), Session: a(sk.Session), SessionFamily: a(sk.Family), Authorization: a(pk)}
	vector, err := session.NewAuthoritySnapshot(v)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(lookup, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Subject: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "passkey-fixture", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Audience: "passkey-fixture", Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, Authentication: metadata, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		t.Fatal(err)
	}
	_ = record
	resolved, _ := remember.Bindings()
	payload, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": "session-a", "FamilyID": "family-a", "TenantID": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "UserID": "01ARZ3NDEKTSV4RRFFQ69G5FAW", "Audience": "passkey-fixture", "Version": uint64(1), "FamilyVersion": uint64(1), "Remember": resolved, "Authority": v, "Lookup": digest, "Authentication": metadata, "IssuedAt": now, "LastActivityAt": now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','family-a','01ARZ3NDEKTSV4RRFFQ69G5FAW',1,'active',$1)`, now.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','session-a','01ARZ3NDEKTSV4RRFFQ69G5FAW','family-a',1,1,'active',1,$1,$2,$3)`, digest.Sum[:], now.Add(30*time.Minute).Format("2006-01-02T15:04:05.000000000Z"), payload); err != nil {
		t.Fatal(err)
	}
	crypto, err := primitive.New(primitive.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.Hash(ctx, []byte(fixturePassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW','password',1,'argon2id',$1)`, hash.String()); err != nil {
		t.Fatal(err)
	}
	sessions, err := sessionpg.NewRepository(pool, sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Lookup(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAV", digest); err != nil {
		t.Fatal("fixture session read", err)
	}
	passwords, err := passwordpg.NewRepository(pool, passwordpg.Config{MaximumDuration: time.Second, HashPolicy: primitive.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := passwords.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", SubjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}); err != nil {
		t.Fatal("fixture credential read", err)
	}
	configuration := risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	riskPolicy, err := risk.NewPolicy(configuration)
	if err != nil {
		t.Fatal("fixture risk policy", err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{33}, 32), bytes.Repeat([]byte{34}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: pool, Schema: "passkey_admission", Namespace: "verify", Policy: riskPolicy, Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{35}, 32), Tenants: []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV"}, MaximumRecords: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: riskPolicy, Keys: []risk.CounterDigestKey{key}, Store: store, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	riskPolicyID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: riskPolicy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(riskPolicyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, lost.Record())
		return err
	}}})
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := passwordpg.NewReauthenticationSigningKey("fixture", private)
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	clear(private)
	query := kernel.CommandQueryPolicy{Authorization: enrollmentPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 5 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &query, AdmissionPolicy: &query}
	targets := []passwordpg.ReauthenticationTarget{}
	for _, finish := range []bool{false, true} {
		targets = append(targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: enrollmentOperation(finish).OperationID, Audience: "passkey-enrollment"})
	}
	targets = append(targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.passkey.update", Audience: "passkey-enrollment"})
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "passkey-fixture", PolicyNamespace: "users", Audience: "passkey-fixture", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	proofs, err := passwordpg.NewReauthenticationService(pool, passwordpg.ReauthenticationConfig{Repository: passwordpg.Config{MaximumDuration: 5 * time.Second, HashPolicy: primitive.DefaultPolicy()}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: 4 * time.Second, DummyHash: hash, Now: proofNow}, Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: []session.DigestKey{lookup}, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "passkey-verify", Keys: []risk.EvidenceKey{evidence}}, Coordinator: coordinator, SigningKey: signer, VerificationKeys: map[string]ed25519.PublicKey{"fixture": public}, Issuer: "passkey-fixture", Environment: "isolated", Targets: targets, TTL: 5 * time.Minute, IdentifierKey: bytes.Repeat([]byte{36}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	options, err := passwordpg.NewActionPrimarySource(proofs, passwordpg.ActionPrimaryConfig{Action: enrollmentOperation(false).OperationID, Audience: "passkey-enrollment", MaximumAge: 5 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := passwordpg.NewActionPrimarySource(proofs, passwordpg.ActionPrimaryConfig{Action: enrollmentOperation(true).OperationID, Audience: "passkey-enrollment", MaximumAge: 5 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := riskpg.NewRepository(riskpg.Config{Schema: "passkey_risk", PolicyVersion: 1, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"fixture": bytes.Repeat([]byte{37}, 32)}, CurrentEnvelopeKey: "fixture", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: riskPolicy, Keys: []risk.CounterDigestKey{key}}, EnforceLockouts: true})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{38}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewEnrollmentService(pool, EnrollmentConfig{Protocol: webauthn.Config{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", RelyingParty: webauthn.RelyingParty{ID: "identity.example", Name: "Passkey", Origins: []string{"https://identity.example"}, Version: 1}, ChallengeKey: challenge, MaximumDuration: 5 * time.Second}, RPNamespace: "shared-rp", Coordinator: coordinator, Authorization: enrollmentPolicy{}, OptionsSource: options, RegistrationSource: registration, Risk: protected, PolicyID: "passkey-fixture", PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &enrollmentFixture{ctx: ctx, pool: pool, service: service, proofs: proofs, bearer: auth.NewBearerCredential(wire), counters: counters}
}

func (f *enrollmentFixture) request(t *testing.T, finish bool) RegistrationRequest {
	t.Helper()
	op := enrollmentOperation(finish)
	return f.actionRequest(t, op.OperationID)
}

func (f *enrollmentFixture) actionRequest(t *testing.T, action string) RegistrationRequest {
	t.Helper()
	secret, err := primitive.NewSecret([]byte(fixturePassword))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-consumer", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	proof, err := f.proofs.Verify(f.ctx, passwordpg.ReauthenticationRequest{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Session: f.bearer, Password: secret, Target: passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: action, Audience: "passkey-enrollment"}, Caller: caller, Network: "127.0.0.1", Device: "passkey-browser"})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted || proof.Proof == (auth.ReauthenticationProof{}) {
		t.Fatal("genuine native action proof", err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Action = authorization.Action(action)
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}
	return RegistrationRequest{Primary: passwordpg.ActionPrimaryRequest{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CommandID: id, Session: f.bearer, Proof: proof.Proof, Caller: caller}, Origin: "https://identity.example", Network: "127.0.0.1", Device: "passkey-browser"}
}
