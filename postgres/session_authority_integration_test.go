//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This seeds non-authenticating owner state to prove the actual public MFA and
// mapping reader boundary. It does not prove WebAuthn, issuance or possession.
func TestNativePasskeySessionAuthorityReadsOriginalOwners(t *testing.T) {
	ctx, db := mappingDatabase(t)
	base := kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}
	history, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	factors, err := (mfapg.MigrationSource{Version: 1}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range append(append(history, factors...), mappings...) {
		if _, err := db.Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("owned history", err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','user-a','ref-a',2,'passkey',1,true);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
INSERT INTO identity_passkey.relying_parties(rp_namespace,rp_id) VALUES('shared-rp','identity.example');
INSERT INTO identity_passkey.user_handles(rp_namespace,tenant_id,user_id,user_handle,authority_version) VALUES('shared-rp','tenant-a','user-a',decode(repeat('01',32),'hex'),1);
INSERT INTO identity_passkey.credentials(rp_namespace,tenant_id,user_id,reference_id,credential_id,version,state,created_at) VALUES('shared-rp','tenant-a','user-a','ref-a',decode(repeat('02',64),'hex'),1,'active',clock_timestamp())`); err != nil {
		t.Fatal("component owner state", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("authority pool cleanup", err)
		}
	})
	config := SessionAuthorityConfig{TenantID: "tenant-a", RPNamespace: "shared-rp", RPID: "identity.example", MaximumDuration: time.Second}
	owner, err := NewSessionAuthority(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	record := authorityRecord(t)
	before := time.Now().UTC()
	observation, err := owner.ObservePasskeySession(ctx, "shared-rp", record)
	after := time.Now().UTC()
	if err != nil || observation.PasskeyVersion != 1 || observation.FactorVersion != 1 || observation.ReadStartedAt.Before(before) || observation.ReadStartedAt.After(after) || observation.ValidUntil.Sub(observation.ReadStartedAt) != 20*time.Second {
		t.Fatal("original current mapping/factor authority denied or renewed", err)
	}
	for _, scenario := range []struct{ name, sql string }{
		{"mapping-generation", `UPDATE identity_passkey.user_handles SET authority_version=2`},
		{"credential-version", `UPDATE identity_passkey.credentials SET version=2`},
		{"credential-revoked", `UPDATE identity_passkey.credentials SET state='revoked'`},
		{"credential-compromised", `UPDATE identity_passkey.credentials SET state='compromised'`},
		{"rp-binding", `UPDATE identity_passkey.relying_parties SET rp_id='other.example'`},
		{"factor-generation", `UPDATE identity_mfa.factor_authorities SET version=2`},
		{"factor-enrolled", `UPDATE identity_mfa.factor_authorities SET active_factors=1`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := db.Exec(ctx, scenario.sql); err != nil {
				t.Fatal(err)
			}
			observed, err := owner.ObservePasskeySession(ctx, "shared-rp", record)
			if err == nil || observed.PasskeyVersion != 0 || observed.FactorVersion != 0 || !observed.ReadStartedAt.IsZero() || !observed.ValidUntil.IsZero() {
				t.Fatal("withdrawn owner admitted or refreshed original snapshot")
			}
			if _, err := db.Exec(ctx, `UPDATE identity_passkey.user_handles SET authority_version=1; UPDATE identity_passkey.credentials SET version=1,state='active'; UPDATE identity_passkey.relying_parties SET rp_id='identity.example'; UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0`); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := owner.ObservePasskeySession(ctx, "other-rp", record); err == nil {
		t.Fatal("request selected a foreign RP namespace")
	}
	testNativePasskeyAuthorityWork(t, ctx, pool, owner, record)
	if _, err := db.Exec(ctx, `DELETE FROM identity_mfa.factor_authorities`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ObservePasskeySession(ctx, "shared-rp", record); err == nil {
		t.Fatal("missing MFA state inferred empty")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := owner.ObservePasskeySession(canceled, "shared-rp", record); !errors.Is(err, context.Canceled) {
		t.Fatal("authority cancellation lost", err)
	}
}

type authorityInvocation struct {
	store                  *SessionAuthority
	pool                   *database.Pool
	record                 session.Session
	command                identity.Command
	admitted, locksChecked bool
	checkLocks             bool
}

func (*authorityInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*authorityInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (p *authorityInvocation) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *authorityInvocation) ApplyFeature(ctx context.Context, w kernel.Work, _ identity.Command) (identity.FeatureReceipt, error) {
	if err := p.store.RequirePasskeySession(ctx, w, p, "shared-rp", p.record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.admitted = true
	if p.checkLocks {
		// The guard has returned, so its rows are closed but its mapping fences
		// must still belong to this exact Work until the coordinator aborts it.
		blocked, stop := context.WithTimeout(ctx, 80*time.Millisecond)
		_, err := p.pool.Raw().Exec(blocked, `UPDATE identity_passkey.user_handles SET authority_version=2 WHERE rp_namespace='shared-rp' AND tenant_id='tenant-a' AND user_id='user-a'`)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		p.locksChecked = true
	}
	if _, err := w.Exec(ctx, `INSERT INTO passkey_authority_probe VALUES(1)`); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}
func (*authorityInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}

func testNativePasskeyAuthorityWork(t *testing.T, ctx context.Context, pool *database.Pool, store *SessionAuthority, record session.Session) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE passkey_authority_probe(value integer)`); err != nil {
		t.Fatal(err)
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current-locks", "late-mapping-withdrawal", "late-factor-withdrawal"} {
		t.Run(mode, func(t *testing.T) {
			feature := &authorityInvocation{store: store, pool: pool, record: record, checkLocks: mode == "current-locks"}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, auditing, lifecycle, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := feature.FeatureOperations()[0]
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, RecordID: "session-a", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "component", PolicyVersion: 1, CorrelationID: "component"}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "component", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: mode}}}})
			if err != nil {
				t.Fatal(err)
			}
			feature.command = command
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: "user-a"}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: "tenant-a", CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			// Withdrawal occurs after a valid plan, not as a malformed request.
			if mode == "late-mapping-withdrawal" {
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_passkey.user_handles SET authority_version=2`)
			}
			if mode == "late-factor-withdrawal" {
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`)
			}
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			_, applyErr := coordinator.ApplyFeature(ctx, work, command)
			result, abortErr := coordinator.Abort(work, applyErr)
			_ = abortErr // The injected unavailable result deliberately aborts.
			want := mode == "current-locks"
			if applyErr == nil || feature.admitted != want || feature.locksChecked != want || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("native authority/lock boundary changed", applyErr, feature.admitted, feature.locksChecked)
			}
			var probes int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM passkey_authority_probe`).Scan(&probes); err != nil || probes != 0 {
				t.Fatal("explicit Abort retained staged work", err)
			}
			// Both owner rows are mutable again after explicit Abort; this also
			// falsifies syntax/privilege errors as the contention-test oracle.
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_passkey.user_handles SET authority_version=1; UPDATE identity_mfa.factor_authorities SET active_factors=0`); err != nil {
				t.Fatal("released owner fences did not unlock", err)
			}
		})
	}
}

func authorityRecord(t *testing.T) session.Session {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	key, err := PasskeyAuthorityKey("shared-rp", "tenant-a", "user-a")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := mfapg.FactorAuthorityKey("tenant-a", "user-a")
	if err != nil {
		t.Fatal(err)
	}
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding("global"), Tenant: binding("tenant"), User: binding("user"), Identifier: binding("identifier"), Credential: binding("credential"), Session: binding("session"), SessionFamily: binding("family"), Authorization: binding("authorization"), Factor: session.OptionalAuthorityBinding{Present: true, Binding: binding(factor)}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: binding(key)}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity", Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: "session-issue", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "ref-a", CredentialVersion: 1}, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
