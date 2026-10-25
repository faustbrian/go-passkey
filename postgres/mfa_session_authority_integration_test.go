//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// The native enrolled key and original UV assertion/challenge are genuine.
// Completed-session metadata below is only the mapping port's input projection:
// it does NOT assert that TOTP was verified or that a session was issued.
func mfaMappingSessionFixture(t *testing.T, discovery bool) (*signinFixture, *SessionAuthority, session.Session) {
	t.Helper()
	f, _ := selectedSigninMFAFixture(t, discovery)
	var result SigninResult
	var flowID identity.PreAuthTransactionID
	var err error
	if discovery {
		r, _ := f.discoverablePending(t)
		flowID = r.FlowID
		result, err = f.signin.DiscoverableSignin(f.ctx, r)
	} else {
		r, _ := f.pending(t)
		flowID = r.FlowID
		result, err = f.signin.Signin(f.ctx, r)
	}
	if err != nil || result.Challenge == nil {
		t.Fatal("genuine enrolled assertion did not produce its native challenge", err)
	}
	grant, _, _, err := f.signin.mfa.issuer.ReadIssuanceOrigin(f.ctx, f.pool, result.Challenge.Proof, "identity.mfa.complete")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := mfapg.NewContinuationReader(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := reader.Read(f.ctx, grant, f.signin.mfa.issuerURL)
	if err != nil {
		t.Fatal(err)
	}
	c := f.signin.config()
	flow, err := sessionpg.ReadPreAuth(f.ctx, f.pool.Raw(), c.Repository, c.Protocol.TenantID, flowID)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-signin", Request: authorization.Request{Tenant: authorization.TenantID(c.Protocol.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, Action: "identity.mfa.complete", Resource: authorization.Resource{Type: "identity.user", ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}}}
	original, err := f.signin.ReadMFAPasskeyPrimary(f.ctx, result.Challenge.Proof, continuation, flow, caller)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := continuation.Bindings()
	digest, _ := continuation.ScopeDigest()
	spec := original.Primary
	spec.Lookup = session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}
	spec.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	spec.LastActivityAt = spec.IssuedAt
	remember, _ := spec.Remember.Bindings()
	completion, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var factor string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2`, string(spec.TenantID), string(spec.UserID)).Scan(&factor); err != nil {
		t.Fatal(err)
	}
	m, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: completion, PrimaryCommandID: original.CommandID, ContinuationID: identity.CommandID(scope.ID), ContinuationScopeDigest: digest, Method: "totp", FactorID: factor, EnrollmentVersion: 1, FactorAuthorityVersion: scope.FactorVersion, ContinuationVersion: 1, Remember: remember, VerifiedAt: spec.IssuedAt, ValidUntil: scope.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithPasskeyMFA(spec, m)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewSessionAuthority(f.pool, SessionAuthorityConfig{TenantID: spec.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return f, authority, record
}

func TestMFAPasskeySessionAuthorityKeepsActualNativeMapping(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discovery], func(t *testing.T) {
			f, owner, record := mfaMappingSessionFixture(t, discovery)
			c := owner.config()
			spec, _ := record.Bindings()
			vector, _ := spec.Authority.Bindings()
			before := time.Now().UTC()
			observed, err := owner.ObserveMFAPasskeySession(f.ctx, c.RPNamespace, record)
			after := time.Now().UTC()
			if err != nil || observed.PasskeyVersion != vector.Passkey.Binding.Version || observed.ReadStartedAt.Before(before) || observed.ReadStartedAt.After(after) || observed.ValidUntil.Sub(observed.ReadStartedAt) != 20*time.Second {
				t.Fatal("current native mapping was denied or its original read window changed", err)
			}
			if _, err := owner.ObservePasskeySession(f.ctx, c.RPNamespace, record); err == nil {
				t.Fatal("completed TOTP entered legacy known-empty MFA reader")
			}
			// Mapping evidence does not claim current factor authority. Its
			// independent owner must reject the changed factor generation.
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1`); err != nil {
				t.Fatal(err)
			}
			mappingOnly, mappingErr := owner.ObserveMFAPasskeySession(f.ctx, c.RPNamespace, record)
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version-1`); err != nil {
				t.Fatal(err)
			}
			if mappingErr != nil || mappingOnly.PasskeyVersion != observed.PasskeyVersion {
				t.Fatal("mapping port invented a factor authority claim", mappingErr)
			}
			testMFAPasskeyMappingReadWindow(t, f, owner, record)
			canceled, cancel := context.WithCancel(f.ctx)
			cancel()
			if _, err := owner.ObserveMFAPasskeySession(canceled, c.RPNamespace, record); !errors.Is(err, context.Canceled) {
				t.Fatal("current mapping ignored cancellation", err)
			}
			for _, scenario := range []struct{ name, sql, restore string }{
				{"mapping-version", `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`, `UPDATE identity_passkey.user_handles SET authority_version=authority_version-1`},
				{"credential-version", `UPDATE identity_passkey.credentials SET version=version+1`, `UPDATE identity_passkey.credentials SET version=version-1`},
				{"revoked", `UPDATE identity_passkey.credentials SET state='revoked'`, `UPDATE identity_passkey.credentials SET state='active'`},
				{"compromised", `UPDATE identity_passkey.credentials SET state='compromised'`, `UPDATE identity_passkey.credentials SET state='active'`},
				{"RP-ID", `UPDATE identity_passkey.relying_parties SET rp_id='other.example'`, `UPDATE identity_passkey.relying_parties SET rp_id='identity.example'`},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					if _, err := f.pool.Raw().Exec(f.ctx, scenario.sql); err != nil {
						t.Fatal(err)
					}
					got, readErr := owner.ObserveMFAPasskeySession(f.ctx, c.RPNamespace, record)
					if _, err := f.pool.Raw().Exec(f.ctx, scenario.restore); err != nil {
						t.Fatal(err)
					}
					if readErr == nil || got.PasskeyVersion != 0 || !got.ReadStartedAt.IsZero() || !got.ValidUntil.IsZero() {
						t.Fatal("changed mapping replaced the original record or emitted positive evidence")
					}
				})
			}
			for _, mode := range []string{"namespace", "tenant", "user", "reference", "RP-key", "factor-key", "factor-method"} {
				t.Run(mode, func(t *testing.T) {
					candidate, namespace := mfaMappingForeignRecord(t, record, mode), c.RPNamespace
					if mode == "namespace" {
						namespace = "foreign-rp"
					}
					if _, err := owner.ObserveMFAPasskeySession(f.ctx, namespace, candidate); err == nil {
						t.Fatal("foreign completed session mapping admitted", mode)
					}
				})
			}
			testMFAPasskeyMappingWork(t, f, owner, record)
			if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity_passkey.credentials`); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.ObserveMFAPasskeySession(f.ctx, c.RPNamespace, record); err == nil {
				t.Fatal("missing credential mapping admitted")
			}
		})
	}
}

func testMFAPasskeyMappingReadWindow(t *testing.T, f *signinFixture, owner *SessionAuthority, record session.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	tx, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE identity_passkey.user_handles IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		observation sessionpg.MFAPasskeySessionAuthorityObservation
		err         error
	}
	result := make(chan readResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		o, err := owner.ObserveMFAPasskeySession(ctx, owner.config().RPNamespace, record)
		result <- readResult{o, err}
	}()
	defer func() {
		cancel()
		_ = tx.Rollback(f.ctx)
		<-done
	}()
	// A real blocked owner query distinguishes the original read start from a
	// timestamp incorrectly captured after contributing IO or a lock wait.
	waiting := false
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !waiting {
		if err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT h.authority_version%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if !waiting {
			select {
			case <-ticker.C:
			case got := <-result:
				t.Fatal("mapping observation did not wait for its original owner", got.err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	released := time.Now().UTC()
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil || !got.observation.ReadStartedAt.Before(released) || got.observation.ValidUntil.Sub(got.observation.ReadStartedAt) != 20*time.Second {
		t.Fatal("mapping wait renewed original primary read window", got.err)
	}
}

func mfaMappingForeignRecord(t *testing.T, original session.Session, mode string) session.Session {
	t.Helper()
	s, _ := original.Bindings()
	v, _ := s.Authority.Bindings()
	m, _ := original.MFAAuthentication().Bindings()
	switch mode {
	case "tenant":
		s.TenantID, s.Authentication.Proof.Tenant = "foreign-tenant", "foreign-tenant"
	case "user":
		s.UserID, s.Authentication.Proof.Subject = "foreign-user", "foreign-user"
	case "reference":
		s.Authentication.CredentialID = "foreign-reference"
	case "RP-key":
		v.Passkey.Binding.ScopeKey = "foreign-key"
	case "factor-key":
		v.Factor.Binding.ScopeKey = "foreign-key"
	case "factor-method":
		m.Method = "otp"
	}
	var err error
	s.Authority, err = session.NewAuthoritySnapshot(v)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := session.NewMFAAuthentication(m)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithPasskeyMFA(s, factor)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// This participant is a deliberate native-scope component seam. The genuine
// mapping and MFA-owned factor fences run in registered coordinator Work; no
// metadata projection is presented as authentication or completed revocation.
type mfaMappingInvocation struct {
	f                 *signinFixture
	store             *SessionAuthority
	record            session.Session
	command           identity.Command
	mode              string
	admitted, checked bool
	returned          kernel.Work
}

func (*mfaMappingInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
}
func (*mfaMappingInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{session.RevokeOneOperation()}
}
func (p *mfaMappingInvocation) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaMappingInvocation) ApplyFeature(ctx context.Context, w kernel.Work, _ identity.Command) (identity.FeatureReceipt, error) {
	s, _ := p.record.Bindings()
	m, _ := p.record.MFAAuthentication().Bindings()
	// Same factor-before-mapping order as the actual native consumers.
	if err := mfapg.RequireTOTPSessionFactor(ctx, w, p, s.UserID, m.FactorID, mfapg.TOTPSessionFactorState{EnrollmentVersion: m.EnrollmentVersion, AuthorityVersion: m.FactorAuthorityVersion}); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.mode == "foreign-instance" {
		foreign := *p
		return identity.FeatureReceipt{}, p.store.RequireMFAPasskeySession(ctx, w, &foreign, p.store.config().RPNamespace, p.record)
	}
	if err := p.store.RequireMFAPasskeySession(ctx, w, p, p.store.config().RPNamespace, p.record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.admitted, p.returned = true, w
	if p.mode == "current-locks" {
		for _, sql := range []string{`UPDATE identity_passkey.relying_parties SET rp_id=rp_id`, `UPDATE identity_passkey.user_handles SET authority_version=authority_version`, `UPDATE identity_passkey.credentials SET version=version`} {
			blocked, stop := context.WithTimeout(ctx, 80*time.Millisecond)
			_, err := p.f.pool.Raw().Exec(blocked, sql)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				return identity.FeatureReceipt{}, identity.ConflictError{}
			}
		}
		p.checked = true
	}
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}
func (*mfaMappingInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}

func testMFAPasskeyMappingWork(t *testing.T, f *signinFixture, store *SessionAuthority, record session.Session) {
	t.Helper()
	directory, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
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
	s, _ := record.Bindings()
	for _, mode := range []string{"current-locks", "late-withdrawal", "foreign-instance", "foreign-subject", "sibling-target"} {
		t.Run(mode, func(t *testing.T) {
			p := &mfaMappingInvocation{f: f, store: store, record: record, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, auditing, lifecycle, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(f.pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := session.RevokeOneOperation()
			b := identity.CommandBinding{CommandID: id, TenantID: s.TenantID, UserID: s.UserID, ActorID: identity.ActorID(s.UserID), ActorKind: authorization.SubjectUser, RecordID: s.SessionID, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "component", PolicyVersion: 1, CorrelationID: "component"}
			if mode == "foreign-subject" {
				p.record = mfaMappingForeignRecord(t, record, "user")
			}
			if mode == "sibling-target" {
				b.RecordID = "sibling-session"
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "component", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: mode}}}})
			if err != nil {
				t.Fatal(err)
			}
			p.command = command
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(s.UserID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(s.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "late-withdrawal" {
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`); err != nil {
					t.Fatal(err)
				}
			}
			reservation, _, err := coordinator.ReserveCommand(f.ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(f.ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			_, applyErr := coordinator.ApplyFeature(f.ctx, w, command)
			_, _ = coordinator.Abort(w, applyErr)
			want := mode == "current-locks" || mode == "sibling-target"
			if applyErr == nil || p.admitted != want || p.checked != (mode == "current-locks") {
				t.Fatal("mapping Work scope/fence changed", applyErr, p.admitted, p.checked)
			}
			if err := store.RequireMFAPasskeySession(f.ctx, p.returned, p, store.config().RPNamespace, record); err == nil {
				t.Fatal("returned Work retained mapping authority")
			}
			if mode == "late-withdrawal" {
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.user_handles SET authority_version=authority_version-1`); err != nil {
					t.Fatal(err)
				}
			}
			// Explicit abort must release all fences, not merely close rows.
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.relying_parties SET rp_id=rp_id; UPDATE identity_passkey.user_handles SET authority_version=authority_version; UPDATE identity_passkey.credentials SET version=version`); err != nil {
				t.Fatal(err)
			}
		})
	}
}
