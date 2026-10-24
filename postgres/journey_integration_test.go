//go:build integration

package postgres

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// Existing password/session seed state is declared by the enrollment fixture.
// Enrollment, signed browser assertion, issued credential, current session read,
// inventory and CSRF-protected logout all use their actual native public owners.
func TestPasskeyEnrollmentSigninInventoryReadAndCookieLogout(t *testing.T) {
	f := newSigninFixture(t)
	completion, _ := f.pending(t)
	issued, err := f.signin.Signin(f.ctx, completion)
	if err != nil {
		t.Fatal("native signin", err)
	}
	passkeyJourneyReadInventoryLogout(t, f, issued)
}

func passkeyJourneyReadInventoryLogout(t *testing.T, f *signinFixture, issued SigninResult, expectedLabels ...string) {
	t.Helper()
	if len(expectedLabels) == 0 {
		expectedLabels = []string{"Signin key"}
	}
	reader, profile, authority, input := passkeyJourneyReader(t, f, issued)
	accepted, err := reader.Get(f.ctx, input)
	if err != nil || !accepted.Authenticated || accepted.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("real issued passkey session unusable", err)
	}
	spec, _ := accepted.Session.Bindings()
	config := f.signin.config()
	inventory, err := NewInventoryService(f.pool, InventoryConfig{TenantID: spec.TenantID, RPNamespace: config.Profile.RPNamespace, RPID: config.Protocol.RelyingParty.ID, Passkey: &profile, Protocol: webauthnpg.Config{Coordinator: config.Coordinator, PolicyID: config.Flow.PolicyID, PolicyVersion: config.Flow.PolicyVersion}, Authorization: config.Authorization, PolicyVersion: config.Flow.PolicyVersion, Rate: &f.counters, MaximumDuration: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-journey", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Tenant: authorization.TenantID(spec.TenantID), Action: "identity.passkey.list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}}}
	listing := InventoryRequest{Credential: input.Credential, Caller: caller, AttemptID: attempt, Limit: 10}
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != len(expectedLabels) {
		t.Fatal("passkey-authenticated safe inventory", err)
	}
	labels := make([]string, 0, len(page.Credentials))
	used := false
	for _, credential := range page.Credentials {
		labels = append(labels, credential.Label)
		used = used || credential.LastUsedAt != nil
	}
	want := slices.Clone(expectedLabels)
	slices.Sort(labels)
	slices.Sort(want)
	if !used || !slices.Equal(labels, want) {
		t.Fatal("passkey inventory labels or actual usage changed")
	}

	history, err := (sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "session_store", Version: 1}, Version: 2}, Version: 8}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var installed bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_regclass('session_store.session_revocations') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal("logout history lookup", err)
	}
	if !installed {
		if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
			t.Fatal("logout history", err)
		}
	}
	executor, err := sessionpg.NewCookieRevokeOneExecutor(f.pool, sessionpg.RevokeOneExecutorConfig{Execution: sessionpg.IssueExecutorConfig{Repository: config.Repository, Profile: sessionpg.IssueAdmissionConfig{GlobalAuthorityID: config.Profile.GlobalAuthorityID, PolicyNamespace: config.Profile.PolicyNamespace, Audience: config.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Coordinator: config.Coordinator, Authorization: config.Authorization, Clock: config.Clock, PolicyID: config.Flow.PolicyID, PolicyVersion: config.Flow.PolicyVersion, AuditRetentionVersion: 1}, Sessions: reader, Passkey: &sessionpg.PasskeySessionAdmission{Profile: config.Profile, Authority: authority}}, []session.CSRFKey{f.csrf})
	if err != nil {
		t.Fatal(err)
	}
	op := session.RevokeOneOperation()
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: commandID, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: spec.SessionID, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: config.Flow.PolicyID, PolicyVersion: config.Flow.PolicyVersion, CorrelationID: "passkey-journey"}
	command, err := session.NewRevokeOneCommand(binding, accepted.Session)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PrepareRevokeOneWithCSRF(accepted, command, wrong, f.csrf); err == nil {
		t.Fatal("foreign browser synchronizer admitted")
	}
	csrfWire, err := issued.CSRF.Reveal()
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
	if _, err := executor.ExecuteRevokeOne(f.ctx, request); !errors.Is(err, session.ErrCSRFDenied) {
		t.Fatal("cookie logout accepted legacy dispatch", err)
	}
	result, err := executor.ExecuteRevokeOneWithCSRF(f.ctx, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual passkey cookie logout", err, result.Outcome)
	}
	if got, err := reader.Get(f.ctx, input); err != nil || got.Authenticated {
		t.Fatal("logged-out passkey credential authenticated", err)
	}
	listing.AttemptID, _ = identity.NewCommandID()
	if page, err := inventory.List(f.ctx, listing); err == nil || len(page.Credentials) != 0 {
		t.Fatal("logged-out credential disclosed inventory")
	}
	var revocations, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE session_id=$1),(SELECT count(*) FROM audit.records WHERE action='identity.session.revoke' AND outcome=$2 AND subject_id=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='session.revoked.v1' AND convert_from(payload,'UTF8')::jsonb->>'subject_id'=$1)`, spec.SessionID, int64(audit.OutcomeSucceeded)).Scan(&revocations, &audits, &events); err != nil || revocations != 1 || audits != 1 || events != 1 {
		t.Fatal("logout required effects not coherent", err, revocations, audits, events)
	}
}

func passkeyJourneyReader(t *testing.T, f *signinFixture, issued SigninResult) (*session.SessionService, sessionpg.PasskeySessionServiceConfig, *SessionAuthority, session.GetRequest) {
	t.Helper()
	config := f.signin.config()
	authority, err := NewSessionAuthority(f.pool, SessionAuthorityConfig{TenantID: config.Protocol.TenantID, RPNamespace: config.Profile.RPNamespace, RPID: config.Protocol.RelyingParty.ID, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.PasskeySessionServiceConfig{Repository: config.Repository, Profile: config.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, Clock: config.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.lookup}}, Authority: authority}
	reader, err := sessionpg.NewPasskeySessionService(f.pool, profile)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return reader, profile, authority, session.GetRequest{TenantID: config.Protocol.TenantID, Credential: credential}
}

func TestIssuedPasskeySessionCannotAdoptWithdrawnOwners(t *testing.T) {
	for _, mode := range []string{"passkey", "factor", "credential", "user", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newSigninFixture(t)
			r, _ := f.pending(t)
			issued, err := f.signin.Signin(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			reader, _, _, input := passkeyJourneyReader(t, f, issued)
			if got, err := reader.Get(f.ctx, input); err != nil || !got.Authenticated {
				t.Fatal("original current passkey read", err)
			}
			sql := ""
			switch mode {
			case "passkey":
				sql = `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`
			case "factor":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1`
			case "credential":
				sql = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey'`
			case "user":
				sql = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "policy":
				sql = `UPDATE authorization_subject_authorities SET version=version+1`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal(err)
			}
			if got, err := reader.Get(f.ctx, input); err != nil || got.Authenticated {
				t.Fatal("withdrawn owner refreshed original authentication", err)
			}
		})
	}
}
