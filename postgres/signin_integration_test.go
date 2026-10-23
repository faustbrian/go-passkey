//go:build integration

package postgres

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func TestIdentifiedPasskeySigninCommitsActualSession(t *testing.T) {
	f := newSigninFixture(t)
	r, options := f.pending(t)
	if err := options.TransferJSON(f.ctx, func(context.Context, []byte) error { return nil }); err == nil {
		t.Fatal("challenge disclosed twice")
	}
	result, err := f.signin.Signin(f.ctx, r)
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
		t.Fatal("native signin", err, result.Session.CommitOutcome)
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.UserID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" || spec.Authentication.Proof.Method != "passkey" || spec.Authentication.Proof.Subject != string(spec.UserID) {
		t.Fatal("committed session provenance", err)
	}
	remember, err := spec.Remember.Bindings()
	if err != nil || remember.Choice != session.BrowserSession || result.Session.Cookie.MaxAge != 0 || !result.Session.Cookie.Expires.IsZero() {
		t.Fatal("original browser-only remember changed", err)
	}
	if _, err := result.CSRF.Reveal(); err != nil {
		t.Fatal("new committed CSRF unavailable", err)
	}
	wire, err := result.Session.Token.Reveal()
	if err != nil || wire == "" {
		t.Fatal("new committed bearer unavailable", err)
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(f.lookup, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := sessionpg.NewRepository(f.pool, f.signin.config().Repository)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repo.Lookup(f.ctx, spec.TenantID, digest)
	if err != nil {
		t.Fatal("actual native lookup failed", err)
	}
	_ = stored
	var sessions, protocol, consumed, audits, outbox int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id=$1),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.signin-verify'),(SELECT count(*) FROM public.outbox_messages WHERE topic='session.created.v1')`, spec.SessionID).Scan(&sessions, &protocol, &consumed, &audits, &outbox); err != nil || sessions != 1 || protocol != 1 || consumed != 1 || audits != 1 || outbox != 1 {
		t.Fatal("signin effects not coherent", err, sessions, protocol, consumed, audits, outbox)
	}
	var serviceActors, userActors int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies WHERE record->'Intent'->'Context'->>'ActorID'='signin-service' AND record->'Intent'->>'Kind'='get-discoverable'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify' AND actor_id=user_id)`).Scan(&serviceActors, &userActors); err != nil || serviceActors != 1 || userActors != 1 {
		t.Fatal("original service actor was replaced before verification", err, serviceActors, userActors)
	}
	ceremony, _ := options.Ceremony()
	var counted, decisions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM passkey_admission.durable_counter_attempts WHERE namespace='signin'),(SELECT count(*) FROM audit.records WHERE action='identity.risk.decide' AND convert_from(canonical_record,'UTF8')::jsonb->'attributes'->>'command.id' IN($1,$2))`, ceremony.ID, string(r.CommandID)).Scan(&counted, &decisions); err != nil || counted != 2 || decisions != 2 {
		t.Fatal("options and verification did not each count and audit actual Authentication admission", err, counted, decisions)
	}
	if replay, err := f.signin.Signin(f.ctx, r); err == nil || replay.Session.Token != (session.Token{}) {
		t.Fatal("assertion replay issued another bearer")
	}
	restarted, err := NewSigninService(f.pool, f.signin.config())
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-signin", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(spec.UserID), Kind: authorization.SubjectUser}, Tenant: authorization.TenantID(spec.TenantID), Action: authorization.Action(signinOperation(true).OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}}}
	query := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: signinOperation(true).OperationID, RecordID: spec.SessionID}
	recovered, err := restarted.RecoverSignin(f.ctx, query, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("restart recovery lost committed original", err)
	}
}

func TestIdentifiedPasskeySigninRejectsOriginalBrowserAndAuthorityChanges(t *testing.T) {
	for _, mode := range []string{"cookie", "origin", "other-flow", "signature", "factor-epoch", "factor-enrolled", "passkey-epoch", "user-epoch", "identifier-epoch", "credential-epoch", "mapping-revoked", "credential-disabled", "policy-epoch", "missing-context", "expired-ceremony"} {
		t.Run(mode, func(t *testing.T) {
			f := newSigninFixture(t)
			r, _ := f.pending(t)
			sql := ""
			switch mode {
			case "cookie":
				r.Cookie, _ = session.NewToken(32)
			case "origin":
				r.Origin = "https://foreign.example"
			case "other-flow":
				other := f.request(t, session.BrowserSession)
				r.FlowID, r.Cookie = other.FlowID, other.Cookie
			case "signature":
				r.Response = bytes.Replace(r.Response, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			case "factor-epoch":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1`
			case "factor-enrolled":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "passkey-epoch":
				sql = `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`
			case "user-epoch":
				sql = `UPDATE identity.users SET authority_version=authority_version+1`
			case "identifier-epoch":
				sql = `UPDATE identity.users SET identifier_version=identifier_version+1`
			case "credential-epoch":
				sql = `UPDATE identity.users SET credential_version=credential_version+1`
			case "mapping-revoked":
				sql = `UPDATE identity_passkey.credentials SET state='revoked'`
			case "credential-disabled":
				sql = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey'`
			case "policy-epoch":
				sql = `UPDATE authorization_subject_authorities SET version=version+1`
			case "missing-context":
				sql = `DELETE FROM identity_passkey.signin_contexts`
			case "expired-ceremony":
				sql = `WITH expired AS(SELECT date_trunc('microseconds',clock_timestamp()-interval '1 second') AS t) UPDATE webauthn.ceremonies SET expires_at=expired.t,record=jsonb_set(record,'{ExpiresAt}',to_jsonb(expired.t)) FROM expired WHERE kind='get-discoverable'`
			}
			if sql != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.signin.Signin(f.ctx, r)
			if err == nil || result.Session.Token != (session.Token{}) {
				t.Fatal("changed original state issued authentication")
			}
			var sessions, effects, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&sessions, &effects, &consumed); err != nil || sessions != 0 || effects != 0 || consumed != 0 {
				t.Fatal("denial retained provisional signin state", err, sessions, effects, consumed)
			}
		})
	}
}

func TestIdentifiedPasskeySigninRaceIssuesOneSession(t *testing.T) {
	f := newSigninFixture(t)
	r, _ := f.pending(t)
	var wg sync.WaitGroup
	success := make(chan SigninResult, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := f.signin.Signin(f.ctx, r)
			if err == nil {
				success <- result
			}
		}()
	}
	wg.Wait()
	close(success)
	count := 0
	for result := range success {
		count++
		if result.Session.Token == (session.Token{}) {
			t.Fatal("winner lacks bearer")
		}
	}
	if count != 1 {
		t.Fatal("assertion race winner count", count)
	}
	var n int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("assertion race session count", err, n)
	}
}

func TestIdentifiedPasskeySigninRequiredEffectFailureRollsBack(t *testing.T) {
	f := newSigninFixture(t)
	r, _ := f.pending(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_signin_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='session.created.v1' THEN RAISE EXCEPTION 'controlled failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_signin_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_signin_outbox()`); err != nil {
		t.Fatal(err)
	}
	if result, err := f.signin.Signin(f.ctx, r); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("failed required effect disclosed bearer")
	}
	var n int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&n); err != nil || n != 0 {
		t.Fatal("required-effect failure retained provisional effects", err, n)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_signin_outbox ON public.outbox_messages; DROP FUNCTION public.reject_signin_outbox()`); err != nil {
		t.Fatal(err)
	}
	// A rolled-back terminal command is historical; start a fresh command on
	// the unchanged original ceremony/flow, rather than claim replay can issue.
	r.CommandID, _ = identity.NewCommandID()
	ctx, stop := context.WithTimeout(f.ctx, 5*time.Second)
	defer stop()
	if result, err := f.signin.Signin(ctx, r); err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("rollback consumed original ceremony/flow", err)
	}
}
