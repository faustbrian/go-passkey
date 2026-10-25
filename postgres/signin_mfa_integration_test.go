//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	webauthn "github.com/faustbrian/go-webauthn"
)

// The raw authenticator is the existing cryptographic WebAuthn test seam. The
// retained confirmed-factor row is a controlled MFA-owner input for this native
// participant test, NOT evidence of actual TOTP activation or factor completion.
// Public-consumer acceptance separately enrolls/confirms TOTP through its owner.
func selectedSigninMFAFixture(t *testing.T, discovery bool) (*signinFixture, SigninMFAConfig) {
	t.Helper()
	f := newSigninFixtureFlagsProfile(t, 0x45, discovery)
	applyLast := func(source migrations.Source) {
		t.Helper()
		history, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	applyLast(kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 16})
	factors := mfapg.TOTPFactorMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}
	applyLast(factors)
	continuations := mfapg.ContinuationMigrationSource{Base: factors, Version: 3}
	applyLast(continuations)
	applyLast(mfapg.PasskeyContinuationMigrationSource{Base: continuations, Version: 4})
	files := issuerpg.Migrations()
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal(entry.Name(), err)
		}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(id))
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'01ARZ3NDEKTSV4RRFFQ69G5FAV','identity.mfa.enable',decode(repeat('01',32),'hex'),1,decode('01','hex'))`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'01ARZ3NDEKTSV4RRFFQ69G5FAV','identity.mfa.enable')`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE user_id='01ARZ3NDEKTSV4RRFFQ69G5FAW'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','01ARZ3NDEKTSV4RRFFQ69G5FAW',$1,2,1,1,'SHA1',6,30,0,'Example',decode('01','hex'),$2,'identity.mfa.enable',$3,$4,$3)`, string(id), raw, now, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	signing := bytes.Repeat([]byte{111}, 32)
	signer, err := capability.NewHMACSHA256Signer("passkey-mfa", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example", ID: "passkey-mfa", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"passkey-primary": bytes.Repeat([]byte{112}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	c := SigninMFAConfig{Lifetime: time.Minute, MaxAttempts: 5, IssuerURL: "https://identity.example", Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "passkey-fixture", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {113}}, PreparationTimeout: time.Second}, Custody: issuerpg.IssuancePreparationConfig{Deployment: "passkey-mfa", ActiveEnvelopeKey: "child", EnvelopeKeys: map[string][]byte{"child": bytes.Repeat([]byte{114}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "passkey-mfa", HMAC: signing}}, Clock: time.Now}, Envelope: crypto, EnvelopeKeyID: "passkey-primary"}
	f.signin, err = NewMFASigninService(f.pool, f.signin.config(), c)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func noMFAChallengeSession(t *testing.T, result SigninResult) {
	t.Helper()
	if result.Session.Token != (session.Token{}) || result.Session.Session != (session.Session{}) || result.CSRF != (session.CSRFToken{}) || result.Session.Cookie.Value != "" {
		t.Fatal("passkey primary disclosed a provisional session")
	}
}

func TestPasskeyMFAActualAssertionCreatesOnlyOriginalChallenge(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discovery], func(t *testing.T) {
			f, _ := selectedSigninMFAFixture(t, discovery)
			var result SigninResult
			var err error
			var command identity.CommandID
			var flowID identity.PreAuthTransactionID
			var retry func() (SigninResult, error)
			if discovery {
				r, _ := f.discoverablePending(t)
				command, flowID = r.CommandID, r.FlowID
				assertSigninMFARateReads(t, f, func() (passkey.CeremonyRateSource, error) {
					return f.signin.DiscoverableSigninRateSource(f.ctx, passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: r.DiscoverableSigninRequest, CeremonyID: r.CeremonyID})
				}, passkey.CeremonyRateSource{CeremonyID: r.CeremonyID, Lifetime: 5 * time.Minute, Kind: passkey.RateSourceAnonymousFlow, AnonymousFlowID: r.FlowID})
				retry = func() (SigninResult, error) { return f.signin.DiscoverableSignin(f.ctx, r) }
				result, err = f.signin.DiscoverableSignin(f.ctx, r)
			} else {
				r, _ := f.pending(t)
				command, flowID = r.CommandID, r.FlowID
				assertSigninMFARateReads(t, f, func() (passkey.CeremonyRateSource, error) {
					return f.signin.SigninRateSource(f.ctx, passkey.SigninCeremonyRateRequest{SigninRequest: r.SigninRequest, CeremonyID: r.CeremonyID})
				}, passkey.CeremonyRateSource{CeremonyID: r.CeremonyID, Lifetime: 5 * time.Minute, Kind: passkey.RateSourceIdentifier, Identifier: r.Identifier})
				retry = func() (SigninResult, error) { return f.signin.Signin(f.ctx, r) }
				result, err = f.signin.Signin(f.ctx, r)
			}
			if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Challenge == nil || result.Challenge.Proof == (capability.Proof{}) || result.Replayed {
				t.Fatal("verified primary did not commit a child", err, result.Receipt.Outcome)
			}
			noMFAChallengeSession(t, result)
			var sessions, children, effects, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM identity_mfa.continuations WHERE origin_purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&sessions, &children, &effects, &consumed); err != nil || sessions != 0 || children != 1 || effects != 1 || consumed != 0 {
				t.Fatal("challenge effects not atomic/sessionless", err, sessions, children, effects, consumed)
			}
			grant, origin, _, err := f.signin.mfa.issuer.ReadIssuanceOrigin(f.ctx, f.pool, result.Challenge.Proof, "identity.mfa.complete")
			if err != nil || origin != command {
				t.Fatal("child origin", err)
			}
			reader, err := mfapg.NewContinuationReader(f.pool, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			continuation, err := reader.Read(f.ctx, grant, f.signin.mfa.issuerURL)
			if err != nil {
				t.Fatal("durable continuation", err)
			}
			flow, err := sessionpg.ReadPreAuth(f.ctx, f.pool.Raw(), f.signin.config().Repository, f.signin.config().Protocol.TenantID, flowID)
			if err != nil {
				t.Fatal(err)
			}
			caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-signin", Request: authorization.Request{Tenant: authorization.TenantID(f.signin.config().Protocol.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, Action: "identity.mfa.complete", Resource: authorization.Resource{Type: "identity.user", ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}}}
			original, err := f.signin.ReadMFAPasskeyPrimary(f.ctx, result.Challenge.Proof, continuation, flow, caller)
			if err != nil || original.CommandID != command || original.Primary.Authentication.Proof.Purpose != session.PasskeyMFAPrimaryPurpose {
				t.Fatal("original primary recovery", err)
			}
			for range 2 {
				again, err := f.signin.ReadMFAPasskeyPrimary(f.ctx, result.Challenge.Proof, continuation, flow, caller)
				if err != nil || !again.Primary.Authentication.Proof.IssuedAt.Equal(original.Primary.Authentication.Proof.IssuedAt) || !again.Primary.Authentication.Proof.ExpiresAt.Equal(original.Primary.Authentication.Proof.ExpiresAt) || again.Primary.Authentication != original.Primary.Authentication {
					t.Fatal("recovery renewed original primary", err)
				}
			}
			remember, _ := original.Primary.Remember.Bindings()
			if remember.Choice != session.BrowserSession {
				t.Fatal("remember upgraded")
			}
			if replay, e := retry(); e == nil || replay.Challenge != nil && replay.Challenge.Proof != (capability.Proof{}) {
				t.Fatal("assertion replay disclosed another challenge credential")
			} else {
				noMFAChallengeSession(t, replay)
			}
			q := identity.RecoveryQuery{CommandID: command, TenantID: original.Primary.TenantID, UserID: original.Primary.UserID, ActorID: identity.ActorID(original.Primary.UserID), ActorKind: authorization.SubjectUser, OperationID: signinOperation(true).OperationID, RecordID: string(command)}
			recoveryCaller := caller.Clone()
			recoveryCaller.Request.Action = authorization.Action(q.OperationID)
			receipt, err := f.signin.RecoverSignin(f.ctx, q, recoveryCaller)
			if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("metadata recovery", err)
			}
		})
	}
}

func assertSigninMFARateReads(t *testing.T, f *signinFixture, read func() (passkey.CeremonyRateSource, error), want passkey.CeremonyRateSource) {
	t.Helper()
	before := rateAdmissionCount(t, f)
	for range 2 {
		source, err := read()
		if err != nil || source != want {
			t.Fatal("original selected-MFA rate metadata unavailable or disclosed eligibility", err)
		}
	}
	var sessions, children, effects, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM identity_mfa.continuations WHERE origin_purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&sessions, &children, &effects, &consumed); err != nil || sessions != 0 || children != 0 || effects != 0 || consumed != 0 || rateAdmissionCount(t, f) != before {
		t.Fatal("rate reads changed authentication or risk state", err, sessions, children, effects, consumed)
	}
}

func TestPasskeyMFARateSourceBindsSelectionWithoutEligibilityOracle(t *testing.T) {
	f, m := selectedSigninMFAFixture(t, false)
	for _, identifier := range []string{"passkey@example.test", "absent@example.test"} {
		t.Run(identifier, func(t *testing.T) {
			r := f.request(t, session.BrowserSession)
			r.Identifier = identifier
			options, err := f.signin.AuthenticationOptions(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			ceremony, _ := options.Ceremony()
			r.CommandID, _ = identity.NewCommandID()
			request := passkey.SigninCeremonyRateRequest{SigninRequest: r, CeremonyID: ceremony.ID}
			assertSigninMFARateReads(t, f, func() (passkey.CeremonyRateSource, error) {
				return f.signin.SigninRateSource(f.ctx, request)
			}, passkey.CeremonyRateSource{CeremonyID: ceremony.ID, Lifetime: 5 * time.Minute, Kind: passkey.RateSourceIdentifier, Identifier: identifier})
			for _, selected := range []bool{false, true} {
				var other *SigninService
				if selected {
					changed := m
					changed.MaxAttempts++
					other, err = NewMFASigninService(f.pool, f.signin.config(), changed)
				} else {
					other, err = NewSigninService(f.pool, f.signin.config())
				}
				if err != nil {
					t.Fatal(err)
				}
				source, err := other.SigninRateSource(f.ctx, request)
				requireNoRateSource(t, source, err)
			}
		})
	}
}

func TestPasskeyMFARejectsWrongAndChangedOriginals(t *testing.T) {
	for _, mode := range []string{"wrong signature", "cross browser", "changed factor", "pending TOTP", "changed key", "expired", "default profile", "changed selected profile"} {
		t.Run(mode, func(t *testing.T) {
			f, c := selectedSigninMFAFixture(t, false)
			r, _ := f.pending(t)
			switch mode {
			case "wrong signature":
				r.Response = bytes.Replace(r.Response, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			case "cross browser":
				r.Cookie, _ = session.NewToken(32)
			case "changed factor":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1`); err != nil {
					t.Fatal(err)
				}
			case "pending TOTP":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.totp_factors SET state=1,confirmed_at=NULL`); err != nil {
					t.Fatal(err)
				}
			case "changed key":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := f.pool.Raw().Exec(f.ctx, `WITH expired AS(SELECT date_trunc('microseconds',clock_timestamp()-interval '1 second') AS t) UPDATE webauthn.ceremonies SET expires_at=expired.t,record=jsonb_set(record,'{ExpiresAt}',to_jsonb(expired.t)) FROM expired WHERE kind='get-discoverable'`); err != nil {
					t.Fatal(err)
				}
			case "default profile":
				var err error
				f.signin, err = NewSigninService(f.pool, f.signin.config())
				if err != nil {
					t.Fatal(err)
				}
			case "changed selected profile":
				c.Lifetime = 2 * time.Minute
				var err error
				f.signin, err = NewMFASigninService(f.pool, f.signin.config(), c)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.signin.Signin(f.ctx, r)
			if err == nil || result.Challenge != nil {
				t.Fatal("changed primary created challenge")
			}
			noMFAChallengeSession(t, result)
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations)+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')`).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("denial retained effects", err, effects)
			}
		})
	}
}

type signinMFAUserPolicy struct {
	mode string
	seen authorization.DecisionContext
}

func (p *signinMFAUserPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Subject.Kind != authorization.SubjectUser {
		return (signinPolicy{}).Decide(ctx, c)
	}
	p.seen = c.Clone()
	if c.PolicyRevision != 1 || c.Request.Tenant != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || c.Request.Subject.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" || c.Request.Action != "identity.passkey.signin-verify" || c.Request.Resource.Type != "identity.user" || c.Request.Resource.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" {
		return authorization.Decision{}, errors.New("unexpected verified-user authorization scope")
	}
	switch p.mode {
	case "error":
		return authorization.Decision{}, errors.New("policy unavailable")
	case "wrong revision":
		return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
	default:
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	}
}

func TestPasskeyMFARequiresVerifiedUserAuthorization(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		for _, mode := range []string{"deny", "error", "wrong revision"} {
			t.Run(map[bool]string{false: "identified", true: "discoverable"}[discovery]+"/"+mode, func(t *testing.T) {
				f, m := selectedSigninMFAFixture(t, discovery)
				config := f.signin.config()
				policy := &signinMFAUserPolicy{mode: mode}
				config.Authorization = policy
				var err error
				f.signin, err = NewMFASigninService(f.pool, config, m)
				if err != nil {
					t.Fatal(err)
				}
				var result SigninResult
				if discovery {
					r, _ := f.discoverablePending(t)
					result, err = f.signin.DiscoverableSignin(f.ctx, r)
				} else {
					r, _ := f.pending(t)
					result, err = f.signin.Signin(f.ctx, r)
				}
				if err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted || result.Challenge != nil {
					t.Fatal("unauthorized verified user committed a challenge", err, result.Receipt.Outcome)
				}
				if policy.seen.PolicyRevision != 1 || policy.seen.Request.Tenant != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || policy.seen.Request.Subject.Kind != authorization.SubjectUser || policy.seen.Request.Subject.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" || policy.seen.Request.Action != "identity.passkey.signin-verify" || policy.seen.Request.Resource.Type != "identity.user" || policy.seen.Request.Resource.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" {
					t.Fatal("verified-user authorization did not retain exact signin scope")
				}
				noMFAChallengeSession(t, result)
				var effects int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations)+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM webauthn.ceremonies WHERE kind='get-discoverable' AND consumed_by IS NOT NULL)+(SELECT count(*) FROM capability_identity_one_use WHERE purpose='identity.mfa.complete')+(SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')+(SELECT count(*) FROM identity_passkey.credentials WHERE last_used_at IS NOT NULL)`).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("denied verified user retained assertion or authentication effects", err, effects)
				}
			})
		}
	}
}

func TestPasskeyMFAOriginalPrimaryRejectsForeignFlowAndChangedAuthorities(t *testing.T) {
	for _, mode := range []string{"another valid browser flow", "changed factor", "changed policy"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := selectedSigninMFAFixture(t, false)
			r, _ := f.pending(t)
			result, err := f.signin.Signin(f.ctx, r)
			if err != nil || result.Challenge == nil || result.Challenge.Proof == (capability.Proof{}) {
				t.Fatal("genuine assertion did not commit a child", err)
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
			flow, err := sessionpg.ReadPreAuth(f.ctx, f.pool.Raw(), f.signin.config().Repository, f.signin.config().Protocol.TenantID, r.FlowID)
			if err != nil {
				t.Fatal(err)
			}
			caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-signin", Request: authorization.Request{Tenant: authorization.TenantID(f.signin.config().Protocol.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, Action: "identity.mfa.complete", Resource: authorization.Resource{Type: "identity.user", ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}}}
			if original, err := f.signin.ReadMFAPasskeyPrimary(f.ctx, result.Challenge.Proof, continuation, flow, caller); err != nil || original.CommandID != r.CommandID {
				t.Fatal("valid original primary unavailable", err)
			}
			switch mode {
			case "another valid browser flow":
				other := f.request(t, session.BrowserSession)
				flow, err = sessionpg.ReadPreAuth(f.ctx, f.pool.Raw(), f.signin.config().Repository, f.signin.config().Protocol.TenantID, other.FlowID)
			case "changed factor":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1`)
			case "changed policy":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE authorization_subject_authorities SET version=version+1`)
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := f.signin.ReadMFAPasskeyPrimary(f.ctx, result.Challenge.Proof, continuation, flow, caller)
			if err == nil || !reflect.DeepEqual(out, MFAPasskeyPrimary{}) {
				t.Fatal("foreign browser or changed authority restored primary", err)
			}
			noMFAChallengeSession(t, result)
		})
	}
}

func TestPasskeyMFARequiredEffectFailureRollsBack(t *testing.T) {
	f, _ := selectedSigninMFAFixture(t, false)
	r, _ := f.pending(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_passkey_child() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='mfa.challenge.created.v1' THEN RAISE EXCEPTION 'controlled failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_passkey_child BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_passkey_child()`); err != nil {
		t.Fatal(err)
	}
	result, err := f.signin.Signin(f.ctx, r)
	if err == nil || result.Challenge != nil {
		t.Fatal("failed required effect disclosed child")
	}
	noMFAChallengeSession(t, result)
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations)+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')+(SELECT count(*) FROM capability_identity_one_use WHERE purpose='identity.mfa.complete')`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("rollback retained provisional effects", err, effects)
	}
}

func TestPasskeyMFARaceCommitsOneChallengeWithoutSession(t *testing.T) {
	f, _ := selectedSigninMFAFixture(t, false)
	r, _ := f.pending(t)
	// Separate parsed incoming cookies avoid using Token's shared reveal flag as
	// an accidental test-side serialization of real concurrent browser requests.
	wire, err := r.Cookie.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	winners := make(chan SigninResult, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := r
			request.Cookie, _ = session.ParseToken(wire)
			result, e := f.signin.Signin(f.ctx, request)
			if e == nil {
				winners <- result
			}
		}()
	}
	wg.Wait()
	close(winners)
	count := 0
	for result := range winners {
		count++
		noMFAChallengeSession(t, result)
		if result.Challenge == nil || result.Challenge.Proof == (capability.Proof{}) {
			t.Fatal("fresh winner lost original child")
		}
	}
	if count != 1 {
		t.Fatal("challenge race winner count", count)
	}
	var children, sessions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations),(SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a')`).Scan(&children, &sessions); err != nil || children != 1 || sessions != 0 {
		t.Fatal("race created duplicate child or session", err, children, sessions)
	}
}

// This controlled kernel-authority seam flips only the exact selected record
// after genuine signature verification and before native Work. Aggregate epochs
// remain unchanged to isolate the required exact-reference lock/check rather
// than letting a neighboring user-version guard conceal a missing key fence.
type disabledReferenceAssertionStore struct {
	*signinInvocation
	disabled bool
}

func (s *disabledReferenceAssertionStore) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	if _, err := s.service.pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(s.service.config().Protocol.TenantID), string(s.reference.UserID), string(s.reference.ID)); err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	s.disabled = true
	return s.signinInvocation.FinalizeAssertion(ctx, input)
}

func TestPasskeyMFARejectsExactCredentialDisabledAfterVerifiedSelection(t *testing.T) {
	f, _ := selectedSigninMFAFixture(t, false)
	r, _ := f.pending(t)
	p, err := f.signin.prepare(f.ctx, r.SigninRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	id, err := signinResponseCredentialID(r.Response)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.selectCredential(f.ctx, id); err != nil {
		t.Fatal(err)
	}
	p.ceremonyID = r.CeremonyID
	if err := p.readContext(f.ctx); err != nil {
		t.Fatal(err)
	}
	store := &disabledReferenceAssertionStore{signinInvocation: p}
	protocol, err := webauthn.NewDiscoverable(f.signin.config().Protocol, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	_, err = protocol.VerifyDiscoverableAssertion(f.ctx, webauthn.VerifyDiscoverableAssertionRequest{Context: p.ceremonyContext(), CeremonyID: r.CeremonyID, Origin: r.Origin, Response: r.Response, ExpectedVersion: 1})
	if !store.disabled {
		t.Fatal("test did not reach verified assertion/native authority boundary")
	}
	if err == nil || p.output.Challenge != nil {
		t.Fatal("disabled authenticating reference committed a challenge")
	}
	noMFAChallengeSession(t, p.output)
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations)+(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify')`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("exact-key denial retained provisional effects", err, effects)
	}
}

func TestPasskeyMFARecoversActualCommitDisconnectThroughOwnedScope(t *testing.T) {
	for _, mode := range []string{"before commit", "after commit", "mismatched original browser"} {
		t.Run(mode, func(t *testing.T) {
			f, m := selectedSigninMFAFixture(t, false)
			completion, _ := f.pending(t)
			fault := &enrollmentCommitFault{before: mode == "before commit", marker: "UPDATE identity_passkey.credentials SET last_used_at"}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal("fault pool unavailable", err)
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if pool.Close(ctx) != nil {
					t.Error("fault pool cleanup failed")
				}
			}()
			config := f.signin.config()
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			interrupted, err := NewMFASigninService(pool, config, m)
			if err != nil {
				t.Fatal(err)
			}
			result, err := interrupted.Signin(f.ctx, completion)
			if err == nil || !fault.hit.Load() || result.Receipt.Outcome != identity.CommitOutcomeUnknown || result.Challenge != nil && result.Challenge.Proof != (capability.Proof{}) {
				t.Fatal("lost COMMIT acknowledgment disclosed challenge or lost ambiguity", err, result.Receipt.Outcome)
			}
			noMFAChallengeSession(t, result)
			if mode == "mismatched original browser" {
				// Controlled retained-row corruption after an actual commit: the
				// digest and child still match, but the MFA-owned source does not.
				// A final historical receipt remains metadata, not permission to
				// restore a child credential or current authentication authority.
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.continuations SET source_preauth_id='AgICAgICAgICAgICAgICAg'`); err != nil {
					t.Fatal(err)
				}
			}
			restarted, err := NewMFASigninService(f.pool, config, m)
			if err != nil {
				t.Fatal(err)
			}
			q := identity.RecoveryQuery{CommandID: completion.CommandID, TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorKind: authorization.SubjectUser, OperationID: signinOperation(true).OperationID, RecordID: string(completion.CommandID)}
			caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "passkey-signin", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.UserID), Kind: authorization.SubjectUser}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
			// The actual interrupted command retains its original half-second
			// coordinator lease. Let it lapse before exercising RecoveryWork.
			timer := time.NewTimer(600 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			case <-timer.C:
			}
			recovered, err := restarted.RecoverSignin(f.ctx, q, caller)
			want, count := identity.CommitOutcomeCommitted, 1
			if mode == "before commit" {
				want, count = identity.CommitOutcomeNotCommitted, 0
			}
			if recovered.Outcome != want || recovered.Binding.CommandID != q.CommandID || recovered.Validate() != nil || mode != "before commit" && err != nil {
				t.Fatal("recovery did not reconcile exact retained original", err, recovered.Outcome, want)
			}
			var sessions, children, effects, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE session_id<>'session-a'),(SELECT count(*) FROM identity_mfa.continuations),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.signin-verify'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&sessions, &children, &effects, &consumed); err != nil || sessions != 0 || children != count || effects != count || consumed != 0 {
				t.Fatal("recovery split challenge owners or created authentication", err, sessions, children, effects, consumed)
			}
			if replay, err := restarted.Signin(f.ctx, completion); err == nil || replay.Challenge != nil && replay.Challenge.Proof != (capability.Proof{}) {
				t.Fatal("recovery reconstructed challenge credential")
			} else {
				noMFAChallengeSession(t, replay)
			}
		})
	}
}
