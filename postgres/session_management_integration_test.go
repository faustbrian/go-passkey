//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

type sessionManagementTestFixture struct {
	*signinFixture
	manager   *SessionManagementService
	inventory *InventoryService
	listing   InventoryRequest
	request   passkey.SessionUpdateRequest
	issued    SigninResult
}

func newSessionManagementTestFixture(t *testing.T) *sessionManagementTestFixture {
	t.Helper()
	f := newSigninFixture(t)
	c := f.signin.config()
	signin, _ := f.pending(t)
	issued, err := f.signin.Signin(f.ctx, signin)
	if err != nil {
		t.Fatal("actual passkey session", err)
	}
	spec, err := issued.Session.Session.Bindings()
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
	// Retain the actual transported token for the subsequent consumer journey;
	// the issuer's reveal-once object was already consumed above.
	issued.Session.Token = token
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: c.Profile.Audience, Clock: c.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.lookup}}
	manager, err := NewSessionManagementService(f.pool, SessionManagementConfig{Protocol: c.Protocol, Profile: c.Profile, Validation: validation, SessionRepository: c.Repository, OptionsRequests: keyedFixtureConfig(t, f.enrollmentFixture, *c.Coordinator.QueryPolicy), Coordinator: c.Coordinator, Authorization: c.Authorization, Clock: c.Clock, Transport: session.CredentialBearer, Risk: f.service.config().Risk, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion})
	if err != nil {
		t.Fatal("actual session-bound manager", err)
	}
	reader, err := NewSessionAuthority(f.pool, SessionAuthorityConfig{TenantID: spec.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	passkeyReader := sessionpg.PasskeySessionServiceConfig{Repository: c.Repository, Profile: c.Profile, Validation: validation, Authority: reader}
	inventory, err := NewInventoryService(f.pool, InventoryConfig{TenantID: spec.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, Passkey: &passkeyReader, Protocol: webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion}, Authorization: c.Authorization, PolicyVersion: c.Flow.PolicyVersion, Rate: &f.counters, MaximumDuration: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(c.Flow.PolicyVersion), CorrelationID: "inline-session-rename", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Tenant: authorization.TenantID(spec.TenantID), Action: "identity.passkey.list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}}}
	attempt, _ := identity.NewCommandID()
	listing := InventoryRequest{Credential: credential, Caller: caller, AttemptID: attempt, Limit: 10}
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal("actual passkey inventory", err)
	}
	caller.Request.Action = "identity.passkey.update"
	r := passkey.SessionUpdateRequest{Credential: credential, Caller: caller, ReferenceID: identity.CredentialID(page.Credentials[0].ReferenceID), ExpectedVersion: page.Credentials[0].Version, Name: "Fresh passkey rename", Origin: c.Flow.Origin, Network: "127.0.0.1"}
	return &sessionManagementTestFixture{signinFixture: f, manager: manager, inventory: inventory, listing: listing, request: r, issued: issued}
}

func (f *sessionManagementTestFixture) completion(t *testing.T) passkey.SessionUpdateCompletion {
	t.Helper()
	options, err := f.manager.UpdateOptions(f.ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: f.request, IdempotencyKey: optionsKey(t, "inline-session-rename-options")})
	if err != nil {
		t.Fatal("action-bound fresh assertion options", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("genuine ceremony withheld")
	}
	challenge := signinChallenge(t, f.ctx, options.Options.TransferJSON)
	return passkey.SessionUpdateCompletion{SessionUpdateRequest: f.request, IdempotencyKey: optionsKey(t, "inline-session-rename-completion"), CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 2)}
}

func TestPasskeySessionAssertionRenamesWithoutPasswordProof(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	r := f.request
	completion := f.completion(t)
	out, err := f.manager.Update(f.ctx, completion)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Credential == nil || out.Credential.Label != r.Name || out.Credential.Version != r.ExpectedVersion+1 {
		t.Fatal("fresh UV assertion did not atomically rename", err)
	}
	retry, err := f.manager.Update(f.ctx, completion)
	if err != nil || !retry.Replayed || retry.CommandID != out.CommandID || retry.Credential != nil || retry.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original mutation retry repeated proof or lost metadata-only outcome", err)
	}
	f.listing.AttemptID, _ = identity.NewCommandID()
	page, err := f.inventory.List(f.ctx, f.listing)
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != r.Name || page.Credentials[0].Version != r.ExpectedVersion+1 {
		t.Fatal("renamed inventory unavailable to original passkey session", err)
	}
	// Use the original real session through read/logout, then prove the renamed
	// authenticator still signs in and serves another actual read/logout journey.
	passkeyJourneyReadInventoryLogout(t, f.signinFixture, f.issued, r.Name)
	next := f.signinFixture.request(t, session.BrowserSession)
	options, err := f.signin.AuthenticationOptions(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("fresh signin ceremony absent")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	next.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: next, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 3)})
	if err != nil {
		t.Fatal("renamed credential no longer signs in", err)
	}
	passkeyJourneyReadInventoryLogout(t, f.signinFixture, issued, r.Name)
}

func TestPasskeySessionUpdateRejectsChangedIntentAndCustody(t *testing.T) {
	for _, mode := range []string{"name", "version", "target", "origin", "network", "actor", "tenant", "resource", "action", "session", "csrf", "signature", "ceremony", "response"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionManagementTestFixture(t)
			original := f.completion(t)
			r := original
			r.IdempotencyKey = optionsKey(t, "substitution-"+mode)
			r.Caller = original.Caller.Clone()
			switch mode {
			case "name":
				r.Name = "Substituted intention"
			case "version":
				r.ExpectedVersion++
			case "target":
				r.ReferenceID = "another-credential"
			case "origin":
				r.Origin = "https://foreign.example"
			case "network":
				r.Network = "192.0.2.99"
			case "actor":
				r.Caller.Request.Subject.ID = "another-user"
			case "tenant":
				r.Caller.Request.Tenant = "another-tenant"
			case "resource":
				r.Caller.Request.Resource.ID = "another-user"
			case "action":
				r.Caller.Request.Action = "identity.passkey.revoke"
			case "session":
				token, err := session.NewToken(32)
				if err != nil {
					t.Fatal(err)
				}
				r.Credential, err = session.NewCredential(session.CredentialBearer, token)
				if err != nil {
					t.Fatal(err)
				}
			case "csrf":
				var err error
				r.CSRFToken, err = session.NewCSRFToken()
				if err != nil {
					t.Fatal(err)
				}
			case "signature":
				r.Response = bytes.Replace(r.Response, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			case "ceremony":
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				r.CeremonyID = string(id)
			case "response":
				r.Response = nil
			}
			if out, err := f.manager.Update(f.ctx, r); err == nil || out.Credential != nil {
				t.Fatal("changed original request mutated metadata", err)
			}
			f.unchanged(t)
			if out, err := f.manager.Update(f.ctx, original); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("rejected substitution consumed original proof", err)
			}
		})
	}
}

func (f *sessionManagementTestFixture) unchanged(t *testing.T) {
	t.Helper()
	var version string
	var audits, events, protocol int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$1`, string(f.request.ReferenceID)).Scan(&version); err != nil || version != "1" {
		t.Fatal("denial changed metadata", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential'),(SELECT count(*) FROM webauthn.effects WHERE purpose='identity.passkey.update' AND after_credential IS NOT NULL)`, int64(audit.OutcomeSucceeded)).Scan(&audits, &events, &protocol); err != nil || audits != 0 || events != 0 || protocol != 0 {
		t.Fatal("denial leaked committed rename effects", err, audits, events, protocol)
	}
}

func TestPasskeySessionUpdateRejectsWithdrawnOwnersAndExpiredAssertion(t *testing.T) {
	for _, mode := range []string{"session", "user", "credential", "mapping", "factor", "missing-factor", "passkey-epoch", "policy", "context", "expired", "uv", "counter"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionManagementTestFixture(t)
			r := f.completion(t)
			sql := ""
			switch mode {
			case "session":
				sql = `UPDATE session_store.sessions SET state='revoked'`
			case "user":
				sql = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "credential":
				sql = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey'`
			case "mapping":
				sql = `UPDATE identity_passkey.credentials SET state='revoked'`
			case "factor":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "missing-factor":
				sql = `DELETE FROM identity_mfa.factor_authorities`
			case "passkey-epoch":
				sql = `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`
			case "policy":
				sql = `UPDATE authorization_subject_authorities SET version=version+1`
			case "context":
				sql = `DELETE FROM identity_passkey.signin_contexts`
			case "expired":
				sql = `WITH expired AS(SELECT date_trunc('microseconds',clock_timestamp()-interval '1 second') AS t) UPDATE webauthn.ceremonies SET expires_at=expired.t,record=jsonb_set(record,'{ExpiresAt}',to_jsonb(expired.t)) FROM expired WHERE ceremony_id=$1`
			case "uv", "counter":
				// Reconstruct the controlled authenticator response with valid
				// signature but a missing UV flag or regressed positive counter.
				challenge := assertionResponseChallenge(t, r.Response)
				count := uint32(0)
				if mode == "uv" {
					f.assertionFlags = 0x01
					count = 2
				}
				r.Response = f.assertion(t, challenge, count)
			}
			if sql != "" {
				var err error
				if mode == "expired" {
					_, err = f.pool.Raw().Exec(f.ctx, sql, r.CeremonyID)
				} else {
					_, err = f.pool.Raw().Exec(f.ctx, sql)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if out, err := f.manager.Update(f.ctx, r); err == nil || out.Credential != nil {
				t.Fatal("withdrawn authority/invalid assertion renamed credential", err)
			}
			f.unchanged(t)
		})
	}
}

func assertionResponseChallenge(t *testing.T, response []byte) string {
	t.Helper()
	var envelope struct {
		Response struct {
			Client string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil {
		t.Fatal(err)
	}
	client, err := base64.RawURLEncoding.DecodeString(envelope.Response.Client)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(client, &data); err != nil || data.Challenge == "" {
		t.Fatal("authenticator challenge absent", err)
	}
	return data.Challenge
}

func TestPasskeySessionUpdateOptionsRetryNeverRevealsAnotherChallenge(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	r := f.completion(t)
	original := passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: f.request, IdempotencyKey: optionsKey(t, "inline-session-rename-options")}
	out, err := f.manager.UpdateOptions(f.ctx, original)
	if err != nil || !out.Replayed || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("options retry lost committed original", err)
	}
	if _, ok := out.Options.Ceremony(); ok {
		t.Fatal("options retry renewed ceremony")
	}
	if err := out.Options.TransferJSON(f.ctx, func(context.Context, []byte) error { t.Fatal("options retry disclosed challenge"); return nil }); err == nil {
		t.Fatal("options retry exported options")
	}
	changed := original
	changed.Name = "Changed original intent"
	if out, err := f.manager.UpdateOptions(f.ctx, changed); err == nil || out.CommandID != "" {
		t.Fatal("same options key admitted changed intent")
	}
	collision := r
	collision.IdempotencyKey = original.IdempotencyKey
	if out, err := f.manager.Update(f.ctx, collision); err == nil || out.Credential != nil {
		t.Fatal("options key became a completion key")
	}
	if out, err := f.manager.Update(f.ctx, r); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("key conflict consumed genuine assertion", err)
	}
	changedCompletion := r
	changedCompletion.Name = "Rewritten committed intent"
	if out, err := f.manager.Update(f.ctx, changedCompletion); err == nil || out.Credential != nil {
		t.Fatal("committed key accepted changed completion")
	}
	consumed := r
	consumed.IdempotencyKey = optionsKey(t, "consumed-original-assertion")
	consumed.ExpectedVersion++
	if out, err := f.manager.Update(f.ctx, consumed); err == nil || out.Credential != nil {
		t.Fatal("new key renewed consumed ceremony")
	}
}

func TestPasskeySessionUpdateCookieRequiresOriginalCSRF(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	config := f.manager.config()
	config.Transport = session.CredentialCookie
	config.CSRFKeys = []session.CSRFKey{f.csrf}
	manager, err := NewSessionManagementService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	f.manager = manager
	f.request.Credential, err = session.NewCredential(session.CredentialCookie, f.issued.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := f.issued.CSRF.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	f.request.CSRFToken, err = session.ParseCSRFToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	wrong := f.request
	wrong.CSRFToken, err = session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := manager.UpdateOptions(f.ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: wrong, IdempotencyKey: optionsKey(t, "wrong-cookie-options")}); err == nil || out.CommandID != "" {
		t.Fatal("foreign cookie synchronizer admitted options")
	}
	r := f.completion(t)
	bad := r
	bad.CSRFToken = wrong.CSRFToken
	if out, err := manager.Update(f.ctx, bad); err == nil || out.Credential != nil {
		t.Fatal("foreign cookie synchronizer renamed credential")
	}
	if out, err := manager.Update(f.ctx, r); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine original cookie/CSRF assertion denied", err)
	}
}

func TestPasskeySessionUpdateAssertionCannotMoveToSiblingSession(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	next := f.signinFixture.request(t, session.BrowserSession)
	options, err := f.signin.AuthenticationOptions(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("sibling signin ceremony missing")
	}
	challenge := signinChallenge(t, f.ctx, options.TransferJSON)
	next.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := f.signin.Signin(f.ctx, SigninCompletion{SigninRequest: next, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, 2)})
	if err != nil {
		t.Fatal("actual sibling passkey session", err)
	}
	wire, err := sibling.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	original := f.completion(t)
	original.Response = f.assertion(t, assertionResponseChallenge(t, original.Response), 3)
	stolen := original
	stolen.Credential = credential
	stolen.IdempotencyKey = optionsKey(t, "sibling-session-substitution")
	if out, err := f.manager.Update(f.ctx, stolen); err == nil || out.Credential != nil {
		t.Fatal("genuine sibling session borrowed original assertion")
	}
	f.unchanged(t)
	if out, err := f.manager.Update(f.ctx, original); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("sibling denial consumed original action proof", err)
	}
}

func TestPasskeySessionUpdateRecoversActualCommitDisconnect(t *testing.T) {
	for _, finish := range []bool{false, true} {
		for _, before := range []bool{true, false} {
			t.Run(map[bool]string{true: "completion/", false: "options/"}[finish]+map[bool]string{true: "before-commit", false: "after-commit"}[before], func(t *testing.T) {
				f := newSessionManagementTestFixture(t)
				r := passkey.SessionUpdateCompletion{SessionUpdateRequest: f.request, IdempotencyKey: optionsKey(t, "inline-session-rename-options")}
				marker := "INSERT INTO identity_passkey.signin_contexts"
				if finish {
					r = f.completion(t)
					marker = "UPDATE identity_passkey.credentials SET display_label"
				}
				call := func(s *SessionManagementService, ctx context.Context) (passkey.UpdateResult, error) {
					if finish {
						return s.Update(ctx, r)
					}
					out, err := s.UpdateOptions(ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: r.SessionUpdateRequest, IdempotencyKey: r.IdempotencyKey})
					if _, ok := out.Options.Ceremony(); ok {
						t.Fatal("ambiguous/recovered options disclosed ceremony")
					}
					return passkey.UpdateResult{CommandID: out.CommandID, Receipt: out.Receipt, Replayed: out.Replayed, Outcome: out.Receipt.Outcome}, err
				}
				fault := &enrollmentCommitFault{before: before, marker: marker}
				pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := pool.Close(ctx); err != nil {
						t.Error(err)
					}
				}()
				config := f.manager.config()
				config.Coordinator.LeaseDuration = 500 * time.Millisecond
				interrupted, err := NewSessionManagementService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
				out, err := call(interrupted, f.ctx)
				if !fault.hit.Load() || out.CommandID == "" || out.Credential != nil || err == nil && (!out.Replayed || out.Outcome != identity.CommitOutcomeCommitted) {
					t.Fatal("lost COMMIT acknowledgement exposed fresh success", err)
				}
				restarted, err := NewSessionManagementService(f.pool, config)
				if err != nil {
					t.Fatal(err)
				}
				want := identity.CommitOutcomeCommitted
				if before {
					want = identity.CommitOutcomeNotCommitted
				}
				ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
				defer stop()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					recovered, err := call(restarted, ctx)
					if recovered.Outcome == want {
						if recovered.CommandID != out.CommandID || !recovered.Replayed || recovered.Credential != nil || recovered.Receipt.Validate() != nil || !before && err != nil {
							t.Fatal("recovery lost original metadata-only outcome", err)
						}
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("original assertion update did not reconcile", err)
					case <-ticker.C:
					}
				}
				if before || !finish {
					f.unchanged(t)
				} else {
					var label, version string
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT display_label,metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$1`, string(r.ReferenceID)).Scan(&label, &version); err != nil || label != r.Name || version != "2" {
						t.Fatal("commit recovery split rename", err)
					}
				}
			})
		}
	}
}

func TestPasskeySessionUpdateRequiredEffectsRollbackAndSameKeyRace(t *testing.T) {
	for _, mode := range []string{"rollback", "race"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionManagementTestFixture(t)
			r := f.completion(t)
			if mode == "rollback" {
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_inline_rename() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='identity.passkey.rename_credential' THEN RAISE EXCEPTION 'controlled failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_inline_rename BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_inline_rename()`); err != nil {
					t.Fatal(err)
				}
				if out, err := f.manager.Update(f.ctx, r); err == nil || out.Credential != nil {
					t.Fatal("required effect failure disclosed committed rename")
				}
				f.unchanged(t)
				return
			}
			var wg sync.WaitGroup
			results := make([]passkey.UpdateResult, 2)
			failures := make([]error, 2)
			start := make(chan struct{})
			for i := range results {
				wg.Add(1)
				go func(i int) { defer wg.Done(); <-start; results[i], failures[i] = f.manager.Update(f.ctx, r) }(i)
			}
			close(start)
			wg.Wait()
			fresh := 0
			for i, out := range results {
				if failures[i] == nil && out.Outcome == identity.CommitOutcomeCommitted && !out.Replayed {
					fresh++
					if out.Credential == nil {
						t.Fatal("winner lost metadata")
					}
				}
			}
			if fresh != 1 {
				t.Fatal("same-key assertion did not have exactly one winner", fresh)
			}
			out, err := f.manager.Update(f.ctx, r)
			if err != nil || !out.Replayed || out.Credential != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("race lost original metadata-only outcome", err)
			}
		})
	}
}
