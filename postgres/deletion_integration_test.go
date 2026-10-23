//go:build integration

package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
)

// This exposes only the real native preparation/execution boundary so current
// owners can advance deterministically between them; all key/proof/Work owners
// remain genuine. The complete public Delete path is exercised separately.
func preparedDeletion(t *testing.T, s *DeletionService, ctx context.Context, r passkey.DeleteRequest) (*deletionInvocation, *kernel.Coordinator, *kernel.ContributorRegistry) {
	t.Helper()
	c := s.config()
	_, spec, err := s.readers.authenticatePrimary(ctx, r.Primary, deletionOperation())
	if err != nil {
		t.Fatal(err)
	}
	fields, err := c.Recovery.Fields()
	if err != nil {
		t.Fatal(err)
	}
	intent, err := s.readers.managementRequestIntent(r.Primary, r.ReferenceID, r.ExpectedVersion, r.Network, fields)
	if err != nil {
		t.Fatal(err)
	}
	p := &deletionInvocation{service: s, request: r, record: spec}
	coordinator, registry, err := s.runtime(p)
	if err != nil {
		t.Fatal(err)
	}
	scope := kernel.RequestKeyScope{TenantID: c.TenantID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: deletionOperation().OperationID}
	key, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, optionsRequestCaller(r.Primary.Caller, scope, c.RequestKeys.Policy.PolicyVersion))
	if err != nil {
		t.Fatal(err)
	}
	p.request.Primary.CommandID, p.request.Primary.RecordID = key.CommandID, string(r.ReferenceID)
	p.request.Primary.Caller.CorrelationID = string(key.CommandID)
	if err := p.prepare(ctx); err != nil {
		t.Fatal(err)
	}
	return p, coordinator, registry
}

func TestKeyedPasskeyDeleteRejectsCurrentOwnerAdvancesAfterPreparation(t *testing.T) {
	for _, mode := range []string{"factor-generation", "protocol-assertion", "metadata-rename"} {
		t.Run(mode, func(t *testing.T) {
			f := newSigninFixture(t)
			removal, rename, inventory, listing := deletionFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "advance-after-prepare-"+mode)
			p, coordinator, registry := preparedDeletion(t, removal, f.ctx, r)
			switch mode {
			case "factor-generation":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1`); err != nil {
					t.Fatal(err)
				}
			case "protocol-assertion":
				completion, _ := f.pending(t)
				if _, err := f.signin.Signin(f.ctx, completion); err != nil {
					t.Fatal("actual intervening signed assertion", err)
				}
			case "metadata-rename":
				if out, err := rename.Update(f.ctx, managementRequest(t, f.enrollmentFixture, page.Credentials[0], "intervening-rename", "Newer metadata")); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(err)
				}
			}
			if out, err := p.execute(f.ctx, coordinator, registry); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("prepared removal adopted advanced current owner")
			}
			var consumed, erased, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM webauthn.credentials WHERE record->'PublicKey'='null'::jsonb),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential')`, string(r.Primary.Proof.Proof.ID)).Scan(&consumed, &erased, &events); err != nil || consumed != 0 || erased != 0 || events != 0 {
				t.Fatal("current-owner conflict left partial removal", err)
			}
		})
	}
}

func addDeletionFixturePasskey(t *testing.T, f *enrollmentFixture) {
	t.Helper()
	options, err := f.service.RegistrationOptions(f.ctx, f.request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("second actual enrollment ceremony absent")
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
	if _, err := f.service.Register(f.ctx, RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, id, challenge), Label: "Independent passkey"}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyedPasskeyDeletePreservesLivePaginationAndRequiresActualRecovery(t *testing.T) {
	for _, recovery := range []bool{true, false} {
		t.Run(map[bool]string{true: "live-next-page", false: "another-passkey-is-not-recovery"}[recovery], func(t *testing.T) {
			f := newSigninFixture(t)
			removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
			addDeletionFixturePasskey(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 2 {
				t.Fatal("two genuine passkeys unavailable", err)
			}
			r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "delete-first-page")
			if !recovery {
				if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity.identifiers WHERE kind='email'`); err != nil {
					t.Fatal(err)
				}
				if out, err := removal.Delete(f.ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("another passkey substituted for configured usable recovery")
				}
				var active int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_passkey.credentials WHERE state='active'`).Scan(&active); err != nil || active != 2 {
					t.Fatal("last-recovery denial removed a credential", err)
				}
				return
			}
			if out, err := removal.Delete(f.ctx, r); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
			listing.Limit = 1
			listing.AttemptID, _ = identity.NewCommandID()
			after, err := inventory.List(f.ctx, listing)
			if err != nil || len(after.Credentials) != 1 || after.Credentials[0].ReferenceID != page.Credentials[1].ReferenceID || after.Next != "" {
				t.Fatal("revoked leading tombstone starved live bounded page", err)
			}
		})
	}
}

func TestKeyedPasskeyDeleteSameKeyContentionHasOneOriginalEffect(t *testing.T) {
	f := newSigninFixture(t)
	removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "same-key-delete-contention")
	results, failures := make([]passkey.DeleteResult, 2), make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	for i := range results {
		go func(i int) { defer wg.Done(); <-start; results[i], failures[i] = removal.Delete(f.ctx, r) }(i)
	}
	close(start)
	wg.Wait()
	var command identity.CommandID
	fresh := 0
	for i, out := range results {
		if failures[i] == nil && out.Outcome == identity.CommitOutcomeCommitted && !out.Replayed {
			fresh++
			command = out.CommandID
		}
	}
	if fresh != 1 || command == "" {
		t.Fatal("contention did not produce exactly one fresh removal")
	}
	for _, out := range results {
		if out.CommandID != "" && out.CommandID != command {
			t.Fatal("one key allocated competing deletion identities")
		}
	}
	replay, err := removal.Delete(f.ctx, r)
	if err != nil || replay.CommandID != command || !replay.Replayed || replay.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("contention lost original metadata-only outcome", err)
	}
	var events, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_purpose='identity.passkey.delete')`).Scan(&events, &consumed); err != nil || events != 1 || consumed != 1 {
		t.Fatal("contention repeated removal/proof/effects", err)
	}
}

func TestKeyedPasskeyDeleteMutationQuotaRetainsOriginalDeniedOutcome(t *testing.T) {
	f := newSigninFixture(t)
	removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "delete-quota-original")
	var originalCharges int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM passkey_risk.counter_charges WHERE operation='identity.passkey.delete'`).Scan(&originalCharges); err != nil || originalCharges != 0 {
		t.Fatal("fresh deletion operation already charged", err)
	}
	// The coordinator commits each genuine mutation reservation before domain
	// work. Required-effect failure rolls back proof/removal, not its charge.
	// Reuse the still-current signed proof across five distinct original keys;
	// never reset counters, change policy or fabricate additional credentials.
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.fail_delete_quota_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='identity.passkey.remove_credential' THEN RAISE EXCEPTION 'required removal effect unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_delete_quota_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.fail_delete_quota_effect()`); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		attemptRequest := r
		attemptRequest.IdempotencyKey = optionsKey(t, fmt.Sprintf("delete-quota-effect-failure-%d", attempt))
		out, err := removal.Delete(f.ctx, attemptRequest)
		if err == nil || out.CommandID == "" || out.Outcome != identity.CommitOutcomeNotCommitted || out.Receipt.Validate() != nil {
			t.Fatal("required-effect failure did not retain genuine noncommit", attempt, err)
		}
	}
	// The sixth call has usable recovery, the same unconsumed current proof and
	// working required effects. Only the unchanged actual mutation limit denies.
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_delete_quota_effect ON public.outbox_messages; DROP FUNCTION public.fail_delete_quota_effect()`); err != nil {
		t.Fatal(err)
	}
	denied, err := removal.Delete(f.ctx, r)
	if err == nil || denied.CommandID == "" || denied.Outcome != identity.CommitOutcomeNotCommitted || denied.Receipt.Validate() != nil {
		t.Fatal("sixth deletion did not retain actual quota-denied noncommit", err)
	}
	assertUnchanged := func() {
		t.Helper()
		var state, version, reference, metadata, authority string
		var enabled bool
		var consumed, erased, succeeded, events, quotaDenied int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT m.state,m.version::text,c.version::text,c.enabled,m.metadata_version::text,h.authority_version::text,(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$2 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM webauthn.credentials WHERE record->'PublicKey'='null'::jsonb),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.remove_credential' AND outcome=$3),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.remove_credential' AND outcome=$4 AND convert_from(canonical_record,'UTF8')::jsonb->'attributes'->>'command.id'=$5) FROM identity_passkey.credentials m JOIN identity.credential_references c ON c.tenant_id=m.tenant_id AND c.user_id=m.user_id AND c.credential_id=m.reference_id JOIN identity_passkey.user_handles h ON h.rp_namespace=m.rp_namespace AND h.tenant_id=m.tenant_id AND h.user_id=m.user_id WHERE m.reference_id=$1`, string(r.ReferenceID), string(r.Primary.Proof.Proof.ID), int16(audit.OutcomeSucceeded), int16(audit.OutcomeDenied), string(denied.CommandID)).Scan(&state, &version, &reference, &enabled, &metadata, &authority, &consumed, &erased, &succeeded, &events, &quotaDenied); err != nil || state != "active" || version != "1" || reference != "1" || !enabled || metadata != "1" || authority != "1" || consumed != 0 || erased != 0 || succeeded != 0 || events != 0 || quotaDenied != 1 {
			t.Fatal("quota denial changed proof/removal owners or successful lifecycle effects", err)
		}
		var minimum, maximum string
		var charges, allowed, windows, snapshots int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM passkey_risk.counter_charges WHERE tenant_id=$1 AND operation='identity.passkey.delete'),(SELECT count(*) FROM passkey_risk.counter_charges WHERE tenant_id=$1 AND operation='identity.passkey.delete' AND allowed),(SELECT count(*) FROM passkey_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.passkey.delete'),(SELECT min(value)::text FROM passkey_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.passkey.delete'),(SELECT max(value)::text FROM passkey_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.passkey.delete'),(SELECT count(*) FROM passkey_risk.counter_snapshots s JOIN passkey_risk.counter_charges c USING(command_id) WHERE c.tenant_id=$1 AND c.operation='identity.passkey.delete')`, string(r.Primary.TenantID)).Scan(&charges, &allowed, &windows, &minimum, &maximum, &snapshots); err != nil || charges != 6 || allowed != 5 || windows != 4 || minimum != "6" || maximum != "6" || snapshots != 24 {
			t.Fatal("actual deletion risk owner omitted or repeated original quota charges", err)
		}
		var protocolVersion string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text FROM webauthn.credentials`).Scan(&protocolVersion); err != nil || protocolVersion != "1" {
			t.Fatal("quota denial changed protocol version", err)
		}
	}
	assertUnchanged()
	replay, err := removal.Delete(f.ctx, r)
	if err == nil || replay.CommandID != denied.CommandID || replay.Outcome != identity.CommitOutcomeNotCommitted || !replay.Replayed || replay.Receipt.Validate() != nil || !reflect.DeepEqual(replay.Receipt, denied.Receipt) {
		t.Fatal("same original deletion key changed denied receipt or reexecuted", err)
	}
	assertUnchanged()
}

func TestKeyedPasskeyDeleteRequiresFreshActualProofButRetainsExpiredHistory(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired-original-denies", true: "expired-committed-history"}[committed], func(t *testing.T) {
			var advanced time.Time
			account, registration := pendingEnrollment(t, func() time.Time {
				if !advanced.IsZero() {
					return advanced
				}
				return time.Now()
			})
			if _, err := account.service.Register(account.ctx, registration); err != nil {
				t.Fatal(err)
			}
			f := newSigninFixtureForEnrolledAccount(t, account)
			removal, _, inventory, listing := deletionFixture(t, account)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := deletionRequest(t, account, page.Credentials[0], "proof-expiry-delete")
			var original identity.CommandID
			if committed {
				out, err := removal.Delete(f.ctx, r)
				if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(err)
				}
				original = out.CommandID
			}
			advanced = r.Primary.Proof.Proof.ExpiresAt.Add(time.Microsecond)
			out, err := removal.Delete(f.ctx, r)
			if committed {
				if err != nil || !out.Replayed || out.CommandID != original || out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("expired historical proof reran or hid original commitment", err)
				}
			} else if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("genuinely expired original signed proof authorized removal")
			}
		})
	}
}

func TestKeyedPasskeyDeleteRevokesActualSessionAndRetriesMetadata(t *testing.T) {
	f := newSigninFixture(t)
	removal, rename, inventory, listing := deletionFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal("original safe inventory", err)
	}
	renameRequest := managementRequest(t, f.enrollmentFixture, page.Credentials[0], "rename-before-deletion", "Before deletion")
	if out, err := rename.Update(f.ctx, renameRequest); err != nil || out.Credential == nil || out.Credential.Version != 2 {
		t.Fatal("real metadata-only rename", err)
	}
	var reader *session.SessionService
	var access session.GetRequest
	for count := uint32(1); count <= 2; count++ {
		request := f.request(t, session.BrowserSession)
		options, err := f.signin.AuthenticationOptions(f.ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		ceremony, ok := options.Ceremony()
		if !ok {
			t.Fatal("real assertion ceremony absent")
		}
		challenge := signinChallenge(t, f.ctx, options.TransferJSON)
		request.CommandID, _ = identity.NewCommandID()
		pending := SigninCompletion{SigninRequest: request, CeremonyID: ceremony.ID, Response: f.assertion(t, challenge, count)}
		issued, err := f.signin.Signin(f.ctx, pending)
		if err != nil {
			t.Fatal("real signed passkey assertion", err)
		}
		reader, _, _, access = passkeyJourneyReader(t, f, issued)
		if got, err := reader.Get(f.ctx, access); err != nil || !got.Authenticated {
			t.Fatal("original issued passkey session", err)
		}
	}
	listing.AttemptID, _ = identity.NewCommandID()
	page, err = inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].Version != 2 {
		t.Fatal("observed independent management version", err)
	}
	r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "original-passkey-delete")
	first, err := removal.Delete(f.ctx, r)
	if err != nil || first.CommandID == "" || first.Replayed || first.Outcome != identity.CommitOutcomeCommitted || first.Receipt.Validate() != nil || first.Receipt.Feature == nil || first.Receipt.Feature.BeforeVersion != 1 || first.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("genuine keyed removal did not commit exact reference transition", err)
	}
	var state, metadata, reference, protocol, authority, credentialEpoch string
	var enabled, erased bool
	var events, audits, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT m.state,m.metadata_version::text,c.version::text,c.enabled,w.version::text,w.record->'PublicKey'='null'::jsonb,h.authority_version::text,u.credential_version::text FROM identity_passkey.credentials m JOIN identity.credential_references c ON c.tenant_id=m.tenant_id AND c.user_id=m.user_id AND c.credential_id=m.reference_id JOIN identity_passkey.user_handles h ON h.rp_namespace=m.rp_namespace AND h.tenant_id=m.tenant_id AND h.user_id=m.user_id JOIN identity.users u ON u.tenant_id=m.tenant_id AND u.user_id=m.user_id JOIN webauthn.credentials w ON w.rp_id=$2 AND w.credential_id=m.credential_id WHERE m.reference_id=$1`, string(r.ReferenceID), "identity.example").Scan(&state, &metadata, &reference, &enabled, &protocol, &erased, &authority, &credentialEpoch); err != nil || state != "revoked" || metadata != "3" || reference != "2" || enabled || protocol != "4" || !erased || authority != "2" || credentialEpoch != "1" {
		t.Fatal("independent removal owners/versions not committed atomically", err)
	}
	if got, err := reader.Get(f.ctx, access); err != nil || got.Authenticated {
		t.Fatal("removed passkey retained session authority", err)
	}
	listing.AttemptID, _ = identity.NewCommandID()
	page, err = inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 0 {
		t.Fatal("password session lost authority or removed credential remained visible", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.records WHERE action='identity.passkey.remove_credential' AND outcome=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$2 AND consumed_purpose='identity.passkey.delete')`, int16(audit.OutcomeSucceeded), string(r.Primary.Proof.Proof.ID)).Scan(&audits, &events, &consumed); err != nil || audits != 1 || events != 1 || consumed != 1 {
		t.Fatal("removal split proof and canonical required effects", err)
	}
	replay, err := removal.Delete(f.ctx, r)
	if err != nil || replay.CommandID != first.CommandID || replay.Outcome != identity.CommitOutcomeCommitted || !replay.Replayed || replay.Receipt.Validate() != nil {
		t.Fatal("original live password session lost metadata-only retry", err)
	}
	changed := r
	changed.ExpectedVersion++
	if out, err := removal.Delete(f.ctx, changed); err == nil || out.CommandID != "" {
		t.Fatal("same deletion key accepted changed intent")
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'`).Scan(&events); err != nil || events != 1 {
		t.Fatal("metadata retry repeated lifecycle", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE session_store.sessions SET state='revoked' WHERE session_id='session-a'`); err != nil {
		t.Fatal(err)
	}
	if out, err := removal.Delete(f.ctx, r); err == nil || out.CommandID != "" {
		t.Fatal("revoked password session disclosed original removal history")
	}
}

func TestKeyedPasskeyDeleteRejectsForeignCustodyAndStaleVersion(t *testing.T) {
	f := newSigninFixture(t)
	removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	original := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "delete-denial-control")
	for _, mode := range []string{"proof-action", "proof-session", "proof-version", "proof-tenant", "proof-signature", "tenant", "actor", "resource", "target", "command", "record", "reference", "version", "network", "session", "key"} {
		t.Run(mode, func(t *testing.T) {
			r := original
			r.Primary.Caller = original.Primary.Caller.Clone()
			r.IdempotencyKey = optionsKey(t, "delete-denial-"+mode)
			switch mode {
			case "proof-action":
				r.Primary.Proof.Action = "identity.passkey.update"
			case "proof-session":
				r.Primary.Proof.SessionID = "other-session"
			case "proof-version":
				r.Primary.Proof.SessionVersion++
			case "proof-tenant":
				r.Primary.Proof.Proof.Tenant = "other-tenant"
			case "proof-signature":
				r.Primary.Proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAAAQ"
			case "tenant":
				r.Primary.TenantID = "other-tenant"
			case "actor":
				r.Primary.Caller.Request.Subject.ID = "other-user"
			case "resource":
				r.Primary.Caller.Request.Resource.ID = "other-user"
			case "target":
				r.Primary.TargetSubjectID = "other-user"
			case "command":
				r.Primary.CommandID = "AAAAAAAAAAAAAAAAAAAAAQ"
			case "record":
				r.Primary.RecordID = string(r.ReferenceID)
			case "reference":
				r.ReferenceID = "other-reference"
			case "version":
				r.ExpectedVersion++
			case "network":
				r.Network = strings.Repeat("n", 129)
			case "session":
				r.Primary.Session = auth.NewBearerCredential("not-original-password-session")
			case "key":
				r.IdempotencyKey = identity.IdempotencyKey{}
			}
			if out, err := removal.Delete(f.ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("foreign or stale request acquired deletion authority")
			}
		})
	}
	for _, scope := range []string{"rp", "namespace"} {
		c := removal.config()
		if scope == "rp" {
			c.RPID = "foreign.example"
		} else {
			c.RPNamespace = "foreign-rp"
		}
		foreign, err := NewDeletionService(f.pool, c)
		if err != nil {
			t.Fatal(err)
		}
		r := original
		r.IdempotencyKey = optionsKey(t, "delete-foreign-"+scope)
		if out, err := foreign.Delete(f.ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("foreign RP selected a local passkey")
		}
	}
	if out, err := removal.Delete(f.ctx, original); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("denied requests consumed original genuine proof or changed target", err)
	}
}

func TestKeyedPasskeyDeleteRejectsWithdrawnCurrentOwnersAndRecovery(t *testing.T) {
	for _, mode := range []string{"session", "user", "reference", "mapping", "factor-new", "factor-missing", "recovery-email", "password-disabled", "password-material-missing", "password-material-version"} {
		t.Run(mode, func(t *testing.T) {
			f := newSigninFixture(t)
			removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "withdrawn-delete-"+mode)
			statement := `UPDATE session_store.sessions SET state='revoked' WHERE session_id='session-a'`
			switch mode {
			case "user":
				statement = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "reference":
				statement = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey'`
			case "mapping":
				statement = `UPDATE identity_passkey.credentials SET state='revoked'`
			case "factor-new":
				statement = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "factor-missing":
				statement = `DELETE FROM identity_mfa.factor_authorities`
			case "recovery-email":
				statement = `DELETE FROM identity.identifiers WHERE kind='email'`
			case "password-disabled":
				statement = `UPDATE identity.credential_references SET enabled=false WHERE owner='identity/password'`
			case "password-material-missing":
				statement = `DELETE FROM identity_password.credentials`
			case "password-material-version":
				statement = `UPDATE identity_password.credentials SET version=version+1`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, statement); err != nil {
				t.Fatal(err)
			}
			if out, err := removal.Delete(f.ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("withdrawn current owner or unusable recovery allowed removal")
			}
			var consumed, events, protocols int
			var version string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM webauthn.credentials WHERE record->'PublicKey'='null'::jsonb),(SELECT metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$2)`, string(r.Primary.Proof.Proof.ID), string(r.ReferenceID)).Scan(&consumed, &events, &protocols, &version); err != nil || consumed != 0 || events != 0 || protocols != 0 || version != "1" {
				t.Fatal("denial left partial deletion/proof/effects", err)
			}
		})
	}
}

func TestKeyedPasskeyDeleteRequiredEffectsRollbackEveryOwner(t *testing.T) {
	for _, mode := range []string{"audit", "outbox"} {
		t.Run(mode, func(t *testing.T) {
			f := newSigninFixture(t)
			removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "required-delete-"+mode)
			sql := `CREATE FUNCTION public.fail_delete_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.passkey.remove_credential' THEN RAISE EXCEPTION 'synthetic required audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_delete_effect BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.fail_delete_effect()`
			if mode == "outbox" {
				sql = `CREATE FUNCTION public.fail_delete_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='identity.passkey.remove_credential' THEN RAISE EXCEPTION 'synthetic required outbox failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_delete_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.fail_delete_effect()`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal(err)
			}
			if out, err := removal.Delete(f.ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("required effect failure acknowledged deletion")
			}
			var state, version, metadata, authority string
			var enabled bool
			var consumed, protocols, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT m.state,c.version::text,c.enabled,m.metadata_version::text,h.authority_version::text,(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$2 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM webauthn.credentials WHERE record->'PublicKey'='null'::jsonb),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential') FROM identity_passkey.credentials m JOIN identity.credential_references c ON c.tenant_id=m.tenant_id AND c.user_id=m.user_id AND c.credential_id=m.reference_id JOIN identity_passkey.user_handles h ON h.rp_namespace=m.rp_namespace AND h.tenant_id=m.tenant_id AND h.user_id=m.user_id WHERE m.reference_id=$1`, string(r.ReferenceID), string(r.Primary.Proof.Proof.ID)).Scan(&state, &version, &enabled, &metadata, &authority, &consumed, &protocols, &events); err != nil || state != "active" || version != "1" || !enabled || metadata != "1" || authority != "1" || consumed != 0 || protocols != 0 || events != 0 {
				t.Fatal("required effect failure split removal owners", err)
			}
		})
	}
}

func TestKeyedPasskeyDeleteRecoversActualCommitDisconnectWithoutReexecution(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-commit", false: "after-commit"}[before], func(t *testing.T) {
			f := newSigninFixture(t)
			removal, _, inventory, listing := deletionFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := deletionRequest(t, f.enrollmentFixture, page.Credentials[0], "disconnected-delete")
			fault := &enrollmentCommitFault{before: before, marker: "UPDATE identity_passkey.credentials SET state='revoked'"}
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
			c := removal.config()
			c.Coordinator.LeaseDuration = 500 * time.Millisecond
			faultFixture := *f.enrollmentFixture
			faultFixture.pool = pool
			c.Recovery, err = passwordpg.NewPasskeyRemovalRecoverySource(deletionResetFixture(t, &faultFixture, c.RequestKeys))
			if err != nil {
				t.Fatal(err)
			}
			interrupted, err := NewDeletionService(pool, c)
			if err != nil {
				t.Fatal(err)
			}
			out, err := interrupted.Delete(f.ctx, r)
			if !fault.hit.Load() || out.CommandID == "" || err == nil && (out.Outcome != identity.CommitOutcomeCommitted || !out.Replayed) {
				t.Fatal("actual COMMIT acknowledgement fault did not retain original unknown/metadata outcome", err)
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
				recovered, err := removal.Delete(ctx, r)
				if recovered.Outcome == want {
					if recovered.CommandID != out.CommandID || !recovered.Replayed || recovered.Receipt.Validate() != nil || !before && err != nil {
						t.Fatal("recovery changed original identity or reran deletion", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original removal did not reconcile", err)
				case <-ticker.C:
				}
			}
			var events, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.remove_credential'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_purpose='identity.passkey.delete')`).Scan(&events, &consumed); err != nil || before && (events != 0 || consumed != 0) || !before && (events != 1 || consumed != 1) {
				t.Fatal("metadata recovery duplicated original deletion/proof/effects", err)
			}
		})
	}
}
