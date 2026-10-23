//go:build integration

package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func managementFixture(t *testing.T, f *enrollmentFixture) (*ManagementService, *InventoryService, InventoryRequest) {
	t.Helper()
	c := f.service.config()
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reader := sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "passkey-fixture", PolicyNamespace: "users", Audience: "passkey-fixture", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "passkey-fixture", Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}}
	source, err := passwordpg.NewActionPrimarySource(f.proofs, passwordpg.ActionPrimaryConfig{Action: "identity.passkey.update", Audience: "passkey-enrollment", MaximumAge: 5 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal("genuine closed management proof source", err)
	}
	keys := keyedFixtureConfig(t, f, *c.Coordinator.QueryPolicy).state()
	s, err := NewManagementService(f.pool, ManagementConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.RPNamespace, RPID: c.Protocol.RelyingParty.ID, ProofAudience: "passkey-enrollment", Password: reader, Source: source, RequestKeys: keys.request, RequestTokenKey: keys.token, RequestCSRFKey: keys.csrf, Coordinator: c.Coordinator, Authorization: c.Authorization, Risk: c.Risk, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, MaximumDuration: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewInventoryService(f.pool, InventoryConfig{TenantID: c.Protocol.TenantID, RPNamespace: c.RPNamespace, RPID: c.Protocol.RelyingParty.ID, Password: &reader, Protocol: webauthnpg.Config{Coordinator: c.Coordinator, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion}, Authorization: c.Authorization, PolicyVersion: c.PolicyVersion, Rate: &f.counters, MaximumDuration: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(f.bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(c.PolicyVersion), CorrelationID: "management-fixture", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, Tenant: authorization.TenantID(c.Protocol.TenantID), Action: "identity.passkey.list", Resource: authorization.Resource{Type: "identity.user", ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}}}
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return s, inventory, InventoryRequest{Credential: credential, Caller: caller, AttemptID: attempt, Limit: 10}
}

func TestKeyedPasskeyRenameRejectsForeignCustodyAndStaleVersion(t *testing.T) {
	f := newSigninFixture(t)
	manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	original := managementRequest(t, f.enrollmentFixture, page.Credentials[0], "rename-scope-control", "New name")
	for _, mode := range []string{"proof-action", "proof-session", "tenant", "actor", "resource", "target", "command-override", "record-override", "reference", "version", "label", "network", "cookie"} {
		t.Run(mode, func(t *testing.T) {
			r := original
			r.Primary.Caller = original.Primary.Caller.Clone()
			r.IdempotencyKey = optionsKey(t, "rename-denial-"+mode)
			switch mode {
			case "proof-action":
				r.Primary.Proof.Action = "identity.passkey.register-verify"
			case "proof-session":
				r.Primary.Proof.SessionID = "another-session"
			case "tenant":
				r.Primary.TenantID = "another-tenant"
			case "actor":
				r.Primary.Caller.Request.Subject.ID = "another-user"
			case "resource":
				r.Primary.Caller.Request.Resource.ID = "another-user"
			case "target":
				r.Primary.TargetSubjectID = "another-user"
			case "command-override":
				r.Primary.CommandID = "AAAAAAAAAAAAAAAAAAAAAQ"
			case "record-override":
				r.Primary.RecordID = string(r.ReferenceID)
			case "reference":
				r.ReferenceID = "AAAAAAAAAAAAAAAAAAAAAQ"
			case "version":
				r.ExpectedVersion++
			case "label":
				r.Name = strings.Repeat("x", 129)
			case "network":
				r.Network = ""
			case "cookie":
				r.Primary.Session = auth.NewBearerCredential("unowned-browser-custody")
			}
			out, err := manager.Update(f.ctx, r)
			if err == nil || out.Credential != nil {
				t.Fatal("foreign/malformed rename acquired metadata or mutated")
			}
		})
	}
	for _, field := range []string{"rp", "namespace"} {
		c := manager.config()
		if field == "rp" {
			c.RPID = "foreign.example"
		} else {
			c.RPNamespace = "foreign-rp"
		}
		foreign, err := NewManagementService(f.pool, c)
		if err != nil {
			t.Fatal(err)
		}
		r := original
		r.IdempotencyKey = optionsKey(t, "rename-denial-"+field)
		if out, err := foreign.Update(f.ctx, r); err == nil || out.Credential != nil {
			t.Fatal("foreign RP selection renamed another RP")
		}
	}
	if out, err := manager.Update(f.ctx, original); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("denied attempts consumed genuine original proof", err)
	}
}

func TestKeyedPasskeyRenameRejectsWithdrawnCurrentOwners(t *testing.T) {
	for _, partition := range []string{"session", "user", "credential", "mapping", "factor-enrolled", "factor-missing"} {
		t.Run(partition, func(t *testing.T) {
			f := newSigninFixture(t)
			manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := managementRequest(t, f.enrollmentFixture, page.Credentials[0], "withdrawn-rename-"+partition, "Must remain unchanged")
			statement := `UPDATE session_store.sessions SET state='revoked' WHERE session_id='session-a'`
			switch partition {
			case "user":
				statement = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "credential":
				statement = `UPDATE identity.credential_references SET enabled=false WHERE owner='passkey'`
			case "mapping":
				statement = `UPDATE identity_passkey.credentials SET state='revoked'`
			case "factor-enrolled":
				statement = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "factor-missing":
				statement = `DELETE FROM identity_mfa.factor_authorities`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, statement); err != nil {
				t.Fatal(err)
			}
			if out, err := manager.Update(f.ctx, r); err == nil || out.Credential != nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("withdrawn current owner allowed rename")
			}
			var label, version string
			var consumed, events, succeeded int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT display_label,metadata_version::text,(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential'),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$2) FROM identity_passkey.credentials WHERE reference_id=$3`, string(r.Primary.Proof.Proof.ID), int16(audit.OutcomeSucceeded), string(r.ReferenceID)).Scan(&label, &version, &consumed, &events, &succeeded); err != nil || label != page.Credentials[0].Label || version != "1" || consumed != 0 || events != 0 || succeeded != 0 {
				t.Fatal("withdrawn current owner left a partial protected mutation", err)
			}
		})
	}
}

func TestKeyedPasskeyRenameMutationRiskBoundRetainsOriginalDeniedOutcome(t *testing.T) {
	f := newSigninFixture(t)
	manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	current := page.Credentials[0]
	var originalUpdates, existingEnrollment int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM passkey_risk.counter_charges WHERE operation='identity.passkey.update'),(SELECT count(*) FROM passkey_risk.counter_charges WHERE operation IN ('identity.passkey.register-options','identity.passkey.register-verify'))`).Scan(&originalUpdates, &existingEnrollment); err != nil || originalUpdates != 0 || existingEnrollment != 2 {
		t.Fatal("actual original mutation capacity does not match this freshly enrolled fixture", err)
	}
	// The real enrollment fixture selects mutation limit5, separately from
	// password proof issuance's Authentication limit10. Enrollment used two
	// genuine proof submissions; these six more remain below that auth bound.
	// No counter state, policy or window is reset to reach this boundary.
	// Native counter identity includes operation, so the two retained enrollment
	// charges above do not occupy this exact update operation's five free slots.
	remaining := 5 - originalUpdates
	for attempt := 1; attempt <= remaining; attempt++ {
		r := managementRequest(t, f.enrollmentFixture, current, fmt.Sprintf("bounded-rename-%d", attempt), fmt.Sprintf("Bounded label %d", attempt))
		out, err := manager.Update(f.ctx, r)
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Credential == nil || out.Credential.Version != current.Version+1 || out.Credential.Label != r.Name || out.Receipt.Validate() != nil {
			t.Fatal("valid rename below actual mutation limit did not advance exactly once", attempt, err)
		}
		current = *out.Credential
	}
	listing.AttemptID, _ = identity.NewCommandID()
	page, err = inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].Version != 6 || page.Credentials[0].Label != current.Label {
		t.Fatal("five real renames were not retained by safe inventory", err)
	}
	sixth := managementRequest(t, f.enrollmentFixture, current, "bounded-rename-sixth", "Must remain denied")
	denied, err := manager.Update(f.ctx, sixth)
	if err == nil || denied.CommandID == "" || denied.Outcome != identity.CommitOutcomeNotCommitted || denied.Credential != nil || denied.Receipt.Validate() != nil {
		t.Fatal("sixth mutation did not retain classified noncommit", err)
	}
	assertBoundedState := func() {
		t.Helper()
		var label, version string
		var consumed, succeeded, events, proofs int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT display_label,metadata_version::text,(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$2),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential'),(SELECT count(*) FROM identity_password.reauthentication_records) FROM identity_passkey.credentials WHERE reference_id=$3`, string(sixth.Primary.Proof.Proof.ID), int16(audit.OutcomeSucceeded), string(sixth.ReferenceID)).Scan(&label, &version, &consumed, &succeeded, &events, &proofs); err != nil || label != current.Label || version != "6" || consumed != 0 || succeeded != 5 || events != 5 || proofs != 8 {
			t.Fatal("mutation denial altered label/version/proof or successful required effects", err)
		}
		var minimum, maximum string
		var charges, allowed, windows, snapshots int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM passkey_risk.counter_charges WHERE tenant_id=$1 AND operation='identity.passkey.update'),(SELECT count(*) FROM passkey_risk.counter_charges WHERE tenant_id=$1 AND operation='identity.passkey.update' AND allowed),(SELECT count(*) FROM passkey_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.passkey.update'),(SELECT min(value)::text FROM passkey_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.passkey.update'),(SELECT max(value)::text FROM passkey_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.passkey.update'),(SELECT count(*) FROM passkey_risk.counter_snapshots s JOIN passkey_risk.counter_charges c USING(command_id) WHERE c.tenant_id=$1 AND c.operation='identity.passkey.update')`, string(sixth.Primary.TenantID)).Scan(&charges, &allowed, &windows, &minimum, &maximum, &snapshots); err != nil || charges != 6 || allowed != 5 || windows != 4 || minimum != "6" || maximum != "6" || snapshots != 24 {
			t.Fatal("actual mutation owner omitted or repeated its six original charges", err)
		}
	}
	assertBoundedState()
	replay, err := manager.Update(f.ctx, sixth)
	if err == nil || replay.CommandID != denied.CommandID || replay.Outcome != identity.CommitOutcomeNotCommitted || !replay.Replayed || replay.Credential != nil || replay.Receipt.Validate() != nil || !reflect.DeepEqual(replay.Receipt, denied.Receipt) {
		t.Fatal("same-key denied retry changed original metadata or reexecuted", err)
	}
	assertBoundedState()
}

func TestKeyedPasskeyRenameRollsBackRequiredEffects(t *testing.T) {
	for _, effect := range []string{"audit", "outbox"} {
		t.Run(effect, func(t *testing.T) {
			f := newSigninFixture(t)
			manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := managementRequest(t, f.enrollmentFixture, page.Credentials[0], "rename-required-"+effect, "Must roll back")
			statement := `CREATE FUNCTION public.fail_rename_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='identity.passkey.rename_credential' THEN RAISE EXCEPTION 'required rename effect unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_rename_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.fail_rename_effect()`
			if effect == "audit" {
				statement = `CREATE FUNCTION public.fail_rename_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.passkey.rename_credential' THEN RAISE EXCEPTION 'required rename effect unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_rename_effect BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.fail_rename_effect()`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, statement); err != nil {
				t.Fatal(err)
			}
			out, updateErr := manager.Update(f.ctx, r)
			if updateErr == nil || out.Credential != nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("required-effect failure exposed success")
			}
			var label string
			var version string
			var consumed, events, succeeded, failed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT display_label,metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$1`, string(r.ReferenceID)).Scan(&label, &version); err != nil || label != page.Credentials[0].Label || version != "1" {
				t.Fatal("required effect failure persisted label", err)
			}
			wantFailed := 0
			if effect == "outbox" {
				wantFailed = 1
			}
			// Abort retains the kernel's separately committed failed/no-change
			// audit, not the rolled-back successful mutation audit. A failed
			// audit writer cannot terminalize even that negative receipt.
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$2),(SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$3),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential')`, string(r.Primary.Proof.Proof.ID), int16(audit.OutcomeSucceeded), int16(audit.OutcomeFailed)).Scan(&consumed, &succeeded, &failed, &events); err != nil || consumed != 0 || succeeded != 0 || failed != wantFailed || events != 0 {
				t.Fatal("required effects split proof/domain owners", err)
			}
			if effect == "outbox" {
				var wire []byte
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT canonical_record FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$1`, int16(audit.OutcomeFailed)).Scan(&wire); err != nil {
					t.Fatal("missing exact failed rename audit", err)
				}
				record, err := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
				attributes := record.Attributes()
				if err != nil || out.CommandID == "" || record.Action() != renameEvent || record.Outcome() != audit.OutcomeFailed || record.Context().TenantID() != string(r.Primary.TenantID) || record.Actor().ID() != string(r.Primary.Caller.Request.Subject.ID) || record.Subject().Type() != "passkey" || record.Subject().ID() != string(r.ReferenceID) || attributes["command.id"] != string(out.CommandID) || attributes["aggregate.before_version"] != "1" || attributes["aggregate.after_version"] != "1" || !record.Changes().NoChange() || len(record.Changes().Before()) != 0 || len(record.Changes().After()) != 0 {
					t.Fatal("failed audit lost original scope or claimed metadata mutation", err)
				}
			}
		})
	}
}

func TestKeyedPasskeyRenameRetainsExpiredProofHistoryButRequiresCurrentSession(t *testing.T) {
	var advanced time.Time
	nativeNow := func() time.Time {
		if !advanced.IsZero() {
			return advanced
		}
		return time.Now()
	}
	f, completion := pendingEnrollment(t, nativeNow)
	if _, err := f.service.Register(f.ctx, completion); err != nil {
		t.Fatal(err)
	}
	manager, inventory, listing := managementFixture(t, f)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	original := managementRequest(t, f, page.Credentials[0], "original-expiry-rename", "Historical label")
	first, err := manager.Update(f.ctx, original)
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(err)
	}
	unconsumed := managementRequest(t, f, *first.Credential, "fresh-expired-rename", "Denied label")
	prepared := unconsumed.Primary
	prepared.CommandID, _ = identity.NewCommandID()
	prepared.RecordID = string(unconsumed.ReferenceID)
	if _, err := manager.config().Source.Prepare(f.ctx, prepared); err != nil {
		t.Fatal("genuine unconsumed proof was not initially usable", err)
	}
	advanced = unconsumed.Primary.Proof.Proof.ExpiresAt.Add(time.Microsecond)
	if _, err := manager.config().Source.Prepare(f.ctx, prepared); err == nil {
		t.Fatal("native proof fixture did not actually expire")
	}
	replayed, err := manager.Update(f.ctx, original)
	if err != nil || !replayed.Replayed || replayed.CommandID != first.CommandID || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Credential != nil {
		t.Fatal("expiry renewed proof or lost original metadata", err)
	}
	if out, err := manager.Update(f.ctx, unconsumed); err == nil || out.Credential != nil {
		t.Fatal("fresh key bypassed real native expiry")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE session_store.sessions SET state='revoked' WHERE session_id='session-a'`); err != nil {
		t.Fatal(err)
	}
	if out, err := manager.Update(f.ctx, original); err == nil || out.CommandID != "" || out.Credential != nil {
		t.Fatal("caller subject alone disclosed history after original session withdrawal")
	}
}

func TestKeyedPasskeyRenameConcurrentVersionsHaveOneWinner(t *testing.T) {
	f := newSigninFixture(t)
	manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	requests := []passkey.UpdateRequest{managementRequest(t, f.enrollmentFixture, page.Credentials[0], "rename-race-a", "Winner A"), managementRequest(t, f.enrollmentFixture, page.Credentials[0], "rename-race-b", "Winner B")}
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	results := make([]passkey.UpdateResult, 2)
	failures := make([]error, 2)
	for i := range requests {
		go func(i int) { defer wg.Done(); <-start; results[i], failures[i] = manager.Update(f.ctx, requests[i]) }(i)
	}
	close(start)
	wg.Wait()
	winners := 0
	for i, out := range results {
		if failures[i] == nil && out.Outcome == identity.CommitOutcomeCommitted {
			winners++
			if out.Replayed || out.Credential == nil || out.Credential.Version != 2 {
				t.Fatal("concurrent winner missing safe updated metadata")
			}
		} else if out.Credential != nil {
			t.Fatal("concurrent loser disclosed updated metadata")
		}
	}
	var version string
	var audits, events, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$1`, page.Credentials[0].ReferenceID).Scan(&version); err != nil || version != "2" || winners != 1 {
		t.Fatal("optimistic rename silently overwrote a winner", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential' AND outcome=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_purpose='identity.passkey.update')`, int16(audit.OutcomeSucceeded)).Scan(&audits, &events, &consumed); err != nil || audits != 1 || events != 1 || consumed != 1 {
		t.Fatal("race split proof/version/required effects", err)
	}
}

func TestKeyedPasskeyRenameSameKeyContentionRetainsOneOriginalCommand(t *testing.T) {
	f := newSigninFixture(t)
	manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal(err)
	}
	r := managementRequest(t, f.enrollmentFixture, page.Credentials[0], "same-key-rename-race", "One original label")
	results, failures := make([]passkey.UpdateResult, 2), make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	for i := range results {
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], failures[i] = manager.Update(f.ctx, r)
		}(i)
	}
	close(start)
	wg.Wait()
	var original identity.CommandID
	fresh := 0
	for i, out := range results {
		if out.Credential != nil {
			if failures[i] != nil || out.Replayed || out.Outcome != identity.CommitOutcomeCommitted || out.Credential.Version != 2 {
				t.Fatal("same-key contender disclosed non-fresh mutation")
			}
			fresh++
			original = out.CommandID
		}
	}
	if fresh != 1 || original == "" {
		t.Fatal("same-key requests did not retain exactly one fresh winner")
	}
	for _, out := range results {
		if out.CommandID != "" && out.CommandID != original {
			t.Fatal("same key allocated a sibling command")
		}
	}
	replay, err := manager.Update(f.ctx, r)
	if err != nil || replay.CommandID != original || !replay.Replayed || replay.Outcome != identity.CommitOutcomeCommitted || replay.Credential != nil {
		t.Fatal("same-key contention lost original metadata-only replay", err)
	}
	var version string
	var audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,(SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential'),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential') FROM identity_passkey.credentials WHERE reference_id=$1`, string(r.ReferenceID)).Scan(&version, &audits, &events); err != nil || version != "2" || audits != 1 || events != 1 {
		t.Fatal("same key repeated metadata or required effects", err)
	}
}

func TestKeyedPasskeyRenameRecoversActualCommitDisconnect(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-commit", false: "after-commit"}[before], func(t *testing.T) {
			f := newSigninFixture(t)
			manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
			page, err := inventory.List(f.ctx, listing)
			if err != nil || len(page.Credentials) != 1 {
				t.Fatal(err)
			}
			r := managementRequest(t, f.enrollmentFixture, page.Credentials[0], "rename-commit-disconnect", "Recovered name")
			fault := &enrollmentCommitFault{before: before, marker: "UPDATE identity_passkey.credentials SET display_label"}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal("fault pool unavailable")
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("fault pool cleanup failed")
				}
			}()
			config := manager.config()
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			interrupted, err := NewManagementService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			out, err := interrupted.Update(f.ctx, r)
			if !fault.hit.Load() || out.CommandID == "" || out.Credential != nil || err == nil && (out.Outcome != identity.CommitOutcomeCommitted || !out.Replayed || out.Receipt.Validate() != nil) {
				t.Fatal("lost actual COMMIT acknowledgement exposed rename success", err)
			}
			restarted, err := NewManagementService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			want := identity.CommitOutcomeCommitted
			label, version := r.Name, "2"
			if before {
				want = identity.CommitOutcomeNotCommitted
				label = page.Credentials[0].Label
				version = "1"
			}
			ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
			defer cancel()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				recovered, err := restarted.Update(ctx, r)
				if recovered.Outcome == want {
					if recovered.CommandID != out.CommandID || !recovered.Replayed || recovered.Credential != nil || recovered.Receipt.Validate() != nil || !before && err != nil {
						t.Fatal("recovery changed original identity/outcome or reexecuted", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original rename did not reconcile", err)
				case <-ticker.C:
				}
			}
			var actualLabel, actualVersion string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT display_label,metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$1`, string(r.ReferenceID)).Scan(&actualLabel, &actualVersion); err != nil || actualLabel != label || actualVersion != version {
				t.Fatal("COMMIT recovery split label/version", err)
			}
		})
	}
}

func managementRequest(t *testing.T, f *enrollmentFixture, metadata CredentialMetadata, key, name string) passkey.UpdateRequest {
	t.Helper()
	r := f.actionRequest(t, "identity.passkey.update")
	r.Primary.CommandID, r.Primary.RecordID = "", ""
	return passkey.UpdateRequest{Primary: r.Primary, ReferenceID: identity.CredentialID(metadata.ReferenceID), ExpectedVersion: metadata.Version, Name: name, IdempotencyKey: optionsKey(t, key), Network: r.Network}
}

func TestKeyedPasskeyRenamePreservesActualSigninReadAndLogout(t *testing.T) {
	f := newSigninFixture(t)
	manager, inventory, listing := managementFixture(t, f.enrollmentFixture)
	page, err := inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal("original safe inventory", err)
	}
	before := page.Credentials[0]
	protocolBefore, err := f.service.protocol.LoadCredential(f.ctx, webauthn.Lookup{Context: webauthn.CeremonyContext{TenantID: f.service.config().Protocol.TenantID, UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, RPID: "identity.example"}, f.id)
	if err != nil {
		t.Fatal(err)
	}
	r := managementRequest(t, f.enrollmentFixture, before, "original-label-rename", "Renamed key")
	first, err := manager.Update(f.ctx, r)
	if err != nil || first.CommandID == "" || first.Outcome != identity.CommitOutcomeCommitted || first.Replayed || first.Credential == nil || first.Credential.ReferenceID != before.ReferenceID || first.Credential.Version != 2 || first.Credential.Label != r.Name || first.Receipt.Validate() != nil || first.Receipt.Feature == nil || first.Receipt.Feature.BeforeVersion != 1 || first.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("genuine keyed rename did not commit exact safe transition", err)
	}
	listing.AttemptID, _ = identity.NewCommandID()
	page, err = inventory.List(f.ctx, listing)
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != r.Name || page.Credentials[0].Version != 2 {
		t.Fatal("rename not visible through actual safe inventory", err)
	}
	protocolAfter, err := f.service.protocol.LoadCredential(f.ctx, webauthn.Lookup{Context: webauthn.CeremonyContext{TenantID: f.service.config().Protocol.TenantID, UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, RPID: "identity.example"}, f.id)
	if err != nil || !reflect.DeepEqual(protocolBefore, protocolAfter) {
		t.Fatal("display rename changed protocol credential/counter bytes", err)
	}
	var authorityVersion, metadataVersion string
	var events, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,metadata_version::text FROM identity_passkey.credentials WHERE reference_id=$1`, before.ReferenceID).Scan(&authorityVersion, &metadataVersion); err != nil || authorityVersion != "1" || metadataVersion != "2" {
		t.Fatal("display rename changed credential authority", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.records WHERE action='identity.passkey.rename_credential'),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.rename_credential')`).Scan(&audits, &events); err != nil || audits != 1 || events != 1 {
		t.Fatal("exact rename required effects missing", err)
	}
	replay, err := manager.Update(f.ctx, r)
	if err != nil || replay.CommandID != first.CommandID || replay.Outcome != identity.CommitOutcomeCommitted || !replay.Replayed || replay.Credential != nil {
		t.Fatal("same key reran consumed proof or lost original metadata", err)
	}
	changed := r
	changed.Name = "Different label"
	if out, err := manager.Update(f.ctx, changed); err == nil || out.CommandID != "" || out.Credential != nil {
		t.Fatal("same key accepted changed intent")
	}
	consumed := r
	consumed.IdempotencyKey = optionsKey(t, "new-key-consumed-rename")
	consumed.ExpectedVersion = 2
	if out, err := manager.Update(f.ctx, consumed); err == nil || out.Credential != nil {
		t.Fatal("a new key reused the original consumed update proof")
	}
	completion, _ := f.pending(t)
	issued, err := f.signin.Signin(f.ctx, completion)
	if err != nil {
		t.Fatal("renamed real passkey no longer signs in", err)
	}
	passkeyJourneyReadInventoryLogout(t, f, issued, r.Name)
}
