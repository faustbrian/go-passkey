//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func enrollmentRateCounts(t *testing.T, f *sessionManagementTestFixture) (out [6]int) {
	t.Helper()
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.identity_command_id_claims),
 (SELECT count(*) FROM webauthn.ceremonies),
 (SELECT count(*) FROM webauthn.effects),
 (SELECT count(*) FROM passkey_admission.durable_counter_attempts),
 (SELECT count(*) FROM identity_passkey.credentials),
 (SELECT count(*) FROM public.outbox_messages)`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4], &out[5])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSessionRegistrationRateSourceReadsOriginalCustodyWithoutConsumption(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "bearer", true: "cookie"}[cookie], func(t *testing.T) {
			f, s, intent, completion := pendingSessionEnrollmentCompletion(t, cookie)
			before := enrollmentRateCounts(t, f)
			canceled, cancel := context.WithCancel(f.ctx)
			cancel()
			denied, err := s.SessionRegistrationRateSource(canceled, passkey.NewSessionEnrollmentRequest(intent), completion.CeremonyID)
			if !errors.Is(err, context.Canceled) || denied != (passkey.CeremonyRateSource{}) {
				t.Fatal("canceled rate read lost cancellation or disclosed metadata", err)
			}
			for range 2 {
				source, err := s.SessionRegistrationRateSource(f.ctx, passkey.NewSessionEnrollmentRequest(intent), completion.CeremonyID)
				if err != nil || source.CeremonyID != completion.CeremonyID || source.Lifetime != 5*time.Minute || source.Kind != passkey.RateSourceUser || source.UserID == "" || source.UserID != identity.UserID(intent.Caller.Request.Subject.ID) || source.Identifier != "" || source.AnonymousFlowID != "" {
					t.Fatal("original session enrollment rate metadata absent", err)
				}
			}
			if before != enrollmentRateCounts(t, f) {
				t.Fatal("rate metadata read created commands, protocol/risk or lifecycle effects")
			}
			if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(completion)); err != nil {
				t.Fatal("read consumed original enrollment authorization", err)
			}
			after := enrollmentRateCounts(t, f)
			source, err := s.SessionRegistrationRateSource(f.ctx, passkey.NewSessionEnrollmentRequest(intent), completion.CeremonyID)
			if err != nil || source.CeremonyID != completion.CeremonyID || after != enrollmentRateCounts(t, f) {
				t.Fatal("historical metadata lost original custody or repeated work", err)
			}
			replayed, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(completion))
			fields, bound := replayed.Bindings()
			if err != nil || bound != nil || !fields.Replayed || fields.Credential != nil || after != enrollmentRateCounts(t, f) {
				t.Fatal("rate metadata allowed repeated enrollment", err)
			}
		})
	}
}

func TestSessionRegistrationRateSourceRejectsChangedOriginalCustody(t *testing.T) {
	f, s, original, completion := pendingSessionEnrollmentCompletion(t, true)
	for _, mode := range []string{"zero", "label", "network", "origin", "actor", "tenant", "resource", "action", "session", "csrf", "ceremony", "assertion-parent", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			r := original
			r.Caller = r.Caller.Clone()
			id := completion.CeremonyID
			switch mode {
			case "label":
				r.Label = "substituted"
			case "network":
				r.Network = "192.0.2.2"
			case "origin":
				r.Origin = "https://foreign.example"
			case "actor":
				r.Caller.Request.Subject.ID = "foreign"
			case "tenant":
				r.Caller.Request.Tenant = "foreign"
			case "resource":
				r.Caller.Request.Resource.ID = "foreign"
			case "action":
				r.Caller.Request.Action = "identity.passkey.register-options"
			case "session":
				r.Credential = session.Credential{}
			case "csrf":
				r.CSRFToken = session.CSRFToken{}
			case "ceremony":
				foreign, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				id = string(foreign)
			case "assertion-parent":
				record, err := f.issued.Session.Session.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				p := &sessionEnrollmentInvocation{service: s, record: record}
				parent, err := p.loadContext(f.ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				id = parent.Parent
			case "malformed":
				id = "not-a-command"
			}
			custody := passkey.NewSessionEnrollmentRequest(r)
			if mode == "zero" {
				custody = passkey.SessionEnrollmentRequest{}
			}
			source, err := s.SessionRegistrationRateSource(f.ctx, custody, id)
			requireNoRateSource(t, source, err)
		})
	}
	if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(completion)); err != nil {
		t.Fatal("denied rate reads consumed genuine completion", err)
	}
}

func TestSessionRegistrationRateSourceRejectsWithdrawnAndExpiredCustody(t *testing.T) {
	for _, mode := range []string{"session", "user", "mapping", "factor", "directory", "rp-profile", "missing-parent", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, s, intent, c := pendingSessionEnrollmentCompletion(t, false)
			sql := ""
			switch mode {
			case "session":
				sql = `UPDATE session_store.sessions SET state='revoked'`
			case "user":
				sql = `UPDATE identity.users SET status='banned',authority_version=authority_version+1`
			case "mapping":
				sql = `UPDATE identity_passkey.credentials SET state='revoked'`
			case "factor":
				sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1`
			case "directory":
				sql = `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`
			case "rp-profile":
				config := s.owner.config()
				config.Protocol.RelyingParty.Version++
				var err error
				s, err = NewSessionEnrollmentService(f.pool, config)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-parent":
				if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity_passkey.signin_contexts WHERE ceremony_id=$1`, c.CeremonyID); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				// Advance the real service clock, not the digest-bound protocol
				// record. Reads cannot create a fresh five-minute lease.
				config := s.owner.config()
				config.Clock = signinClock{stamp: time.Now().Add(6 * time.Minute)}
				var err error
				s, err = NewSessionEnrollmentService(f.pool, config)
				if err != nil {
					t.Fatal(err)
				}
			}
			if sql != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			source, err := s.SessionRegistrationRateSource(f.ctx, passkey.NewSessionEnrollmentRequest(intent), c.CeremonyID)
			requireNoRateSource(t, source, err)
		})
	}
}

func TestNilSessionRegistrationRateSourceDenies(t *testing.T) {
	for _, s := range []*SessionEnrollmentService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			source, err := s.SessionRegistrationRateSource(ctx, passkey.SessionEnrollmentRequest{}, "")
			requireNoRateSource(t, source, err)
		}
	}
}

// This isolates the return-time policy using an actual session owner's read,
// not a fabricated proof or edited protocol record. The expiry arguments are
// controlled boundary inputs; genuine A/B linkage/TTL is proved above and by
// TestPasskeySessionEnrollmentRetainsGenuineOriginalAuthorizationCeiling.
func TestSessionRegistrationRateSourceFinalTimeFence(t *testing.T) {
	f, s, intent, _ := pendingSessionEnrollmentCompletion(t, false)
	read, _, err := s.owner.authenticateAction(f.ctx, passkey.SessionUpdateRequest{Credential: intent.Credential, Caller: intent.Caller}, "identity.passkey.register-verify")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if read.ValidateAt(now.Add(2*time.Second)) != nil {
		t.Fatal("fixture does not retain genuine session read validity")
	}
	for _, mode := range []string{"A-at-database-time", "A-at-observed-time", "B-at-database-time", "B-at-observed-time", "missing-A", "missing-B"} {
		t.Run(mode, func(t *testing.T) {
			p := &sessionEnrollmentInvocation{read: read, ceiling: now.Add(time.Second)}
			registration := now.Add(time.Second)
			databaseNow, observedNow := now, now
			switch mode {
			case "A-at-database-time":
				registration, databaseNow = now.Add(2*time.Second), p.ceiling
			case "A-at-observed-time":
				registration, observedNow = now.Add(2*time.Second), p.ceiling
			case "B-at-database-time":
				p.ceiling, databaseNow = now.Add(2*time.Second), registration
			case "B-at-observed-time":
				p.ceiling, observedNow = now.Add(2*time.Second), registration
			case "missing-A":
				p.ceiling = time.Time{}
			case "missing-B":
				registration = time.Time{}
			}
			if p.rateFresh(databaseNow, observedNow, registration) {
				t.Fatal("expired original ceremony metadata escaped final time fence")
			}
		})
	}
	p := &sessionEnrollmentInvocation{read: read, ceiling: now.Add(time.Second)}
	if !p.rateFresh(now, now, now.Add(2*time.Second)) {
		t.Fatal("valid original metadata was suppressed")
	}
}
