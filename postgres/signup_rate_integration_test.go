//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	"github.com/jackc/pgx/v5"
)

func TestSignupRateSourceReadsOnlyOriginalAnonymousMetadata(t *testing.T) {
	f, s, completion := pendingSignup(t)
	request := passkey.SignupCeremonyRateRequest{SignupRequest: completion.SignupRequest, CeremonyID: completion.CeremonyID}
	before := signupRateState(t, f)
	for range 3 {
		source, err := s.SignupRateSource(f.ctx, request)
		if err != nil || source.CeremonyID != completion.CeremonyID || source.Lifetime != 5*time.Minute || source.Kind != passkey.RateSourceAnonymousFlow || source.AnonymousFlowID != completion.FlowID || source.UserID != "" || source.Identifier != "" {
			t.Fatal("signup rate source lost original anonymous custody or exposed prospective identity", err)
		}
	}
	if after := signupRateState(t, f); before != after {
		t.Fatal("rate metadata read changed durable state")
	}
	assertSignupEffects(t, f, 0)
	issued, err := s.Signup(f.ctx, completion)
	if err != nil || issued.Session.Token == (session.Token{}) || issued.CSRF == (session.CSRFToken{}) {
		t.Fatal("rate source consumed original signup custody", err)
	}
	assertSignupEffects(t, f, 1)
	if replay, err := s.Signup(f.ctx, completion); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
		t.Fatal("rate metadata authorized repeated signup authentication")
	}
}

func TestSignupRateSourceRejectsForeignCustodyAndChangedAuthority(t *testing.T) {
	for _, mode := range []string{"cookie", "flow", "origin", "ceremony", "invalid-ceremony", "command", "missing-device", "missing-network", "global", "tenant", "tenant-disabled", "tenant-scope", "context", "prospective-user", "protocol-mode", "protocol-origin", "protocol-handle", "protocol-exclusions"} {
		t.Run(mode, func(t *testing.T) {
			f, s, completion := pendingSignup(t)
			r := passkey.SignupCeremonyRateRequest{SignupRequest: completion.SignupRequest, CeremonyID: completion.CeremonyID}
			query := ""
			switch mode {
			case "cookie":
				r.Cookie, _ = session.NewToken(32)
			case "missing-device":
				r.Device = ""
			case "missing-network":
				r.Network = ""
			case "flow":
				other := signupBrowserRequest(t, f, s)
				r.FlowID, r.Cookie = other.FlowID, other.Cookie
			case "origin":
				r.Origin = "https://foreign.example"
			case "ceremony":
				id, _ := identity.NewCommandID()
				r.CeremonyID = string(id)
			case "invalid-ceremony":
				r.CeremonyID = "invalid"
			case "command":
				r.CommandID = ""
			case "global":
				query = `UPDATE identity.global_authorities SET version=version+1`
			case "tenant":
				query = `UPDATE identity.tenant_authorities SET version=version+1`
			case "tenant-disabled":
				query = `UPDATE identity.tenant_authorities SET enabled=false`
			case "tenant-scope":
				query = `UPDATE identity_passkey.signup_contexts SET tenant_id='foreign-tenant'`
			case "context":
				query = `DELETE FROM identity_passkey.signup_contexts`
			case "prospective-user":
				query = `UPDATE identity_passkey.signup_contexts SET admission=convert_to(replace(convert_from(admission,'UTF8'),'"User":"','"User":"foreign-'),'UTF8')`
			case "protocol-mode":
				query = `UPDATE webauthn.ceremonies SET record=jsonb_set(record,'{Intent,Kind}','"get-discoverable"')`
			case "protocol-origin":
				query = `UPDATE webauthn.ceremonies SET record=jsonb_set(record,'{Intent,Origin}','"https://foreign.example"')`
			case "protocol-handle":
				query = fmt.Sprintf(`UPDATE webauthn.ceremonies SET record=jsonb_set(record,'{Intent,UserHandle}','"%s"')`, base64.StdEncoding.EncodeToString(make([]byte, 32)))
			case "protocol-exclusions":
				query = `UPDATE webauthn.ceremonies SET record=jsonb_set(record,'{Intent,AllowedCredentials}','["AQ=="]')`
			}
			if query != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, query); err != nil {
					t.Fatal("source denial fixture", err)
				}
			}
			before := ""
			if mode == "cookie" {
				before = signupRateState(t, f)
			}
			source, err := s.SignupRateSource(f.ctx, r)
			requireNoRateSource(t, source, err)
			if before != "" && signupRateState(t, f) != before {
				t.Fatal("denied rate source changed durable state")
			}
			assertSignupEffects(t, f, 0)
		})
	}
}

func TestSignupRateSourcePreservesOriginalLifetimeAndDeniesExpiredCeremony(t *testing.T) {
	f, s := newSignupFixture(t)
	config := signupFixtureConfig(f, s)
	config.Flow.FlowTTL = 10 * time.Minute
	service, err := NewSignupService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	r := signupBrowserRequest(t, f, service)
	options, err := service.RegistrationOptions(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("original signup options absent")
	}
	r.CommandID, _ = identity.NewCommandID()
	request := passkey.SignupCeremonyRateRequest{SignupRequest: r, CeremonyID: ceremony.ID}
	var originalExpiry time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT expires_at FROM webauthn.ceremonies WHERE ceremony_id=$1`, ceremony.ID).Scan(&originalExpiry); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{time.Minute, 6 * time.Minute} {
		config.Clock = signinClock{stamp: time.Now().Add(elapsed)}
		later, err := NewSignupService(f.pool, config)
		if err != nil {
			t.Fatal(err)
		}
		source, err := later.SignupRateSource(f.ctx, request)
		if elapsed < 5*time.Minute {
			if err != nil || source.Lifetime != 5*time.Minute || source.CeremonyID != ceremony.ID || source.AnonymousFlowID != r.FlowID {
				t.Fatal("metadata changed original lifetime to remaining or renewed TTL", err)
			}
		} else {
			requireNoRateSource(t, source, err)
		}
		var expiry time.Time
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT expires_at FROM webauthn.ceremonies WHERE ceremony_id=$1`, ceremony.ID).Scan(&expiry); err != nil || !expiry.Equal(originalExpiry) {
			t.Fatal("rate source renewed original ceremony expiry", err)
		}
	}
}

func TestSignupRateSourceRejectsNilAndCanceledContexts(t *testing.T) {
	var absent *SignupService
	source, err := absent.SignupRateSource(context.Background(), passkey.SignupCeremonyRateRequest{})
	requireNoRateSource(t, source, err)
	f, s, completion := pendingSignup(t)
	r := passkey.SignupCeremonyRateRequest{SignupRequest: completion.SignupRequest, CeremonyID: completion.CeremonyID}
	source, err = s.SignupRateSource(nil, r)
	requireNoRateSource(t, source, err)
	ctx, stop := context.WithCancel(f.ctx)
	stop()
	source, err = s.SignupRateSource(ctx, r)
	if err != context.Canceled || source != (passkey.CeremonyRateSource{}) {
		t.Fatal("source lost cancellation or disclosed dimensions", err)
	}
}

// Snapshot every ordinary application table, not just row counts: metadata
// reads must not renew custody, reserve commands, charge risk or mutate effects.
// Only digests remain in memory and none of the underlying secret rows is logged.
func signupRateState(t *testing.T, f *signinFixture) string {
	t.Helper()
	rows, err := f.pool.Raw().Query(f.ctx, `SELECT schemaname,tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY schemaname,tablename`)
	if err != nil {
		t.Fatal(err)
	}
	var tables [][2]string
	for rows.Next() {
		var table [2]string
		if err := rows.Scan(&table[0], &table[1]); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	state := ""
	for _, table := range tables {
		var digest string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,',' ORDER BY to_jsonb(r)::text),'')) FROM `+pgx.Identifier{table[0], table[1]}.Sanitize()+` r`).Scan(&digest); err != nil {
			t.Fatal("source state snapshot", err)
		}
		state += table[0] + "." + table[1] + ":" + digest + ";"
	}
	return state
}
