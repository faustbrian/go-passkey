//go:build integration

package postgres

import (
	"encoding/json"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestPasskeySessionEnrollmentCookieRequiresOriginalCSRFAcrossPhases(t *testing.T) {
	for _, stage := range []string{"A", "B", "C"} {
		t.Run(stage, func(t *testing.T) {
			var f *sessionManagementTestFixture
			var s *SessionEnrollmentService
			var intent passkey.SessionEnrollmentRequestSpec
			var b passkey.SessionEnrollmentAuthorizationSpec
			var c passkey.SessionEnrollmentCompletionSpec
			if stage == "C" {
				f, s, intent, c = pendingSessionEnrollmentCompletion(t, true)
			} else {
				f, s, intent, b = pendingSessionEnrollmentAuthorization(t, true)
			}
			original := intent
			for _, missing := range []bool{false, true} {
				intent.CSRFToken = session.CSRFToken{}
				if !missing {
					var err error
					intent.CSRFToken, err = session.NewCSRFToken()
					if err != nil {
						t.Fatal(err)
					}
				}
				bad := passkey.NewSessionEnrollmentRequest(intent)
				switch stage {
				case "A":
					out, err := s.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: bad, IdempotencyKey: optionsKey(t, "bad-cookie-A")})
					if _, present := out.Options.Ceremony(); err == nil || present {
						t.Fatal("foreign cookie CSRF disclosed assertion options", err)
					}
				case "B":
					r := b
					r.SessionEnrollmentRequest = bad
					out, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(r))
					if _, present := out.Options.Ceremony(); err == nil || present {
						t.Fatal("foreign cookie CSRF authorized enrollment", err)
					}
				case "C":
					r := c
					r.SessionEnrollmentRequest = bad
					if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(r)); err == nil {
						t.Fatal("foreign cookie CSRF enrolled a credential")
					}
				}
				assertSessionEnrollmentUnchanged(t, f)
			}
			switch stage {
			case "A":
				out, err := s.EnrollmentAssertionOptions(f.ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(original), IdempotencyKey: optionsKey(t, "genuine-cookie-A")})
				if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("genuine cookie CSRF assertion denied", err)
				}
			case "B":
				if out, err := s.RegistrationOptions(f.ctx, passkey.NewSessionEnrollmentAuthorization(b)); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("genuine cookie CSRF authorization denied", err)
				}
			case "C":
				if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c)); err != nil {
					t.Fatal("genuine cookie CSRF enrollment denied", err)
				}
			}
		})
	}
}

func TestPasskeySessionEnrollmentRejectsWithdrawnCompletionAuthority(t *testing.T) {
	for _, mode := range []string{"session", "user", "credential", "mapping", "factor", "missing-factor", "passkey-epoch", "policy", "parent", "missing-ceiling", "expired-ceiling", "rp-version"} {
		t.Run(mode, func(t *testing.T) {
			f, s, _, c := pendingSessionEnrollmentCompletion(t, false)
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
			case "parent":
				if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity_passkey.signin_contexts WHERE ceremony_id=$1`, c.CeremonyID); err != nil {
					t.Fatal(err)
				}
			case "missing-ceiling", "expired-ceiling":
				record, err := f.issued.Session.Session.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				p := &sessionEnrollmentInvocation{service: s, record: record}
				parent, err := p.loadContext(f.ctx, c.CeremonyID)
				if err != nil {
					t.Fatal(err)
				}
				// Corrupt only native retained metadata, not a genuine protocol
				// record/digest. The independent protocol tests prove real elapsed
				// expiry; this partition proves native absence/past-value denial.
				parent.AuthorizationExpires = time.Time{}
				if mode == "expired-ceiling" {
					parent.AuthorizationExpires = time.Now().UTC().Add(-time.Second)
				}
				wire, err := json.Marshal(parent)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.signin_contexts SET admission=$1 WHERE ceremony_id=$2`, wire, c.CeremonyID); err != nil {
					t.Fatal(err)
				}
			case "rp-version":
				config := s.owner.config()
				config.Protocol.RelyingParty.Version++
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
			if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c)); err == nil {
				t.Fatal("withdrawn original authority enrolled a key")
			}
			assertSessionEnrollmentUnchanged(t, f)
		})
	}
}

func TestPasskeySessionEnrollmentRetainsGenuineOriginalAuthorizationCeiling(t *testing.T) {
	f, s, _, c := pendingSessionEnrollmentCompletion(t, false)
	record, err := f.issued.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	p := &sessionEnrollmentInvocation{service: s, record: record}
	parent, err := p.loadContext(f.ctx, c.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	lookup := webauthn.Lookup{Context: webauthn.CeremonyContext{CommandID: c.CommandID, TenantID: record.TenantID, UserID: record.UserID, ActorID: identity.ActorID(record.UserID), CorrelationID: string(c.CommandID)}, RPID: s.owner.config().Protocol.RelyingParty.ID}
	lookup.CeremonyID = parent.Parent
	original, err := s.owner.protocol.LoadCeremony(f.ctx, lookup)
	if err != nil || parent.AuthorizationExpires.IsZero() || !parent.AuthorizationExpires.Equal(original.ExpiresAt) {
		t.Fatal("B renewed or lost original genuine assertion expiry", err)
	}
	lookup.CeremonyID = c.CeremonyID
	registration, err := s.owner.protocol.LoadCeremony(f.ctx, lookup)
	if err != nil || !registration.ExpiresAt.After(original.ExpiresAt) {
		t.Fatal("fixture did not distinguish new protocol TTL from original authority", err)
	}
	if _, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c)); err != nil {
		t.Fatal(err)
	}
	committed, err := p.loadContext(f.ctx, string(c.CommandID))
	if err != nil || !committed.AuthorizationExpires.Equal(original.ExpiresAt) {
		t.Fatal("C renewed original authorization ceiling", err)
	}
	wire, err := json.Marshal(committed)
	if err != nil || len(wire) > 4096 {
		t.Fatal("native original context exceeded bounded storage", err)
	}
}

func TestPasskeySessionEnrollmentPreservesOptionalEmptyLabel(t *testing.T) {
	f, s, _, c := pendingSessionEnrollmentCompletion(t, false, "")
	out, err := s.Register(f.ctx, passkey.NewSessionEnrollmentCompletion(c))
	if err != nil {
		t.Fatal("unlabeled resident-key enrollment failed", err)
	}
	fields, err := out.Bindings()
	if err != nil || fields.Credential == nil || fields.Credential.Label != "" {
		t.Fatal("empty label was substituted", err)
	}
	var missing bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT display_label IS NULL FROM identity_passkey.credentials WHERE reference_id=$1`, string(c.CommandID)).Scan(&missing); err != nil || !missing {
		t.Fatal("absent label did not retain existing storage semantics", err)
	}
}
