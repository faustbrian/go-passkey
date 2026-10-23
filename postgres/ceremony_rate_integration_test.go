//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func requireNoRateSource(t *testing.T, source passkey.CeremonyRateSource, err error) {
	t.Helper()
	if err == nil || source != (passkey.CeremonyRateSource{}) {
		t.Fatal("denied custody disclosed original rate dimensions", err)
	}
}

func TestRegistrationRateSourceAuthenticatesOriginalCustodyWithoutConsumption(t *testing.T) {
	f, completion := pendingEnrollment(t)
	request := passkey.RegistrationCeremonyRateRequest{RegistrationRequest: completion.RegistrationRequest, CeremonyID: completion.CeremonyID}
	for _, scenario := range []string{"missing-proof", "wrong-proof-action", "foreign-session", "foreign-origin", "foreign-ceremony", "foreign-caller", "target-override"} {
		t.Run(scenario, func(t *testing.T) {
			r := request
			r.Primary.Caller = request.Primary.Caller.Clone()
			switch scenario {
			case "missing-proof":
				r.Primary.Proof = auth.ReauthenticationProof{}
			case "wrong-proof-action":
				r.Primary.Proof.Action = enrollmentOperation(false).OperationID
			case "foreign-session":
				r.Primary.Session = auth.NewBearerCredential("synthetic-foreign-session")
			case "foreign-origin":
				r.Origin = "https://other.example"
			case "foreign-ceremony":
				id, _ := identity.NewCommandID()
				r.CeremonyID = string(id)
			case "foreign-caller":
				r.Primary.Caller.Request.Subject.ID = "other-user"
			case "target-override":
				r.Primary.TargetSubjectID = "other-user"
			}
			source, err := f.service.RegistrationRateSource(f.ctx, r)
			requireNoRateSource(t, source, err)
		})
	}
	for range 2 {
		source, err := f.service.RegistrationRateSource(f.ctx, request)
		if err != nil || source.CeremonyID != completion.CeremonyID || source.Lifetime != 5*time.Minute || source.Kind != passkey.RateSourceUser || source.UserID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" || source.Identifier != "" || source.AnonymousFlowID != "" {
			t.Fatal("original authenticated ceremony rate source absent", err)
		}
	}
	if _, err := f.service.Register(f.ctx, completion); err != nil {
		t.Fatal("rate-source read consumed genuine action proof or ceremony", err)
	}
	source, err := f.service.RegistrationRateSource(f.ctx, request)
	if err != nil || source.CeremonyID != completion.CeremonyID {
		t.Fatal("historical consumed ceremony lost original rate metadata", err)
	}
	if _, err := f.service.Register(f.ctx, completion); err == nil {
		t.Fatal("rate metadata authorized repeated enrollment mutation")
	}
}

func TestRegistrationRateSourceRejectsActuallyExpiredOriginalProof(t *testing.T) {
	var offset time.Duration
	f, completion := pendingEnrollment(t, func() time.Time { return time.Now().Add(offset) })
	request := passkey.RegistrationCeremonyRateRequest{RegistrationRequest: completion.RegistrationRequest, CeremonyID: completion.CeremonyID}
	if _, err := f.service.RegistrationRateSource(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	offset = 6 * time.Minute
	source, err := f.service.RegistrationRateSource(f.ctx, request)
	requireNoRateSource(t, source, err)
}

func TestSigninRateSourceBindsOriginalIdentifierWithoutEligibilityOracle(t *testing.T) {
	f := newSigninFixture(t)
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
			before := rateAdmissionCount(t, f)
			for range 2 {
				source, err := f.signin.SigninRateSource(f.ctx, request)
				if err != nil || source.CeremonyID != ceremony.ID || source.Lifetime != 5*time.Minute || source.Kind != passkey.RateSourceIdentifier || source.Identifier != identifier || source.UserID != "" || source.AnonymousFlowID != "" {
					t.Fatal("original identified source disclosed eligibility or lost exact identifier", err)
				}
			}
			if rateAdmissionCount(t, f) != before {
				t.Fatal("rate-source read performed another native risk admission")
			}
			wrong := request
			wrong.Identifier = "changed@example.test"
			source, err := f.signin.SigninRateSource(f.ctx, wrong)
			requireNoRateSource(t, source, err)
			wrong = request
			wrong.Cookie = session.Token{}
			source, err = f.signin.SigninRateSource(f.ctx, wrong)
			requireNoRateSource(t, source, err)
			wrong = request
			wrong.FlowID = f.request(t, session.BrowserSession).FlowID
			source, err = f.signin.SigninRateSource(f.ctx, wrong)
			requireNoRateSource(t, source, err)
			discovery := passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: discoverableRequest(r), CeremonyID: ceremony.ID}
			source, err = f.signin.DiscoverableSigninRateSource(f.ctx, discovery)
			requireNoRateSource(t, source, err)
			config := f.signin.config()
			config.Clock = signinClock{stamp: time.Now().Add(6 * time.Minute)}
			advanced, err := NewSigninService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			source, err = advanced.SigninRateSource(f.ctx, request)
			requireNoRateSource(t, source, err)
		})
	}
}

func TestSigninRateSourceMetadataCannotRepeatConsumedCompletion(t *testing.T) {
	f := newSigninFixture(t)
	completion, _ := f.pending(t)
	request := passkey.SigninCeremonyRateRequest{SigninRequest: completion.SigninRequest, CeremonyID: completion.CeremonyID}
	if _, err := f.signin.SigninRateSource(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	issued, err := f.signin.Signin(f.ctx, completion)
	if err != nil || issued.Session.Token == (session.Token{}) {
		t.Fatal("rate-source read consumed original flow or ceremony", err)
	}
	source, err := f.signin.SigninRateSource(f.ctx, request)
	if err != nil || source.CeremonyID != completion.CeremonyID {
		t.Fatal("historical flow lost original rate metadata", err)
	}
	if replay, err := f.signin.Signin(f.ctx, completion); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
		t.Fatal("rate metadata authorized repeated authentication")
	}
	passkeyJourneyReadInventoryLogout(t, f, issued)
}

func TestDiscoverableRateSourceNeverSelectsAccountAndRetainsRealCompletion(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	completion, _ := f.discoverablePending(t)
	request := passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: completion.DiscoverableSigninRequest, CeremonyID: completion.CeremonyID}
	if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity.identifiers WHERE identifier_id='signin-email'`); err != nil {
		t.Fatal(err)
	}
	before := rateAdmissionCount(t, f)
	for range 2 {
		source, err := f.signin.DiscoverableSigninRateSource(f.ctx, request)
		if err != nil || source.CeremonyID != completion.CeremonyID || source.Lifetime != 5*time.Minute || source.Kind != passkey.RateSourceAnonymousFlow || source.AnonymousFlowID != completion.FlowID || source.UserID != "" || source.Identifier != "" {
			t.Fatal("discovery source selected an account or changed original ceremony", err)
		}
	}
	if rateAdmissionCount(t, f) != before {
		t.Fatal("discovery source performed another native risk admission")
	}
	wrong := request
	wrong.Cookie = session.Token{}
	source, err := f.signin.DiscoverableSigninRateSource(f.ctx, wrong)
	requireNoRateSource(t, source, err)
	wrong = request
	wrong.Origin = "https://other.example"
	source, err = f.signin.DiscoverableSigninRateSource(f.ctx, wrong)
	requireNoRateSource(t, source, err)
	identified := passkey.SigninCeremonyRateRequest{SigninRequest: discoverableSigninRequest(completion.DiscoverableSigninRequest), CeremonyID: completion.CeremonyID}
	identified.Identifier = "passkey@example.test"
	source, err = f.signin.SigninRateSource(f.ctx, identified)
	requireNoRateSource(t, source, err)
	config := f.signin.config()
	config.Clock = signinClock{stamp: time.Now().Add(6 * time.Minute)}
	advanced, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	source, err = advanced.DiscoverableSigninRateSource(f.ctx, request)
	requireNoRateSource(t, source, err)
	issued, err := f.signin.DiscoverableSignin(f.ctx, completion)
	if err != nil || issued.Session.Token == (session.Token{}) {
		t.Fatal("source read consumed identifier-free ceremony", err)
	}
	source, err = f.signin.DiscoverableSigninRateSource(f.ctx, request)
	if err != nil || source.CeremonyID != completion.CeremonyID {
		t.Fatal("historical anonymous flow lost original rate metadata", err)
	}
	if replay, err := f.signin.DiscoverableSignin(f.ctx, completion); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
		t.Fatal("anonymous rate metadata authorized repeated authentication")
	}
	passkeyJourneyReadInventoryLogout(t, f, issued)
}

func TestSigninRateSourceRetainsOriginalCeremonyLifetimeWithoutRenewal(t *testing.T) {
	f := newDiscoverableSigninFixture(t)
	config := f.signin.config()
	config.Flow.FlowTTL = 10 * time.Minute
	service, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	f.signin = service
	completion, _ := f.discoverablePending(t)
	request := passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: completion.DiscoverableSigninRequest, CeremonyID: completion.CeremonyID}
	config.Clock = signinClock{stamp: time.Now().Add(time.Minute)}
	later, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	source, err := later.DiscoverableSigninRateSource(f.ctx, request)
	if err != nil || source.CeremonyID != completion.CeremonyID || source.Lifetime != 5*time.Minute {
		t.Fatal("source converted original ceremony policy to remaining or renewed TTL", err)
	}
	config.Clock = signinClock{stamp: time.Now().Add(6 * time.Minute)}
	expired, err := NewSigninService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	// The actual original flow has a ten-minute TTL; the separate original
	// protocol ceremony has expired at five. Neither duration is rewritten.
	source, err = expired.DiscoverableSigninRateSource(f.ctx, request)
	requireNoRateSource(t, source, err)
}

func TestSigninRateSourceRejectsChangedOriginalDirectoryGenerations(t *testing.T) {
	for _, mode := range []string{"identified", "discoverable"} {
		for _, generation := range []string{"global", "tenant"} {
			t.Run(mode+"/"+generation, func(t *testing.T) {
				var f *signinFixture
				if mode == "discoverable" {
					f = newDiscoverableSigninFixture(t)
				} else {
					f = newSigninFixture(t)
				}
				r := f.request(t, session.BrowserSession)
				var ceremonyID string
				if mode == "discoverable" {
					options, err := f.signin.DiscoverableAuthenticationOptions(f.ctx, discoverableRequest(r))
					if err != nil {
						t.Fatal(err)
					}
					ceremony, _ := options.Ceremony()
					ceremonyID = ceremony.ID
				} else {
					options, err := f.signin.AuthenticationOptions(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					ceremony, _ := options.Ceremony()
					ceremonyID = ceremony.ID
				}
				r.CommandID, _ = identity.NewCommandID()
				read := func() (passkey.CeremonyRateSource, error) {
					if mode == "discoverable" {
						return f.signin.DiscoverableSigninRateSource(f.ctx, passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: discoverableRequest(r), CeremonyID: ceremonyID})
					}
					return f.signin.SigninRateSource(f.ctx, passkey.SigninCeremonyRateRequest{SigninRequest: r, CeremonyID: ceremonyID})
				}
				if source, err := read(); err != nil || source.CeremonyID != ceremonyID {
					t.Fatal("genuine original directory source absent before generation advance", err)
				}
				query := `UPDATE identity.global_authorities SET version=version+1 WHERE authority_id='passkey-fixture'`
				if generation == "tenant" {
					query = `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id='01ARZ3NDEKTSV4RRFFQ69G5FAV'`
				}
				changed, err := f.pool.Raw().Exec(f.ctx, query)
				if err != nil || changed.RowsAffected() != 1 {
					t.Fatal("original directory generation did not advance", err)
				}
				source, err := read()
				requireNoRateSource(t, source, err)
			})
		}
	}
}

func rateAdmissionCount(t *testing.T, f *signinFixture) int {
	t.Helper()
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM passkey_admission.durable_counter_attempts`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestNilCeremonyRateSourcesDeny(t *testing.T) {
	var enrollment *EnrollmentService
	var signin *SigninService
	source, err := enrollment.RegistrationRateSource(context.Background(), passkey.RegistrationCeremonyRateRequest{})
	requireNoRateSource(t, source, err)
	source, err = signin.SigninRateSource(context.Background(), passkey.SigninCeremonyRateRequest{})
	requireNoRateSource(t, source, err)
	source, err = signin.DiscoverableSigninRateSource(context.Background(), passkey.DiscoverableCeremonyRateRequest{})
	requireNoRateSource(t, source, err)
}
