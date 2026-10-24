//go:build integration

package postgres

import (
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestPasskeyNativeAlgorithmProfiles(t *testing.T) {
	f, signup := newSignupFixture(t, true)
	for _, profile := range []struct {
		algorithms []webauthn.Algorithm
		valid      bool
	}{
		{nil, true}, {[]webauthn.Algorithm{webauthn.ES256}, true}, {[]webauthn.Algorithm{webauthn.EdDSA}, true},
		{[]webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}, true}, {[]webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}, true},
		{[]webauthn.Algorithm{}, false}, {[]webauthn.Algorithm{webauthn.ES256, webauthn.ES256}, false}, {[]webauthn.Algorithm{webauthn.EdDSA, webauthn.EdDSA}, false},
		{[]webauthn.Algorithm{-257}, false}, {[]webauthn.Algorithm{99}, false}, {[]webauthn.Algorithm{webauthn.ES256, 99}, false}, {[]webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA, webauthn.ES256}, false},
	} {
		algorithms, valid := profile.algorithms, profile.valid
		e := f.service.config()
		e.Protocol.Algorithms = slices.Clone(algorithms)
		enrollment, err := NewEnrollmentService(f.pool, e)
		if (err == nil) != valid {
			t.Fatalf("enrollment profile %v: valid=%v: %v", algorithms, valid, err)
		}
		if valid && !slices.Equal(enrollment.config().Protocol.Algorithms, algorithms) {
			t.Fatal("enrollment changed algorithm order")
		}
		c := f.signin.config()
		c.Protocol.Algorithms = slices.Clone(algorithms)
		signin, err := NewSigninService(f.pool, c)
		if (err == nil) != valid {
			t.Fatalf("signin profile %v: valid=%v: %v", algorithms, valid, err)
		}
		if valid {
			retained := signin.config().Protocol.Algorithms
			if !slices.Equal(retained, algorithms) || (retained == nil) != (algorithms == nil) {
				t.Fatal("signin changed original algorithm profile")
			}
			if len(c.Protocol.Algorithms) > 0 {
				c.Protocol.Algorithms[0] = 99
				if !slices.Equal(signin.config().Protocol.Algorithms, algorithms) {
					t.Fatal("signin retained caller algorithm storage")
				}
			}
		}
		config := signup.core.config()
		config.Protocol.Algorithms = slices.Clone(algorithms)
		_, err = NewSignupService(f.pool, SignupConfig{Protocol: config.Protocol, Profile: config.Profile, Coordinator: config.Coordinator, Authorization: config.Authorization, Clock: config.Clock, Flow: config.Flow, Session: config.Session, CSRF: config.CSRF, Repository: config.Repository, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: signup.evaluation, ConfigurationID: "signup-native", Keys: f.riskConfig.EvidenceKeys}, Counters: f.riskConfig})
		if (err == nil) != valid {
			t.Fatalf("signup profile %v: valid=%v: %v", algorithms, valid, err)
		}
		c = f.signin.config()
		c.Protocol.Algorithms = slices.Clone(algorithms)
		management := SessionManagementConfig{Protocol: c.Protocol, Profile: c.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: c.Profile.Audience, Clock: c.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.lookup}}, SessionRepository: c.Repository, OptionsRequests: signup.optionsRequests, Coordinator: c.Coordinator, Authorization: c.Authorization, Clock: c.Clock, Transport: session.CredentialBearer, Risk: f.service.config().Risk, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion}
		for _, constructor := range []func() (SessionManagementConfig, error){
			func() (SessionManagementConfig, error) {
				s, err := NewSessionManagementService(f.pool, management)
				if err != nil {
					return SessionManagementConfig{}, err
				}
				return s.config(), nil
			},
			func() (SessionManagementConfig, error) {
				s, err := NewSessionEnrollmentService(f.pool, management)
				if err != nil {
					return SessionManagementConfig{}, err
				}
				return s.owner.config(), nil
			},
			func() (SessionManagementConfig, error) {
				s, err := NewSessionDeletionService(f.pool, management)
				if err != nil {
					return SessionManagementConfig{}, err
				}
				return s.owner.config(), nil
			},
		} {
			retained, err := constructor()
			if (err == nil) != valid {
				t.Fatalf("current-session profile %v: valid=%v: %v", algorithms, valid, err)
			}
			if valid && (!slices.Equal(retained.Protocol.Algorithms, algorithms) || (retained.Protocol.Algorithms == nil) != (algorithms == nil)) {
				t.Fatal("current-session constructor changed original algorithm profile")
			}
		}
	}
}
