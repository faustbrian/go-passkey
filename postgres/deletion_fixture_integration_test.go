//go:build integration

package postgres

import (
	"bytes"
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func deletionFixture(t *testing.T, f *enrollmentFixture) (*DeletionService, *ManagementService, *InventoryService, InventoryRequest) {
	t.Helper()
	base := passwordpg.PasskeyManagementReauthenticationMigrationSource{Base: passwordpg.PasskeyReauthenticationMigrationSource{Base: passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	history, err := (passwordpg.PasskeyDeletionReauthenticationMigrationSource{Base: base, Version: 13}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("owned deletion proof suffix", err)
	}
	proof := f.proofConfig
	proof.Targets = append(slices.Clone(proof.Targets), passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.passkey.delete", Audience: "passkey-enrollment"})
	f.proofs, err = passwordpg.NewReauthenticationService(f.pool, proof)
	if err != nil {
		t.Fatal(err)
	}
	manager, inventory, listing := managementFixture(t, f)
	c := manager.config()
	c.Source, err = passwordpg.NewActionPrimarySource(f.proofs, passwordpg.ActionPrimaryConfig{Action: "identity.passkey.delete", Audience: c.ProofAudience, MaximumAge: 5 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := passwordpg.NewPasskeyRemovalRecoverySource(deletionResetFixture(t, f, c.RequestKeys))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewDeletionService(f.pool, DeletionConfig{ManagementConfig: c, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	return owner, manager, inventory, listing
}

func deletionRequest(t *testing.T, f *enrollmentFixture, metadata CredentialMetadata, key string) passkey.DeleteRequest {
	t.Helper()
	r := f.actionRequest(t, "identity.passkey.delete")
	r.Primary.CommandID, r.Primary.RecordID = "", ""
	return passkey.DeleteRequest{Primary: r.Primary, ReferenceID: identity.CredentialID(metadata.ReferenceID), ExpectedVersion: metadata.Version, IdempotencyKey: optionsKey(t, key), Network: r.Network}
}

// This selects the real public request/completion, issuance, encrypted delivery,
// password, factor, risk and session owners. Deletion never sends a reset or
// borrows password material; the concrete recovery source owns current checks.
func deletionResetFixture(t *testing.T, f *enrollmentFixture, requestKeys kernel.RequestKeyConfig) *passwordpg.ResetService {
	t.Helper()
	const origin = "https://identity.example"
	signer, err := capability.NewHMACSHA256Signer("deletion-recovery", bytes.Repeat([]byte{93}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{93}, 32))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "deletion-recovery", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "deletion-recovery-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	address, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"deletion-recovery": bytes.Repeat([]byte{96}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	mail, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "deletion-recovery", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {103}}, ActiveEnvelopeKeyID: "deletion-recovery", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "password-reset", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 1, Profiles: profiles, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	c := f.service.config()
	var screeningCalls atomic.Int32
	t.Cleanup(func() {
		if screeningCalls.Load() != 0 {
			t.Error("passkey removal invoked password reset screening")
		}
	})
	reset, err := passwordpg.NewResetService(f.pool, passwordpg.ResetConfig{
		Repository: passwordpg.Config{MaximumDuration: 3 * time.Second, HashPolicy: primitive.DefaultPolicy()}, ConfigurationID: "deletion-recovery", PolicyID: c.PolicyID, GlobalAuthorityID: "passkey-fixture", AuthorizationNamespace: "users", Origins: []string{origin}, ActiveEnvelopeKeyID: "deletion-recovery", IdentifierKey: [32]byte{97}, Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Coordinator: c.Coordinator,
		Profile: password.ResetProfileConfig{Issuer: origin, Audience: "reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{origin + "/reset"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {95}}},
		Issuer:  issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "reset", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {94}}, PreparationTimeout: time.Second},
		Screening: password.HashPreparationConfig{Primitive: f.proofConfig.Verifier.Primitive, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: f.proofConfig.Verifier.DummyHash, Policy: policy, Now: time.Now, Collect: func(ctx context.Context, scope risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
			// The provider observation is the test seam, not recovery authority.
			// Removal must never invoke it or execute credential-creation work.
			screeningCalls.Add(1)
			signal, err := policy.PasswordSignal(ctx, scope, risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)})
			return []risk.Signal{signal}, err
		}},
		Risk:    f.proofConfig.Risk,
		Request: &passwordpg.ResetRequestConfig{Address: address, RequestKeys: requestKeys, Lifetime: time.Minute, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "deletion-recovery", ActiveEnvelopeKey: "reset-issuer", EnvelopeKeys: map[string][]byte{"reset-issuer": bytes.Repeat([]byte{104}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "deletion-recovery", HMAC: bytes.Repeat([]byte{93}, 32)}}, Clock: time.Now}, Delivery: passwordpg.SignupDeliveryConfig{Owner: mail, Renderer: renderer, Resolver: resolver, Endpoint: origin + "/password/reset", TemplateID: "password-reset", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{105}, Timeout: time.Second}},
	}, keys)
	if err != nil {
		t.Fatal("real password-recovery composition", err)
	}
	return reset
}
