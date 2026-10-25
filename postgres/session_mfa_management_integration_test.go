//go:build integration

package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
)

func TestPasskeyMFAInventoryAndManagementSelectionsStayExplicit(t *testing.T) {
	f := newSessionManagementTestFixture(t)
	c := f.manager.config()
	ic := f.inventory.config()
	ic.Passkey = &sessionpg.PasskeySessionServiceConfig{Repository: c.SessionRepository, Profile: c.Profile, Validation: c.Validation, Authority: f.manager.authority}
	ic.MFAPasskey = &sessionpg.MFAPasskeySessionAdmission{Profile: c.Profile, Authority: f.manager.authority}
	inventory, err := NewInventoryService(f.pool, ic)
	if err != nil {
		t.Fatal("explicit combined inventory construction", err)
	}
	// The constructor must freeze the selected owner profile, not retain this
	// mutable pointer. Ordinary provenance still selects the ordinary reader.
	ic.MFAPasskey.Profile.Audience = "foreign"
	f.listing.AttemptID, _ = identity.NewCommandID()
	page, err := inventory.List(f.ctx, f.listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal("MFA selection or caller mutation changed ordinary inventory", err)
	}
	if service, err := NewInventoryService(f.pool, ic); err == nil || service != nil {
		t.Fatal("mismatched MFA profile admitted")
	}
	ic.MFAPasskey.Profile = c.Profile
	ic.Passkey = nil
	if service, err := NewInventoryService(f.pool, ic); err == nil || service != nil {
		t.Fatal("MFA selection inferred missing base configuration")
	}
	ic.Password = &sessionpg.SessionServiceConfig{}
	if service, err := NewInventoryService(f.pool, ic); err == nil || service != nil {
		t.Fatal("MFA passkey selection entered password profile")
	}
	c.TOTP = true
	manager, err := NewSessionManagementService(f.pool, c)
	if err != nil {
		t.Fatal("explicit TOTP management construction", err)
	}
	out, err := manager.UpdateOptions(f.ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: f.request, IdempotencyKey: optionsKey(t, "mfa-does-not-adopt-ordinary")})
	if err == nil || out.CommandID != "" {
		t.Fatal("TOTP management fell back to genuine ordinary session")
	}
}
