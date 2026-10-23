package postgres

import (
	"context"
	"reflect"
	"testing"

	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

// These assignments exercise existing method signatures as a neutral consumer,
// not merely similarly shaped records that need transport-owned conversion.
var (
	_ func(context.Context, passkey.RegistrationRequest) (webauthn.RegistrationOptions, error)                       = (*EnrollmentService)(nil).RegistrationOptions
	_ func(context.Context, passkey.RegistrationCompletion) (webauthn.VerifiedRegistration, error)                   = (*EnrollmentService)(nil).Register
	_ func(context.Context, passkey.SigninRequest) (webauthn.AssertionOptions, error)                                = (*SigninService)(nil).AuthenticationOptions
	_ func(context.Context, passkey.SigninCompletion) (passkey.SigninResult, error)                                  = (*SigninService)(nil).Signin
	_ func(context.Context, passkey.DiscoverableSigninRequest) (webauthn.AssertionOptions, error)                    = (*SigninService)(nil).DiscoverableAuthenticationOptions
	_ func(context.Context, passkey.DiscoverableSigninCompletion) (passkey.SigninResult, error)                      = (*SigninService)(nil).DiscoverableSignin
	_ func(context.Context, passkey.KeyedRegistrationOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error) = (*EnrollmentService)(nil).KeyedRegistrationOptions
	_ func(context.Context, passkey.KeyedSigninOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)          = (*SigninService)(nil).KeyedAuthenticationOptions
	_ func(context.Context, passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)    = (*SigninService)(nil).KeyedDiscoverableAuthenticationOptions
)

func TestTransportAliasesPreserveExactPublicTypeIdentity(t *testing.T) {
	pairs := [][2]any{
		{RegistrationRequest{}, passkey.RegistrationRequest{}},
		{RegistrationCompletion{}, passkey.RegistrationCompletion{}},
		{SigninRequest{}, passkey.SigninRequest{}},
		{SigninCompletion{}, passkey.SigninCompletion{}},
		{SigninResult{}, passkey.SigninResult{}},
		{DiscoverableSigninRequest{}, passkey.DiscoverableSigninRequest{}},
		{DiscoverableSigninCompletion{}, passkey.DiscoverableSigninCompletion{}},
		{KeyedRegistrationOptionsRequest{}, passkey.KeyedRegistrationOptionsRequest{}},
		{KeyedSigninOptionsRequest{}, passkey.KeyedSigninOptionsRequest{}},
		{KeyedDiscoverableOptionsRequest{}, passkey.KeyedDiscoverableOptionsRequest{}},
		{KeyedRegistrationOptionsResult{}, passkey.KeyedRegistrationOptionsResult{}},
		{KeyedAssertionOptionsResult{}, passkey.KeyedAssertionOptionsResult{}},
		{InventoryRequest{}, passkey.InventoryRequest{}},
		{CredentialMetadata{}, passkey.CredentialMetadata{}},
		{InventoryPage{}, passkey.InventoryPage{}},
		{RegistrationRequest{}.Primary, password.ActionPrimaryRequest{}},
		{RegistrationRequest{}.Primary, passwordpg.ActionPrimaryRequest{}},
	}
	for _, pair := range pairs {
		if reflect.TypeOf(pair[0]) != reflect.TypeOf(pair[1]) {
			t.Fatal("released adapter type is not an exact neutral alias")
		}
	}
}
