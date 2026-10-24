package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

var _ sessionpg.PasskeySignupSessionAuthority = (*SessionAuthority)(nil)

// RequirePasskeySignupSession checks only the exact newly created account and
// known-empty MFA authority from this original anonymous signup invocation,
// then locks its actual RP-wide credential/handle mapping. Existing-account
// assertion admission is unchanged. The session owner separately fences every
// directory/policy/session dimension before commit. No missing row, later epoch
// or reconstructed command can substitute; errors require complete Work abort.
// The borrowed Work remains serial-use and is never retained or closed here.
func (a *SessionAuthority) RequirePasskeySignupSession(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command, namespace string, record session.Session) error {
	spec, version, factorVersion, err := a.record(namespace, record)
	if err != nil || ctx == nil || version != 1 || factorVersion != 1 {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, a.config().MaximumDuration)
	defer stop()
	u, err := w.PasskeyRegistrationUser(bounded, owner, command)
	if err != nil {
		return err
	}
	if u.ID != spec.UserID || u.TenantID != spec.TenantID {
		return identity.ForbiddenError{}
	}
	factor, err := mfapg.RequirePasskeySignupFactors(bounded, w, owner, command)
	if err != nil {
		return err
	}
	if factor.Version() != factorVersion {
		return identity.ForbiddenError{}
	}
	return requireMappingAuthority(bounded, w.Query, a.config(), spec, version, true)
}
