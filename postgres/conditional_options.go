package postgres

import (
	"context"

	passkey "github.com/faustbrian/go-passkey"
)

// ConditionalAuthenticationOptions explicitly selects conditional browser
// presentation over genuine anonymous discovery. The existing PasskeyDiscovery
// startup policy is required. It changes neither protocol options nor durable
// mode, flow, risk, remember or expiry. Complete through DiscoverableSignin;
// read rate metadata through DiscoverableSigninRateSource. This cannot prove
// which mediation a browser actually used and does not enable browser UI.
func (s *SigninService) ConditionalAuthenticationOptions(ctx context.Context, r DiscoverableSigninRequest) (passkey.ConditionalAssertionOptions, error) {
	options, err := s.DiscoverableAuthenticationOptions(ctx, r)
	if err != nil {
		return passkey.ConditionalAssertionOptions{}, err
	}
	return passkey.NewConditionalAssertionOptions(options)
}

// KeyedConditionalAuthenticationOptions explicitly projects the fresh winner
// of existing keyed discovery. Native OptionsRequests and PasskeyDiscovery
// opt-ins remain required. Conditional and ordinary discoverable presentations
// share the same original command and immutable discovery intent: switching
// presentation on retry returns metadata only, never a replacement challenge.
// Identified mode still conflicts. Unknown outcomes retain native recovery;
// no challenge, session or proof is reconstructed here.
func (s *SigninService) KeyedConditionalAuthenticationOptions(ctx context.Context, r KeyedDiscoverableOptionsRequest) (passkey.KeyedConditionalOptionsResult, error) {
	native, err := s.KeyedDiscoverableAuthenticationOptions(ctx, r)
	out := passkey.KeyedConditionalOptionsResult{CommandID: native.CommandID, Receipt: native.Receipt, Replayed: native.Replayed}
	if err != nil || native.Replayed {
		return out, err
	}
	out.Options, err = passkey.NewConditionalAssertionOptions(native.Options)
	return out, err
}
