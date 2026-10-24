package postgres

import (
	"context"
	"testing"
)

func TestConditionalOptionsRequireNativeDiscoveryComposition(t *testing.T) {
	var service *SigninService
	if options, err := service.ConditionalAuthenticationOptions(context.Background(), DiscoverableSigninRequest{}); err == nil {
		if _, ok := options.Ceremony(); ok {
			t.Fatal("nil service returned a conditional ceremony")
		}
		t.Fatal("nil service accepted conditional options")
	}
	if out, err := service.KeyedConditionalAuthenticationOptions(context.Background(), KeyedDiscoverableOptionsRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("nil service admitted keyed conditional options")
	}
}
