package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func TestOriginalCeremonyRateDataRejectsImplicitDisclosure(t *testing.T) {
	for _, value := range []any{
		CeremonyRateSource{CeremonyID: "private-ceremony", Lifetime: 5 * time.Minute, Kind: RateSourceUser, UserID: "private-user"},
		CeremonyRateSource{CeremonyID: "private-ceremony", Lifetime: 5 * time.Minute, Kind: RateSourceIdentifier, Identifier: "private@example.test"},
		CeremonyRateSource{CeremonyID: "private-ceremony", Lifetime: 5 * time.Minute, Kind: RateSourceAnonymousFlow, AnonymousFlowID: "private-flow"},
		RegistrationCeremonyRateRequest{RegistrationRequest: RegistrationRequest{Origin: "https://private.example", Network: "private-network", Device: "private-device"}, CeremonyID: "private-ceremony"},
		SigninCeremonyRateRequest{SigninRequest: SigninRequest{Identifier: "private@example.test", FlowID: "private-flow"}, CeremonyID: "private-ceremony"},
		DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: DiscoverableSigninRequest{FlowID: "private-flow"}, CeremonyID: "private-ceremony"},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			want := fmt.Sprintf("%T(redacted)", value)
			if got := fmt.Sprintf(format, value); got != want {
				t.Fatal("original rate custody escaped through diagnostics")
			}
		}
		if data, err := json.Marshal(value); data != nil || !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("original rate custody escaped through JSON", err)
		}
		marshaler := value.(interface{ MarshalText() ([]byte, error) })
		if data, err := marshaler.MarshalText(); data != nil || err != session.ErrSecretSerialization {
			t.Fatal("original rate custody escaped through text", err)
		}
	}
}
