package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestDiscoverableSigninFailsClosedAndRedactsTransport(t *testing.T) {
	var service *SigninService
	if _, err := service.DiscoverableAuthenticationOptions(context.Background(), DiscoverableSigninRequest{}); err == nil {
		t.Fatal("nil service emitted options")
	}
	if result, err := service.DiscoverableSignin(context.Background(), DiscoverableSigninCompletion{}); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("nil service authenticated")
	}
	request := DiscoverableSigninRequest{Origin: "private-origin", Network: "private-network", Device: "private-device", CorrelationID: "private-correlation"}
	completion := DiscoverableSigninCompletion{DiscoverableSigninRequest: request, CeremonyID: "private-ceremony", Response: []byte("private-response")}
	for _, value := range []any{request, completion} {
		if wire, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) || len(wire) != 0 {
			t.Fatal("implicit browser serialization accepted")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "private-") {
				t.Fatal("browser scope leaked through formatting")
			}
		}
	}
}
