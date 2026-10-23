package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// These carriers preserve custody; they do not verify registration or commit
// identities. Native workflow tests must prove those separate owner boundaries.
func TestSignupRecordsRejectImplicitDisclosure(t *testing.T) {
	cookie, _ := signupTestToken(t)
	csrf := signupTestCSRF(t)
	key, err := identity.NewIdempotencyKey([]byte("synthetic-signup-request-key"))
	if err != nil {
		t.Fatal(err)
	}
	request := SignupRequest{CommandID: "private-signup-command", FlowID: "private-signup-flow", Cookie: cookie, Origin: "https://private-signup.example", Network: "private-signup-network", Device: "private-signup-device", CorrelationID: "private-signup-correlation"}
	completion := SignupCompletion{SignupRequest: request, CeremonyID: "private-signup-ceremony", Response: []byte("private-signup-attestation"), Label: "private-signup-label"}
	result := SignupResult{Session: session.IssueResult{Token: cookie, Cookie: http.Cookie{Name: "private-signup-cookie", Value: "synthetic-signup-session-bearer"}}, CSRF: csrf}
	keyed := KeyedSignupOptionsRequest{SignupRequest: request, IdempotencyKey: key, Caller: authorization.DecisionContext{Request: authorization.Request{Subject: authorization.Subject{ID: "private-signup-service"}, Tenant: "private-signup-tenant"}}}
	for _, test := range []struct {
		name  string
		value interface {
			MarshalJSON() ([]byte, error)
			MarshalText() ([]byte, error)
		}
	}{
		{"SignupRequest", request}, {"SignupRequest", &request},
		{"SignupCompletion", completion}, {"SignupCompletion", &completion},
		{"SignupResult", result}, {"SignupResult", &result},
		{"KeyedSignupOptionsRequest", keyed}, {"KeyedSignupOptionsRequest", &keyed},
		{"SignupRequest", SignupRequest{}},
		{"SignupCompletion", SignupCompletion{}},
		{"SignupResult", SignupResult{}},
		{"KeyedSignupOptionsRequest", KeyedSignupOptionsRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := "passkey." + test.name + "(redacted)"
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
				if got := fmt.Sprintf(format, test.value); got != want {
					t.Fatal("signup diagnostic lost redaction")
				}
				// fmt invokes the nested Formatter on exported transport fields,
				// including through pointers, slices and maps.
				for _, nested := range []any{struct{ Value any }{test.value}, []any{test.value}, map[string]any{"Value": test.value}} {
					if got := fmt.Sprintf(format, nested); strings.Contains(got, "private-signup") || strings.Contains(got, "synthetic-signup") {
						t.Fatal("nested signup diagnostic disclosed input")
					}
				}
			}
			if data, err := test.value.MarshalJSON(); data != nil || err != session.ErrSecretSerialization {
				t.Fatal("signup JSON denial lost its exact sentinel")
			}
			if data, err := test.value.MarshalText(); data != nil || err != session.ErrSecretSerialization {
				t.Fatal("signup text denial lost its exact sentinel")
			}
			for _, nested := range []any{test.value, struct{ Value any }{test.value}, []any{test.value}} {
				data, err := json.Marshal(nested)
				if data != nil || !errors.Is(err, session.ErrSecretSerialization) {
					t.Fatal("implicit signup JSON disclosed custody")
				}
				if strings.Contains(err.Error(), "private-signup") || strings.Contains(err.Error(), "synthetic-signup") {
					t.Fatal("signup serialization error disclosed input")
				}
			}
		})
	}
}

func TestSignupCompletionBorrowsResponseAndPreservesOriginalCustody(t *testing.T) {
	cookie, wire := signupTestToken(t)
	request := SignupRequest{CommandID: "original-command", FlowID: "original-flow", Cookie: cookie, Origin: "https://signup.example", Network: "original-network", Device: "original-device", CorrelationID: "original-correlation"}
	response := []byte("borrowed-attestation")
	completion := SignupCompletion{SignupRequest: request, CeremonyID: "original-ceremony", Response: response, Label: "original-label"}
	response[0] = 'B'
	if completion.Response[0] != 'B' {
		t.Fatal("carrier unexpectedly took ownership of the borrowed response")
	}
	completion.CommandID = "completion-command"
	if request.CommandID != "original-command" || completion.FlowID != request.FlowID || completion.Origin != request.Origin || completion.Network != request.Network || completion.Device != request.Device || completion.CorrelationID != request.CorrelationID {
		t.Fatal("completion did not retain original flow and trusted ingress")
	}
	// Copying a carrier must not mint another reveal permission for its cookie.
	if got, err := completion.Cookie.Reveal(); err != nil || got != wire {
		t.Fatal("completion lost original cookie custody")
	}
	if got, err := request.Cookie.Reveal(); got != "" || !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("carrier copy duplicated cookie reveal permission")
	}
}

func TestSignupResultPreservesSessionOwnerRevealCustody(t *testing.T) {
	token, wire := signupTestToken(t)
	csrf := signupTestCSRF(t)
	result := SignupResult{Session: session.IssueResult{Token: token}, CSRF: csrf}
	copy := result
	if got, err := result.Session.Token.Reveal(); err != nil || got != wire {
		t.Fatal("signup result lost session-owner custody")
	}
	if got, err := copy.Session.Token.Reveal(); got != "" || !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("signup result duplicated session reveal permission")
	}
	if got, err := result.CSRF.Reveal(); err != nil || got == "" {
		t.Fatal("signup result lost CSRF custody")
	}
	if got, err := copy.CSRF.Reveal(); got != "" || !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("signup result duplicated CSRF reveal permission")
	}
}

func signupTestToken(t *testing.T) (session.Token, string) {
	t.Helper()
	wire := base64.RawURLEncoding.EncodeToString([]byte("synthetic-signup-cookie-32-bytes!!"))
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	return token, wire
}

func signupTestCSRF(t *testing.T) session.CSRFToken {
	t.Helper()
	wire := base64.RawURLEncoding.EncodeToString([]byte("synthetic-signup-csrf-32-bytes!!"))
	token, err := session.ParseCSRFToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
