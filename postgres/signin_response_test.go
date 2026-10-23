package postgres

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSigninCredentialSelectorBoundsAndCanonicalIdentity(t *testing.T) {
	for _, size := range []int{1, 32, 1024} {
		want := bytes.Repeat([]byte{0xa5}, size)
		response, _ := json.Marshal(map[string]string{"rawId": base64.RawURLEncoding.EncodeToString(want)})
		id, err := signinResponseCredentialID(response)
		if err != nil || !bytes.Equal(id, want) {
			t.Fatal("bounded canonical credential rejected", size, err)
		}
		clear(response)
		if !bytes.Equal(id, want) {
			t.Fatal("selector retained caller buffer")
		}
	}
	for _, response := range [][]byte{
		nil, []byte("null"), []byte("{}"), []byte(`{"rawId":null}`), []byte(`{"rawId":12}`), []byte(`{"rawId":""}`), []byte(`{"rawId":"!"}`), []byte(`{"rawId":"_x"}`), []byte(`{"rawId":"_w=="}`), []byte(`{"rawId":"_w"} trailing`), bytes.Repeat([]byte{' '}, 262145),
	} {
		if id, err := signinResponseCredentialID(response); err == nil || id != nil {
			t.Fatal("invalid selector response admitted")
		}
	}
	tooLarge, _ := json.Marshal(map[string]string{"rawId": base64.RawURLEncoding.EncodeToString(make([]byte, 1025))})
	if id, err := signinResponseCredentialID(tooLarge); err == nil || id != nil {
		t.Fatal("oversized credential admitted")
	}
}

func FuzzSigninCredentialSelector(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("null"), []byte("{}"), []byte(`{"rawId":"_w"}`), []byte(`{"rawId":"_x"}`), []byte(`{"rawId":null}`), []byte(`{"rawId":"AQ","unknown":{"nested":[]}}`), bytes.Repeat([]byte{' '}, 262145)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, response []byte) {
		id, err := signinResponseCredentialID(response)
		if err != nil {
			if id != nil {
				t.Fatal("denied selector retained partial credential")
			}
			return
		}
		if len(response) == 0 || len(response) > 262144 || len(id) == 0 || len(id) > 1024 {
			t.Fatal("selector exceeded hostile bounds")
		}
		var raw struct {
			RawID string `json:"rawId"`
		}
		if json.Unmarshal(response, &raw) != nil || base64.RawURLEncoding.EncodeToString(id) != raw.RawID {
			t.Fatal("selector admitted noncanonical identity")
		}
	})
}
