package passkey

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzDeviceLabel(f *testing.F) {
	for _, value := range []string{"Laptop", "Clé", "  phone  ", "", "\xff", "\x00", strings.Repeat("x", 129)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, input string) {
		label, err := NewDeviceLabel(input)
		if err != nil {
			return
		}
		if label.Value() != input {
			t.Fatal("accepted label was silently changed")
		}
		rebuilt, err := NewDeviceLabel(label.Value())
		if err != nil || rebuilt.Value() != input {
			t.Fatal("accepted label did not round trip")
		}
	})
}

func FuzzUserHandle(f *testing.F) {
	for _, input := range [][]byte{nil, make([]byte, 31), make([]byte, 32), bytes.Repeat([]byte{255}, 32), make([]byte, 33)} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		handle, err := NewUserHandle(input)
		if err != nil {
			if len(input) == 32 {
				t.Fatal("stored bytes cannot be imported losslessly")
			}
			return
		}
		output, err := handle.Bytes()
		if err != nil || !bytes.Equal(input, output) || len(output) != 32 {
			t.Fatal("handle projection changed original identity")
		}
		output[0] ^= 255
		retained, _ := handle.Bytes()
		if !bytes.Equal(retained, input) {
			t.Fatal("handle projection aliases its immutable storage")
		}
	})
}
