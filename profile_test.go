package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOpaqueUserHandlePreservesStoredBytesWithoutAliasing(t *testing.T) {
	input := bytes.Repeat([]byte{37}, 32)
	handle, err := NewUserHandle(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 99
	first, err := handle.Bytes()
	if err != nil || len(first) != 32 || first[0] != 37 {
		t.Fatal("stored handle changed with input", err)
	}
	first[0] = 98
	second, _ := handle.Bytes()
	if second[0] != 37 {
		t.Fatal("returned bytes alias identity handle")
	}
	// Explicit persisted all-zero bytes are distinct from the invalid Go zero.
	if _, err := NewUserHandle(make([]byte, 32)); err != nil {
		t.Fatal("lossless import rewrote a stored handle", err)
	}
	if _, err := (UserHandle{}).Bytes(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero handle admitted", err)
	}
	for _, size := range []int{0, 1, 31, 33, 64, 1024} {
		if _, err := NewUserHandle(make([]byte, size)); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unsupported handle profile admitted", size)
		}
	}
	for _, value := range []any{handle, struct{ Handle UserHandle }{handle}} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivateValue) {
			t.Fatal("implicit handle export admitted", err)
		}
	}
	for _, value := range []any{handle, struct{ Handle UserHandle }{handle}, struct{ handle UserHandle }{handle}} {
		// fmt may show an opaque closure's code address for an unexported
		// enclosing field. Detect actual repeated handle data, not unrelated
		// short digit sequences that can occur in that address under ASLR.
		if got := fmt.Sprintf("%+v %#v", value, value); strings.Contains(got, "37 37 37 37") || strings.Contains(got, "0x25, 0x25, 0x25, 0x25") || strings.Contains(got, "JSUlJSUl") {
			t.Fatal("handle diagnostic disclosed identity bytes")
		}
	}
}

func TestOpaqueUserHandleGenerationRequiresLiveContext(t *testing.T) {
	policy := UserHandlePolicy{}
	a, err := policy.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	aa, _ := a.Bytes()
	bb, _ := b.Bytes()
	if len(aa) != 32 || bytes.Equal(aa, bb) {
		t.Fatal("opaque handles reused identity-derived output")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := policy.Generate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled generation ignored caller", err)
	}
	if _, err := policy.Generate(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context generated a handle", err)
	}
}

func TestDeviceLabelsAreBoundedLosslessDisplayMetadata(t *testing.T) {
	for _, value := range []string{"Laptop", "Clé personnelle", "  tablet  ", strings.Repeat("x", 128)} {
		label, err := NewDeviceLabel(value)
		if err != nil || label.Value() != value {
			t.Fatal("valid label was changed", err)
		}
		if got := fmt.Sprintf("%+v %#v", label, label); strings.Contains(got, value) {
			t.Fatal("label diagnostics disclosed supplied metadata")
		}
		if got := fmt.Sprintf("%+v %#v", struct{ label DeviceLabel }{label}, struct{ label DeviceLabel }{label}); strings.Contains(got, value) {
			t.Fatal("nested label diagnostics disclosed supplied metadata")
		}
	}
	for _, value := range []string{"", "  ", "\u00a0", "line\nbreak", "\x00", "\u0085", "\xff", strings.Repeat("x", 129)} {
		if _, err := NewDeviceLabel(value); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid label admitted")
		}
	}
	if (DeviceLabel{}).Value() != "" {
		t.Fatal("zero label not empty")
	}
}
