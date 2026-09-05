package protocol

import (
	"bytes"
	"testing"
)

func TestAddressRoundTrip(t *testing.T) {
	cases := []Address{
		NewAddress("1.2.3.4", 443),
		NewAddress("2606:4700:4700::1111", 853),
		NewAddress("example.com", 80),
	}
	for _, want := range cases {
		buf := want.AppendTo(nil)
		got, err := ReadAddress(bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("ReadAddress(%v): %v", want, err)
		}
		if got.Host != want.Host || got.Port != want.Port {
			t.Errorf("round trip: got %v, want %v", got, want)
		}
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	want := Metadata{Command: CmdConnect, Address: NewAddress("example.com", 443)}
	buf := want.AppendTo(nil)
	got, err := ReadMetadata(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if got.Command != want.Command || got.Address.String() != want.Address.String() {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestHashPasswordLen(t *testing.T) {
	if h := HashPassword("secret"); len(h) != HashLen {
		t.Errorf("hash len = %d, want %d", len(h), HashLen)
	}
}
