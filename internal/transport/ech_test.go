package transport

import (
	"bytes"
	"testing"
)

// A real Cloudflare key list, as published in a zone's HTTPS record.
const cfECH = "AEX+DQBB+QAgACBnGFTz8BeO0l8BRWdo0OuUszpJc/i4KugpBOXTe8vgVgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

func TestParseECHList(t *testing.T) {
	want, err := ParseECHList(cfECH)
	if err != nil {
		t.Fatal(err)
	}
	// What `dig +short HTTPS` prints is accepted as is.
	dig := `1 . alpn="h3,h2" ipv4hint=104.21.56.65 ech=` + cfECH + ` ipv6hint=2606:4700::1`
	got, err := ParseECHList(dig)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("dig line: %v", err)
	}
	if _, err := ParseECHList("not base64!"); err == nil {
		t.Fatal("garbage accepted")
	}
	if name := publicName(want); name != "cloudflare-ech.com" {
		t.Fatalf("public name %q", name)
	}
	if name := publicName([]byte{0, 1}); name != "" {
		t.Fatalf("truncated list gave %q", name)
	}
}
