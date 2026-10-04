package transport

import (
	"bytes"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// clientHello returns the ClientHello record fp would send for sni.
func clientHello(t *testing.T, fp, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := utls.UClient(c1, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, clientHelloID(fp))
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	raw := u.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}, raw...)
}

func TestFragmentRecords(t *testing.T) {
	const sni = "cdn.example.ir"
	hello := clientHello(t, "firefox", sni)
	f := &Fragment{Records: true, MinSize: 20, MaxSize: 60}
	pieces := f.split(hello, sni)
	if len(pieces) < 5 {
		t.Fatalf("only %d pieces for a %d-byte hello", len(pieces), len(hello))
	}
	var body []byte
	for i, p := range pieces {
		if len(p) < recordHeaderLen || p[0] != 0x16 || p[1] != hello[1] || p[2] != hello[2] {
			t.Fatalf("piece %d is not a handshake record: % x", i, p[:min(5, len(p))])
		}
		n := int(p[3])<<8 | int(p[4])
		if n == 0 || n != len(p)-recordHeaderLen {
			t.Fatalf("piece %d: record length %d, payload %d", i, n, len(p)-recordHeaderLen)
		}
		if bytes.Contains(p, []byte(sni)) {
			t.Fatalf("piece %d carries the whole server name", i)
		}
		body = append(body, p[recordHeaderLen:]...)
	}
	if !bytes.Equal(body, hello[recordHeaderLen:]) {
		t.Fatal("record bodies do not reassemble to the hello")
	}
}

func TestFragmentTCP(t *testing.T) {
	const sni = "cdn.example.ir"
	hello := clientHello(t, "firefox", sni)
	trailer := []byte("after")
	f := &Fragment{MinSize: 30, MaxSize: 80}
	pieces := f.split(append(append([]byte{}, hello...), trailer...), sni)
	var all []byte
	for i, p := range pieces {
		if bytes.Contains(p, []byte(sni)) {
			t.Fatalf("piece %d carries the whole server name", i)
		}
		all = append(all, p...)
	}
	if !bytes.Equal(all, append(hello, trailer...)) {
		t.Fatal("pieces do not concatenate to the input")
	}
}

func TestFragmentLeavesOtherWritesAlone(t *testing.T) {
	f := &Fragment{Records: true, MinSize: 1, MaxSize: 2}
	for _, p := range [][]byte{[]byte("GET / HTTP/1.1\r\n"), {0x16, 0x03, 0x01, 0x10, 0x00, 1, 2}} {
		if got := f.split(p, "x"); len(got) != 1 || !bytes.Equal(got[0], p) {
			t.Fatalf("split(%q) = %d pieces, want it unchanged", p, len(got))
		}
	}
}
