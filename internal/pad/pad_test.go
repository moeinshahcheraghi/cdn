package pad

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := New(a), New(b)

	sizes := []int{1, 7, 80, 517, 1399, 1400, 3000, 4096, 5000, 32767, 32768, 70000}
	var want bytes.Buffer
	for _, n := range sizes {
		chunk := make([]byte, n)
		_, _ = rand.Read(chunk)
		want.Write(chunk)
	}

	errc := make(chan error, 1)
	go func() {
		defer a.Close()
		if err := ca.WriteHeader([]byte("hello")); err != nil {
			errc <- err
			return
		}
		src := want.Bytes()
		off := 0
		for _, n := range sizes {
			if _, err := ca.Write(src[off : off+n]); err != nil {
				errc <- err
				return
			}
			off += n
		}
		errc <- nil
	}()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil || string(hdr) != "hello" {
		t.Fatalf("header: %q %v", hdr, err)
	}
	got, err := io.ReadAll(cb)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), want.Len())
	}
}

func TestPadLenRanges(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if p := padLen(80); p < 0 || 80+p > padSmall {
			t.Fatalf("small pad out of range: %d", p)
		}
		if p := padLen(2000); p < 0 || 2000+p > padLarge {
			t.Fatalf("medium pad out of range: %d", p)
		}
		if p := padLen(padLarge); p != 0 {
			t.Fatalf("large write padded: %d", p)
		}
	}
}
