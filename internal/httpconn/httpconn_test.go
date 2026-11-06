package httpconn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const secret = "/secret/path"

// startServer runs a hub behind an HTTP/2 TLS server, like the origin as a
// CDN's client sees it. serve handles each session.
func startServer(t *testing.T, serve func(net.Conn)) (*Hub, string) {
	t.Helper()
	hub := NewHub(serve)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, secret+"/"); ok && hub.Handle(w, r, rest) {
			return
		}
		http.NotFound(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return hub, srv.Listener.Addr().String()
}

func dial(t *testing.T, addr string) *Conn {
	t.Helper()
	tc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, tc, "cdn.example", secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func echo(c net.Conn) {
	io.Copy(c, c)
	c.(interface{ CloseWrite() error }).CloseWrite()
}

// Bytes must cross both ways intact, and a half-close must reach the far
// side as a clean end of stream without cutting the other direction.
func TestEchoAndHalfClose(t *testing.T) {
	_, addr := startServer(t, echo)
	c := dial(t, addr)
	payload := make([]byte, 3<<20)
	rand.Read(payload)
	go func() {
		// Uneven writes, so batching and ordering are both exercised.
		for p := payload; len(p) > 0; {
			n := min(len(p), 1+int(p[0])*97)
			c.Write(p[:n])
			p = p[n:]
		}
		c.CloseWrite()
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %d of %d bytes", len(got), len(payload))
	}
}

// The server closing right after its last write must still deliver it.
func TestCloseDeliversWhatWasWritten(t *testing.T) {
	_, addr := startServer(t, func(c net.Conn) {
		c.Write([]byte("last words"))
		c.Close()
	})
	c := dial(t, addr)
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "last words" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadDeadline(t *testing.T) {
	_, addr := startServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	c := dial(t, addr)
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want deadline error, got %v", err)
	}
}

// A CDN may deliver uploads out of order; the stream must not notice.
func TestUploadsReordered(t *testing.T) {
	hub := NewHub(func(net.Conn) {})
	s := hub.open(strings.Repeat("a", 32), httptest.NewRequest("GET", "/", nil))
	for _, seq := range []uint64{2, 0, 3, 1} {
		if err := s.push(seq, []byte{byte('A' + seq)}); err != nil {
			t.Fatal(err)
		}
	}
	s.push(4, nil) // end marker
	got, _ := io.ReadAll(s)
	if string(got) != "ABCD" {
		t.Fatalf("got %q", got)
	}
	if err := s.push(100, []byte("x")); err == nil {
		t.Fatal("an upload far ahead of the stream was accepted")
	}
}

// Requests that are not exactly ours are left to the website.
func TestForeignRequestsNotHandled(t *testing.T) {
	hub := NewHub(func(net.Conn) {})
	for _, tc := range []struct{ method, rest string }{
		{"GET", "short"},
		{"GET", strings.Repeat("A", 32)},
		{"POST", strings.Repeat("a", 32) + "/0"}, // no such session
		{"PUT", strings.Repeat("a", 32)},
		{"GET", strings.Repeat("a", 32) + "/0"},
	} {
		w := httptest.NewRecorder()
		if hub.Handle(w, httptest.NewRequest(tc.method, "/", nil), tc.rest) {
			t.Fatalf("%s %s was handled", tc.method, tc.rest)
		}
		if w.Code != 200 || w.Body.Len() != 0 || len(w.Header()) != 0 {
			t.Fatalf("%s %s wrote a response", tc.method, tc.rest)
		}
	}
}
