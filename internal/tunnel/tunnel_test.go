package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/fallback"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/transport"
)

const testPassword = "test-password"

// testEnv starts an echo service, a banner (server-speaks-first) service, a
// fallback origin, and the tunnel server, all on loopback.
type testEnv struct {
	server, echo, banner string
}

func startEnv(t *testing.T, opts ...func(*Server)) *testEnv {
	t.Helper()
	echo := listen(t)
	go serveEach(echo, func(c net.Conn) { io.Copy(c, c) })

	banner := listen(t)
	go serveEach(banner, func(c net.Conn) {
		c.Write([]byte("BANNER\n"))
		io.Copy(c, c)
	})

	origin := listen(t)
	go http.Serve(origin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "cover site")
	}))

	tlsCfg, err := transport.NewServerTLSConfig("", "", "localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(tlsCfg, []string{testPassword}, fallback.New(origin.Addr().String()))
	for _, o := range opts {
		o(srv)
	}
	ln := listen(t)
	go serveEach(ln, srv.Handle)

	return &testEnv{server: ln.Addr().String(), echo: echo.Addr().String(), banner: banner.Addr().String()}
}

func listen(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func serveEach(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); h(c) }()
	}
}

func newClient(t *testing.T, env *testEnv, mux bool) *Client {
	t.Helper()
	cfg := &config.ClientConfig{
		Server: env.server, Password: testPassword, SNI: "localhost",
		Fingerprint: "chrome", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: mux, Concurrency: 8, Pool: 2},
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)
	return c
}

func addrOf(t *testing.T, hostport string) protocol.Address {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	return protocol.NewAddress(host, port)
}

func TestEchoMuxAndDirect(t *testing.T) {
	env := startEnv(t)
	for _, mux := range []bool{true, false} {
		c := newClient(t, env, mux)
		payload := make([]byte, 3<<20)
		rand.Read(payload)

		stream, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
		if err != nil {
			t.Fatalf("mux=%v open: %v", mux, err)
		}
		go func() {
			stream.Write(payload)
			stream.(interface{ CloseWrite() error }).CloseWrite()
		}()
		got, err := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
		if err != nil {
			t.Fatalf("mux=%v read: %v", mux, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("mux=%v echo mismatch (%d bytes)", mux, len(got))
		}
		stream.Close()
	}
}

func TestServerSpeaksFirst(t *testing.T) {
	env := startEnv(t)
	c := newClient(t, env, true)
	stream, err := c.OpenStream(context.Background(), addrOf(t, env.banner))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 7)
	if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != "BANNER\n" {
		t.Fatalf("banner: %q %v", buf, err)
	}
}

// A probe that sends a complete-but-short HTTP request must be answered by
// the cover site immediately, not after the auth timeout.
func TestShortProbeAnsweredPromptly(t *testing.T) {
	env := startEnv(t)
	for _, probe := range []string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		protocol.HashPassword("wrong") + "\r\n\x01\x01\x00\x00\x00\x00\x00\x50\r\n",
	} {
		conn, err := tls.Dial("tcp", env.server, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
			t.Errorf("server negotiated %q, want http/1.1 so a browser probe gets a working site", got)
		}
		start := time.Now()
		conn.Write([]byte(probe))
		// A real web server answers a complete request at once; read just the
		// status line rather than to EOF, since the cover site keeps HTTP/1.1
		// connections alive (which is itself correct cover behaviour).
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		elapsed := time.Since(start)
		conn.Close()
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 ") {
			t.Fatalf("probe %q: no HTTP response from cover site: %q (%v)", probe[:8], line, err)
		}
		if elapsed > time.Second {
			t.Fatalf("probe answered after %v; a real web server answers at once", elapsed)
		}
	}
}
