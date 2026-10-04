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
	"strings"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/transport"
)

const wsPath = "/cdn-secret-path"

// fakeCDN stands in for Cloudflare: it terminates TLS for the domain and
// forwards the connection, WebSocket upgrade and all, to the origin. The
// client must reach the tunnel through it without knowing it is there.
func fakeCDN(t *testing.T, origin string) string {
	t.Helper()
	cfg, err := selfSignedFor(t, "cdn.example")
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	go serveEach(ln, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		// Like a CDN in "full" mode, the hop to the origin is HTTPS of its
		// own; the tunnel server therefore sees a plain upgrade inside TLS.
		up, err := tls.Dial("tcp", origin, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			return
		}
		defer up.Close()
		// A CDN reads the request itself before proxying it on.
		br := bufio.NewReader(tc)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.URL.Path != wsPath || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			io.WriteString(tc, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
			return
		}
		if err := req.Write(up); err != nil {
			return
		}
		go func() {
			io.Copy(up, br)
			up.Close()
		}()
		io.Copy(tc, up)
	})
	return ln.Addr().String()
}

func selfSignedFor(t *testing.T, name string) (*tls.Config, error) {
	t.Helper()
	return transport.NewServerTLSConfig("", "", name, nil)
}

// Traffic must survive the full CDN path: browser-shaped TLS to the CDN, an
// ordinary WebSocket upgrade, and the tunnel inside it.
func TestWebSocketThroughCDN(t *testing.T) {
	env := startEnv(t, func(s *Server) { s.SetWebSocketPath(wsPath) })
	cdn := fakeCDN(t, env.server)

	cfg := &config.ClientConfig{
		Server: cdn, Password: testPassword, SNI: "cdn.example",
		Fingerprint: "firefox", AllowInsecure: true,
		WS:  config.WSClientConfig{Path: wsPath},
		Mux: config.MuxConfig{Enabled: true, Concurrency: 4, Pool: 2, RotateSeconds: 300, RotateMB: 1024},
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)

	stream, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatalf("open through CDN: %v", err)
	}
	defer stream.Close()
	payload := make([]byte, 2<<20)
	rand.Read(payload)
	go func() {
		stream.Write(payload)
		stream.(interface{ CloseWrite() error }).CloseWrite()
	}()
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
	if err != nil {
		t.Fatalf("read through CDN: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch through CDN (%d bytes)", len(got))
	}
}

// Anything that is not the secret path must look like an ordinary website,
// so a censor scanning paths finds nothing.
func TestWrongWebSocketPathLooksLikeAWebsite(t *testing.T) {
	env := startEnv(t, func(s *Server) { s.SetWebSocketPath(wsPath) })
	for _, path := range []string{"/", "/ws", wsPath + "x"} {
		conn, err := tls.Dial("tcp", env.server, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		req := "GET " + path + " HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" +
			"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
			"Sec-WebSocket-Version: 13\r\n\r\n"
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(req))
		line, err := bufio.NewReader(conn).ReadString('\n')
		conn.Close()
		if err != nil {
			t.Fatalf("path %q: no answer: %v", path, err)
		}
		if strings.Contains(line, "101") {
			t.Fatalf("path %q was upgraded; only the secret path may be", path)
		}
		if !strings.HasPrefix(line, "HTTP/1.1 ") {
			t.Fatalf("path %q: not an HTTP answer: %q", path, line)
		}
	}
}

// A fragmented ClientHello must still handshake with the CDN in both modes.
func TestFragmentedHelloThroughCDN(t *testing.T) {
	env := startEnv(t, func(s *Server) { s.SetWebSocketPath(wsPath) })
	cdn := fakeCDN(t, env.server)
	for _, mode := range []string{"records", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.ClientConfig{
				Server: cdn, Password: testPassword, SNI: "cdn.example",
				Fingerprint: "firefox", AllowInsecure: true,
				WS:       config.WSClientConfig{Path: wsPath},
				Fragment: &config.FragmentConfig{Enabled: true, Mode: mode, Size: "10-40", Delay: "1-3"},
				Mux:      config.MuxConfig{Enabled: true, Concurrency: 4, Pool: 1},
			}
			echoThrough(t, cfg, env.echo, 256<<10)
		})
	}
}

// echoThrough sends n random bytes to the echo service over a fresh client
// built from cfg and checks they come back intact.
func echoThrough(t *testing.T, cfg *config.ClientConfig, echo string, n int) {
	t.Helper()
	c := NewClient(cfg)
	t.Cleanup(c.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := c.OpenStream(ctx, addrOf(t, echo))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer stream.Close()
	payload := make([]byte, n)
	rand.Read(payload)
	go func() {
		stream.Write(payload)
		stream.(interface{ CloseWrite() error }).CloseWrite()
	}()
	got, err := io.ReadAll(io.LimitReader(stream, int64(n)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo: %d of %d bytes, err %v", len(got), n, err)
	}
}
