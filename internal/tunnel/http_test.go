package tunnel

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/moeinshah0/tunnel/internal/config"
)

// fakeHTTPCDN stands in for Cloudflare on the HTTP route: HTTP/2 to the
// client, and a small pool of reused HTTP/1.1 connections to the origin, so
// requests of different sessions, and of visitors, share origin connections
// and may arrive in any order.
func fakeHTTPCDN(t *testing.T, origin string) string {
	t.Helper()
	target := &url.URL{Scheme: "https", Host: origin}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 2,
	}
	proxy.FlushInterval = -1
	srv := httptest.NewUnstartedServer(proxy)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func httpRouteConfig(cdn string) *config.ClientConfig {
	return &config.ClientConfig{
		Server: cdn, Password: testPassword, SNI: "cdn.example",
		Fingerprint: "firefox", AllowInsecure: true,
		HTTP: config.WSClientConfig{Path: wsPath},
		Mux:  config.MuxConfig{Enabled: true, Concurrency: 4, Pool: 2, RotateSeconds: 300, RotateMB: 1024},
	}
}

// The tunnel must work over plain HTTP requests through a CDN, on origin
// connections that also carry ordinary visitors.
func TestHTTPThroughCDN(t *testing.T) {
	env := startEnv(t, func(s *Server) { s.SetWebSocketPath(wsPath) })
	cdn := fakeHTTPCDN(t, env.server)

	// A visitor first, so a pooled origin connection begins with a request
	// for the website and later carries tunnel requests too.
	visit := func(path string) string {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		resp, err := c.Get("https://" + cdn + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := visit("/"); got != "cover site" {
		t.Fatalf("visitor got %q, want the cover site", got)
	}

	echoThrough(t, httpRouteConfig(cdn), env.echo, 4<<20)

	// Visitors are still served by the website afterwards, including on
	// paths under the secret one that are not tunnel requests.
	for _, p := range []string{"/index.html", wsPath + "/nope", wsPath + "/" + strings.Repeat("a", 32) + "/0"} {
		if got := visit(p); got != "cover site" {
			t.Fatalf("visitor to %s got %q", p, got)
		}
	}
}

// Many streams at once over a pool of HTTP carriers.
func TestHTTPManyStreams(t *testing.T) {
	env := startEnv(t, func(s *Server) { s.SetWebSocketPath(wsPath) })
	cdn := fakeHTTPCDN(t, env.server)
	c := NewClient(httpRouteConfig(cdn))
	t.Cleanup(c.Close)
	users(t, c, env.echo, 16, 256<<10, func() {})
}
