package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Observe the decrypted upgrade/GET at a CDN stand-in, rather than just
// comparing the profile lookup function with itself.
func TestBrowserHeadersOnWire(t *testing.T) {
	for _, tc := range []struct{ fp, token, version string }{
		{"firefox", "Firefox/120.0", "120"}, {"chrome", "Chrome/133.0.0.0", "133"},
		{"safari", "Version/16.0", "16.0"}, {"ios", "iPhone OS 14_0", "14"}, {"edge", "Edg/85.", "85"},
	} {
		t.Run(tc.fp, func(t *testing.T) {
			// Fail explicitly if upgrading uTLS changes the preset version.
			if got := clientHelloID(tc.fp).Version; got != tc.version {
				t.Fatalf("update UA profile for preset version %s", got)
			}
			for _, mode := range []string{"ws", "http"} {
				seen := make(chan string, 1)
				srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Get("User-Agent"); w.WriteHeader(403) }))
				srv.EnableHTTP2 = true
				srv.StartTLS()
				ep := Endpoint{Server: srv.Listener.Addr().String(), SNI: "example.com", Fingerprint: tc.fp, AllowInsecure: true}
				if mode == "ws" {
					ep.WS = &WSClient{Path: "/lab"}
				} else {
					ep.HTTP = &WSClient{Path: "/lab"}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				d := NewDialer([]Endpoint{ep})
				conn, err := d.DialEndpoint(ctx, &ep, "")
				cancel()
				if conn != nil {
					conn.Close()
				}
				srv.Close()
				if err == nil {
					t.Fatal("expected test server's 403 rejection")
				}
				select {
				case ua := <-seen:
					if !strings.Contains(ua, tc.token) {
						t.Fatalf("%s sent %q", mode, ua)
					}
				case <-time.After(time.Second):
					t.Fatalf("%s did not reach HTTP handler: %v", mode, err)
				}
			}
		})
	}
}
