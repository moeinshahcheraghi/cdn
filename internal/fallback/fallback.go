// Package fallback makes the server indistinguishable from an ordinary web
// server: any connection that fails authentication (including a censor's
// active probe) is spliced to a real HTTP origin, replaying whatever bytes
// were already read so the origin sees an untouched request.
package fallback

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/relay"
)

// Handler forwards unauthenticated connections to a fixed origin.
type Handler struct {
	origin string
	tls    *tls.Config // non-nil when the origin is itself HTTPS
}

// New returns a Handler targeting origin (host:port of a real HTTP service).
// An origin on port 443 is dialed over TLS, so any public HTTPS site can
// serve as cover without a local web server.
func New(origin string) *Handler {
	h := &Handler{origin: origin}
	if host, port, err := net.SplitHostPort(origin); err == nil && port == "443" {
		h.tls = &tls.Config{ServerName: host}
	}
	return h
}

// Serve replays prefix and then splices client <-> origin. It never reveals
// that authentication failed; to a probe this looks like a plain reverse proxy.
func (h *Handler) Serve(client net.Conn, prefix []byte) {
	defer client.Close()
	up, err := h.dial()
	if err != nil {
		logx.Debugf("fallback: dial origin %s: %v", h.origin, err)
		return
	}
	defer up.Close()
	if len(prefix) > 0 {
		if _, err := up.Write(prefix); err != nil {
			return
		}
	}
	logx.Debugf("fallback: serving probe from %s via %s", client.RemoteAddr(), h.origin)
	relay.Pipe(client, up)
}

func (h *Handler) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if h.tls != nil {
		d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: h.tls}
		return d.DialContext(ctx, "tcp", h.origin)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", h.origin)
}
