// Package fallback makes the server indistinguishable from an ordinary web
// server: any connection that fails authentication (including a censor's
// active probe) is spliced to a real HTTP origin, replaying whatever bytes
// were already read so the origin sees an untouched request.
package fallback

import (
	"net"
	"time"

	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/relay"
)

// Handler forwards unauthenticated connections to a fixed origin.
type Handler struct {
	origin string
}

// New returns a Handler targeting origin (host:port of a real HTTP service).
func New(origin string) *Handler { return &Handler{origin: origin} }

// Serve replays prefix and then splices client <-> origin. It never reveals
// that authentication failed; to a probe this looks like a plain reverse proxy.
func (h *Handler) Serve(client net.Conn, prefix []byte) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", h.origin, 10*time.Second)
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
