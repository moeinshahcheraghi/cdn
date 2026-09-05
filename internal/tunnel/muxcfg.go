// Package tunnel wires the client ingress to the encrypted transport, opening
// per-request streams either directly or over a pool of smux sessions.
package tunnel

import (
	"github.com/xtaci/smux"
)

// smuxConfig is tuned for throughput: large receive/stream buffers keep the
// pipe full over high-latency links.
//
// smux's own keepalive is disabled on purpose. It would emit an 8-byte frame
// every few seconds in both directions for the life of the session, a
// metronome no browser produces and an easy long-flow signature for DPI.
// Liveness comes from kernel TCP keepalive instead (see transport), which is
// invisible above TCP, and idle sessions are retired by the client pool.
func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveDisabled = true
	c.MaxFrameSize = 32 * 1024
	c.MaxReceiveBuffer = 8 * 1024 * 1024
	c.MaxStreamBuffer = 2 * 1024 * 1024
	return c
}
