// Package tunnel wires the client ingress to the encrypted transport, opening
// per-request streams either directly or over a pool of smux sessions.
package tunnel

import (
	"time"

	"github.com/xtaci/smux"
)

// smuxConfig is tuned for throughput: large receive/stream buffers keep the
// pipe full over high-latency links, and keepalives shed dead sessions.
func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 15 * time.Second
	c.KeepAliveTimeout = 45 * time.Second
	c.MaxFrameSize = 32 * 1024
	c.MaxReceiveBuffer = 8 * 1024 * 1024
	c.MaxStreamBuffer = 2 * 1024 * 1024
	return c
}
