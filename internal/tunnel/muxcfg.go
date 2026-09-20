// Package tunnel wires the client ingress to the encrypted transport, opening
// per-request streams either directly or over a pool of smux sessions.
package tunnel

import (
	"math"

	"github.com/xtaci/smux"
)

// streamBuffer is the per-stream receive window: enough for ~80 Mbit/s at
// 100 ms RTT per user, without letting one slow user hoard memory.
const streamBuffer = 1 << 20

// smuxConfig is tuned for throughput and, crucially, so that slow streams
// cannot stall the session. smux pauses reading the whole connection when
// unconsumed data across all streams exceeds MaxReceiveBuffer; a few users
// on bad links, each holding a full window of unread data, would otherwise
// freeze every other user sharing that session (see TestHeadOfLineBlocking).
// The session bucket is therefore sized above streams*streamBuffer, so the
// only limit a stream ever hits is its own window. streams is the maximum
// number of streams the session may carry; the server, which does not know
// the client's setting, passes a generous upper bound.
//
// smux's own keepalive is disabled on purpose. It would emit an 8-byte frame
// every few seconds in both directions for the life of the session, a
// metronome no browser produces and an easy long-flow signature for DPI.
// Liveness comes from kernel TCP keepalive instead (see transport), which is
// invisible above TCP, and idle sessions are retired by the client pool.
func smuxConfig(streams int) *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveDisabled = true
	c.MaxFrameSize = 32 * 1024
	c.MaxStreamBuffer = streamBuffer
	if streams < 1 {
		streams = 1
	}
	bucket := int64(streams)*streamBuffer + 8<<20
	if bucket > math.MaxInt32 {
		bucket = math.MaxInt32
	}
	c.MaxReceiveBuffer = int(bucket)
	return c
}

// serverMuxStreams is the stream bound used for server-side sessions; it is
// an accounting cap, not an allocation.
const serverMuxStreams = 1024
