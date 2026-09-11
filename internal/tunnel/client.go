package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/pad"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/xtaci/smux"
)

// idleTimeout is how long a session with no streams is kept before the pool
// closes it. Browsers drop idle HTTP/2 connections on a similar scale, so a
// tunnel that hangs on to a silent connection for hours would stand out.
const idleTimeout = 4 * time.Minute

// headerGrace is how long a fresh mux stream waits for the application's
// first bytes so the per-stream header can share a frame with them, instead
// of going out as a separate tiny record.
const headerGrace = 30 * time.Millisecond

// Client opens tunneled streams to the server for each inbound request.
type Client struct {
	dialer   *transport.Dialer
	authHash string
	mux      config.MuxConfig

	mu       sync.Mutex
	sessions []*muxSession
	closed   bool

	// dialMu serializes creation of new sessions so a burst of requests on a
	// cold or saturated pool does not open dozens of TLS handshakes at once.
	dialMu sync.Mutex
}

// muxSession is a pooled smux session plus the moment it last went idle.
type muxSession struct {
	*smux.Session
	idleSince time.Time
}

// NewClient constructs a tunnel client from validated config.
func NewClient(c *config.ClientConfig) *Client {
	cl := &Client{
		dialer:   transport.NewDialer(c.Server, c.SNI, c.Fingerprint, c.AllowInsecure),
		authHash: protocol.HashPassword(c.Password),
		mux:      c.Mux,
	}
	if c.Mux.Enabled {
		go cl.reapIdle()
	}
	return cl
}

// Warm dials one mux session ahead of the first request so it does not pay
// the TCP+TLS round trips. Failures are logged, not fatal.
func (c *Client) Warm(ctx context.Context) {
	if !c.mux.Enabled {
		return
	}
	if _, err := c.dialSession(ctx); err != nil {
		logx.Warnf("client: warm-up: %v", err)
	}
}

// OpenStream returns a stream already addressed to target and ready to relay.
func (c *Client) OpenStream(ctx context.Context, target protocol.Address) (net.Conn, error) {
	if c.mux.Enabled {
		return c.openMuxStream(ctx, target)
	}
	return c.openDirect(ctx, target)
}

// header builds the connection-level auth header: digest, CRLF, metadata.
func (c *Client) header(cmd protocol.Command, addr protocol.Address) []byte {
	hdr := make([]byte, 0, 128)
	hdr = append(hdr, c.authHash...)
	hdr = append(hdr, protocol.CRLF...)
	return protocol.Metadata{Command: cmd, Address: addr}.AppendTo(hdr)
}

// openDirect dials a fresh TLS connection carrying a single CONNECT stream.
func (c *Client) openDirect(ctx context.Context, target protocol.Address) (net.Conn, error) {
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	pc := pad.New(conn)
	if err := pc.WriteHeader(c.header(protocol.CmdConnect, target)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: write header: %w", err)
	}
	return pc, nil
}

// openMuxStream returns a stream from a pooled smux session, creating a new
// authenticated session when existing ones are full or absent.
func (c *Client) openMuxStream(ctx context.Context, target protocol.Address) (net.Conn, error) {
	sess, err := c.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := sess.OpenStream()
	if err != nil {
		// Session died between selection and use; drop it and retry once.
		c.dropSession(sess)
		sess, err = c.acquireSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = sess.OpenStream()
		if err != nil {
			return nil, err
		}
	}
	// Per-stream metadata carries no password; the session is already authed.
	// It is sent lazily, merged with the application's first bytes.
	hdr := protocol.Metadata{Command: protocol.CmdConnect, Address: target}.AppendTo(make([]byte, 0, 4096))
	return newHeaderConn(stream, hdr), nil
}

// acquireSession returns a session with spare capacity, dialing one if needed.
// New-session creation is serialized (see dialMu) so that a burst of requests
// arriving on a cold or full pool does not fan out into a storm of concurrent
// TLS handshakes, which both looks nothing like a browser and can overwhelm a
// small VPS. Waiters re-check the pool after taking the dial lock, so most of
// a burst is absorbed by the first session(s) created rather than each dialing.
func (c *Client) acquireSession(ctx context.Context) (*muxSession, error) {
	if s, dial := c.selectSession(); !dial {
		return s, nil
	}
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	if s, dial := c.selectSession(); !dial {
		return s, nil
	}
	return c.dialSession(ctx)
}

// selectSession picks an existing session to reuse, pruning closed ones. It
// returns dial=true when the caller should create a new session instead: no
// live session has spare capacity and the pool still has room to grow.
func (c *Client) selectSession() (sess *muxSession, dial bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.sessions[:0]
	var chosen, least *muxSession
	for _, s := range c.sessions {
		if s.IsClosed() {
			continue
		}
		live = append(live, s)
		n := s.NumStreams()
		if chosen == nil && n < c.mux.Concurrency {
			chosen = s
		}
		if least == nil || n < least.NumStreams() {
			least = s
		}
	}
	c.sessions = live
	if chosen != nil {
		return chosen, false
	}
	if len(c.sessions) >= c.mux.Pool && least != nil {
		// Pool is saturated; reuse the least-loaded session anyway.
		return least, false
	}
	return nil, true
}

// dialSession creates a new authenticated smux session over TLS.
func (c *Client) dialSession(ctx context.Context) (*muxSession, error) {
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	pc := pad.New(conn)
	dummy := protocol.NewAddress("0.0.0.0", 0)
	if err := pc.WriteHeader(c.header(protocol.CmdMux, dummy)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: write mux header: %w", err)
	}
	sess, err := smux.Client(pc, smuxConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: smux client: %w", err)
	}
	ms := &muxSession{Session: sess}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		sess.Close()
		return nil, fmt.Errorf("tunnel: client closed")
	}
	c.sessions = append(c.sessions, ms)
	c.mu.Unlock()
	return ms, nil
}

func (c *Client) dropSession(dead *muxSession) {
	_ = dead.Close()
	c.mu.Lock()
	live := c.sessions[:0]
	for _, s := range c.sessions {
		if s != dead {
			live = append(live, s)
		}
	}
	c.sessions = live
	c.mu.Unlock()
}

// reapIdle closes sessions that have carried no streams for idleTimeout.
func (c *Client) reapIdle() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		now := time.Now()
		live := c.sessions[:0]
		for _, s := range c.sessions {
			switch {
			case s.IsClosed():
				continue
			case s.NumStreams() > 0:
				s.idleSince = time.Time{}
			case s.idleSince.IsZero():
				s.idleSince = now
			case now.Sub(s.idleSince) > idleTimeout:
				logx.Debugf("client: closing idle session")
				_ = s.Close()
				continue
			}
			live = append(live, s)
		}
		c.sessions = live
		c.mu.Unlock()
	}
}

// Close tears down all pooled sessions.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, s := range c.sessions {
		_ = s.Close()
	}
	c.sessions = nil
}

// headerConn defers a stream's header until the first Write so that header
// and payload share one frame (and thus one TLS record). If the application
// reads first (server-speaks-first protocols such as SSH), the header is
// flushed after a short grace period.
type headerConn struct {
	net.Conn
	mu   sync.Mutex
	hdr  []byte // nil once sent
	sent chan struct{}
}

func newHeaderConn(c net.Conn, hdr []byte) *headerConn {
	return &headerConn{Conn: c, hdr: hdr, sent: make(chan struct{})}
}

func (h *headerConn) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hdr == nil {
		return h.Conn.Write(p)
	}
	buf := append(h.hdr, p...)
	hl := len(h.hdr)
	h.hdr = nil
	close(h.sent)
	n, err := h.Conn.Write(buf)
	n -= hl
	if n < 0 {
		n = 0
	}
	return n, err
}

func (h *headerConn) Read(p []byte) (int, error) {
	h.mu.Lock()
	pending := h.hdr != nil
	h.mu.Unlock()
	if pending {
		select {
		case <-h.sent:
		case <-time.After(headerGrace):
			if err := h.flush(); err != nil {
				return 0, err
			}
		}
	}
	return h.Conn.Read(p)
}

func (h *headerConn) flush() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hdr == nil {
		return nil
	}
	hdr := h.hdr
	h.hdr = nil
	close(h.sent)
	_, err := h.Conn.Write(hdr)
	return err
}

// CloseWrite flushes a pending header, then half-closes the stream.
func (h *headerConn) CloseWrite() error {
	if err := h.flush(); err != nil {
		return err
	}
	if cw, ok := h.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return h.Conn.Close()
}
