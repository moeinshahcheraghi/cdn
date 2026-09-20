package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/pad"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/rstream"
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

// rotateTick is how often sessions are checked for retirement.
var rotateTick = 5 * time.Second

// Client opens tunneled streams to the server for each inbound request.
type Client struct {
	dialer   *transport.Dialer
	authHash string
	mux      config.MuxConfig

	mu       sync.Mutex
	sessions []*muxSession
	streams  map[*rstream.Stream]*muxSession // live resumable streams
	closed   bool

	// dialMu serializes creation of new sessions so a burst of requests on a
	// cold or saturated pool does not open dozens of TLS handshakes at once.
	dialMu sync.Mutex
}

// muxSession is a pooled smux session plus its rotation state.
type muxSession struct {
	*smux.Session
	idleSince time.Time
	born      time.Time
	maxAge    time.Duration // 0 = unlimited
	maxBytes  int64         // 0 = unlimited
	bytes     *atomic.Int64
	retired   bool // no new streams; existing ones are being moved away
}

// countConn counts bytes in both directions on a carrier connection.
type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// NewClient constructs a tunnel client from validated config.
func NewClient(c *config.ClientConfig) *Client {
	dialer := transport.NewDialer(c.Server, c.SNI, c.Fingerprint, c.AllowInsecure)
	if c.Reality.PublicKey != "" {
		dialer.Reality = &transport.RealityClient{PublicKey: c.Reality.PublicKey, ShortID: c.Reality.ShortID}
	}
	cl := &Client{
		dialer:   dialer,
		authHash: protocol.HashPassword(c.Password),
		mux:      c.Mux,
		streams:  map[*rstream.Stream]*muxSession{},
	}
	if c.Mux.Enabled {
		go cl.reapIdle()
		go cl.rotate()
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

// openMuxStream opens a resumable stream on a pooled session. The stream
// outlives the session: when the session is retired, rotate moves it.
func (c *Client) openMuxStream(ctx context.Context, target protocol.Address) (net.Conn, error) {
	sess, stream, err := c.openRaw(ctx)
	if err != nil {
		return nil, err
	}
	id := rand.Uint64()
	// Per-stream metadata carries no password; the session is already
	// authed. It is sent lazily, merged with the application's first bytes.
	hdr := protocol.Metadata{Command: protocol.CmdConnectR, Address: target}.AppendTo(make([]byte, 0, 4096))
	hdr = binary.BigEndian.AppendUint64(hdr, id)
	rs := rstream.New(id, resumeTimeout)
	c.mu.Lock()
	c.streams[rs] = sess
	c.mu.Unlock()
	rs.SetOnClose(func() {
		c.mu.Lock()
		delete(c.streams, rs)
		c.mu.Unlock()
	})
	if err := rs.Attach(newHeaderConn(stream, hdr), 0); err != nil {
		rs.Close()
		return nil, err
	}
	return rs, nil
}

// openRaw returns a fresh smux stream on a session with capacity.
func (c *Client) openRaw(ctx context.Context) (*muxSession, *smux.Stream, error) {
	sess, err := c.acquireSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	stream, err := sess.OpenStream()
	if err != nil {
		// Session died between selection and use; drop it and retry once.
		c.dropSession(sess)
		sess, err = c.acquireSession(ctx)
		if err != nil {
			return nil, nil, err
		}
		stream, err = sess.OpenStream()
		if err != nil {
			return nil, nil, err
		}
	}
	return sess, stream, nil
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
// Retired sessions are never chosen.
func (c *Client) selectSession() (sess *muxSession, dial bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.sessions[:0]
	var chosen, least *muxSession
	active := 0
	for _, s := range c.sessions {
		if s.IsClosed() {
			continue
		}
		live = append(live, s)
		if s.retired {
			continue
		}
		active++
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
	if active >= c.mux.Pool && least != nil {
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
	counter := new(atomic.Int64)
	pc := pad.New(countConn{conn, counter})
	dummy := protocol.NewAddress("0.0.0.0", 0)
	if err := pc.WriteHeader(c.header(protocol.CmdMux, dummy)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: write mux header: %w", err)
	}
	sess, err := smux.Client(pc, smuxConfig(c.mux.Concurrency))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: smux client: %w", err)
	}
	ms := &muxSession{Session: sess, born: time.Now(), bytes: counter}
	// Each session draws its own limits from [50%, 100%] of the configured
	// maxima, so sessions born together do not all rotate together.
	if c.mux.RotateSeconds > 0 {
		ms.maxAge = time.Duration(float64(c.mux.RotateSeconds)*(0.5+rand.Float64()*0.5)) * time.Second
	}
	if c.mux.RotateMB > 0 {
		ms.maxBytes = int64(float64(c.mux.RotateMB) * (0.5 + rand.Float64()*0.5) * 1e6)
	}
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

// rotate retires sessions past their age or byte budget and moves their
// streams to fresh sessions, so no TLS connection lives long or carries
// much, while users never notice.
func (c *Client) rotate() {
	t := time.NewTicker(rotateTick)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		now := time.Now()
		var moves []*rstream.Stream
		for _, s := range c.sessions {
			if s.IsClosed() {
				continue
			}
			if !s.retired && ((s.maxAge > 0 && now.Sub(s.born) > s.maxAge) || (s.maxBytes > 0 && s.bytes.Load() > s.maxBytes)) {
				s.retired = true
				logx.Debugf("client: retiring session after %s / %d MB", now.Sub(s.born).Round(time.Second), s.bytes.Load()/1e6)
			}
		}
		for rs, s := range c.streams {
			if s.retired {
				moves = append(moves, rs)
			}
		}
		c.mu.Unlock()

		for _, rs := range moves {
			if err := c.migrate(rs); err != nil {
				// Leave it where it is; the next tick tries again, and if the
				// old carrier dies meanwhile the stream just waits to resume.
				logx.Warnf("client: migrate stream: %v", err)
			}
		}

		// Retired sessions with nothing left on them can go.
		c.mu.Lock()
		live := c.sessions[:0]
		for _, s := range c.sessions {
			if s.retired && s.NumStreams() == 0 {
				_ = s.Close()
				continue
			}
			live = append(live, s)
		}
		c.sessions = live
		c.mu.Unlock()
	}
}

// migrate continues rs over a stream on a fresh session.
func (c *Client) migrate(rs *rstream.Stream) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, carrier, err := c.openRaw(ctx)
	if err != nil {
		return err
	}
	// Stop the old carrier first so our receive offset is final.
	rs.Detach()
	dummy := protocol.NewAddress("0.0.0.0", 0)
	hdr := protocol.Metadata{Command: protocol.CmdResume, Address: dummy}.AppendTo(make([]byte, 0, 64))
	hdr = binary.BigEndian.AppendUint64(hdr, rs.ID())
	hdr = binary.BigEndian.AppendUint64(hdr, rs.RecvOffset())
	_ = carrier.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := carrier.Write(hdr); err != nil {
		carrier.Close()
		return err
	}
	var reply [9]byte
	if _, err := io.ReadFull(carrier, reply[:]); err != nil {
		carrier.Close()
		return fmt.Errorf("resume reply: %w", err)
	}
	_ = carrier.SetDeadline(time.Time{})
	if reply[0] != protocol.ResumeOK {
		carrier.Close()
		rs.Close() // the server no longer has it; nothing to continue
		return fmt.Errorf("server does not know stream %x", rs.ID())
	}
	if err := rs.Attach(carrier, binary.BigEndian.Uint64(reply[1:])); err != nil {
		carrier.Close()
		return err
	}
	c.mu.Lock()
	if _, ok := c.streams[rs]; ok {
		c.streams[rs] = sess
	}
	c.mu.Unlock()
	logx.Debugf("client: moved stream %x to a fresh session", rs.ID())
	return nil
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
