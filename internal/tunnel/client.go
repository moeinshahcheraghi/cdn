package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
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

// rotateTick is how often sessions are checked for retirement and streams
// for a lost or stalled carrier. A lost carrier also triggers a check at once.
var rotateTick = newTunable(2 * time.Second)

// stallTimeout is how long a stream's data may go unacknowledged before its
// connection is declared dead and the stream is moved. Acknowledgements
// normally arrive within a round trip, so this only fires on a flow the
// network has black-holed or throttled to a crawl.
var stallTimeout = newTunable(15 * time.Second)

// tunable is a duration a test may change while clients are running, so the
// change cannot race their rotate goroutines.
type tunable struct{ v atomic.Int64 }

func newTunable(d time.Duration) *tunable {
	t := &tunable{}
	t.set(d)
	return t
}

func (t *tunable) get() time.Duration  { return time.Duration(t.v.Load()) }
func (t *tunable) set(d time.Duration) { t.v.Store(int64(d)) }

// migrateParallel bounds concurrent stream moves, e.g. after a connection
// carrying many users is reset.
const migrateParallel = 8

// resumeReplyTimeout bounds waiting for the server to confirm a resume.
const resumeReplyTimeout = 10 * time.Second

// migrateBackoff is how long to wait before retrying a stream whose move
// failed, so a server that is briefly unreachable is not hammered.
const migrateBackoff = 2 * time.Second

// Client opens tunneled streams to the server for each inbound request.
type Client struct {
	dialer   *transport.Dialer
	authHash string
	mux      config.MuxConfig

	mu        sync.Mutex
	sessions  []*muxSession
	streams   map[*rstream.Stream]*streamRef // live resumable streams
	migrating map[*rstream.Stream]bool
	closed    bool
	kick      chan struct{} // wakes rotate early

	// dialMu serializes creation of new sessions so a burst of requests on a
	// cold or saturated pool does not open dozens of TLS handshakes at once.
	dialMu sync.Mutex
}

// streamRef is what the client remembers about a live resumable stream: the
// session carrying it and where it was going, so it can be moved — or, if
// nothing has crossed it yet, opened again from scratch.
type streamRef struct {
	sess    *muxSession
	target  protocol.Address
	nextTry time.Time // set after a failed move, to back off
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
	ep        *transport.Endpoint
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
	cl := &Client{
		dialer:    transport.NewDialer(Endpoints(c)),
		authHash:  protocol.HashPassword(c.Password),
		mux:       c.Mux,
		streams:   map[*rstream.Stream]*streamRef{},
		migrating: map[*rstream.Stream]bool{},
		kick:      make(chan struct{}, 1),
	}
	if c.Mux.Enabled {
		go cl.reapIdle()
		go cl.rotate()
	}
	return cl
}

// Endpoints lists every route the config describes: the primary server(s)
// as tier 0 and each backup as tier 1.
func Endpoints(c *config.ClientConfig) []transport.Endpoint {
	var eps []transport.Endpoint
	add := func(tier int, server string, servers []string, sni, fp string, r config.RealityClientConfig, ws config.WSClientConfig, insecure bool, frag *config.FragmentConfig) {
		if len(servers) == 0 {
			servers = []string{server}
		}
		for _, srv := range servers {
			ep := transport.Endpoint{Server: srv, SNI: sni, Fingerprint: fp, AllowInsecure: insecure, Tier: tier}
			if r.PublicKey != "" {
				ep.Reality = &transport.RealityClient{PublicKey: r.PublicKey, ShortID: r.ShortID}
			}
			if ws.Path != "" {
				ep.WS = &transport.WSClient{Path: ws.Path, Host: ws.Host}
			}
			ep.Fragment = fragmentOf(frag)
			eps = append(eps, ep)
		}
	}
	add(0, c.Server, c.Servers, c.SNI, c.Fingerprint, c.Reality, c.WS, c.AllowInsecure, c.Fragment)
	for _, b := range c.Backups {
		add(1, b.Server, b.Servers, b.SNI, b.Fingerprint, b.Reality, b.WS, b.AllowInsecure, b.Fragment)
	}
	return eps
}

// fragmentOf converts a validated fragment setting; nil when it is off.
func fragmentOf(f *config.FragmentConfig) *transport.Fragment {
	if f == nil || !f.Enabled {
		return nil
	}
	smin, smax, _ := config.Range(f.Size)
	dmin, dmax, _ := config.Range(f.Delay)
	return &transport.Fragment{
		Records: f.Mode != "tcp",
		MinSize: smin, MaxSize: smax,
		MinDelay: time.Duration(dmin) * time.Millisecond,
		MaxDelay: time.Duration(dmax) * time.Millisecond,
	}
}

// Dialer exposes the underlying dialer for diagnostics.
func (c *Client) Dialer() *transport.Dialer { return c.dialer }

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
	rs := rstream.New(id, resumeTimeout)
	c.mu.Lock()
	c.streams[rs] = &streamRef{sess: sess, target: target}
	c.mu.Unlock()
	rs.SetOnClose(func() {
		c.mu.Lock()
		delete(c.streams, rs)
		c.mu.Unlock()
	})
	// A connection reset by the network must not cost the user anything:
	// resume on another connection right away.
	rs.SetOnCarrierLost(c.wake)
	if err := rs.Attach(newHeaderConn(stream, connectHeader(target, id)), 0); err != nil {
		rs.Close()
		return nil, err
	}
	return rs, nil
}

// connectHeader is the per-stream metadata: no password, since the session
// is already authenticated. It is sent lazily, merged with the application's
// first bytes, so it does not show up as a separate tiny record.
func connectHeader(target protocol.Address, id uint64) []byte {
	hdr := protocol.Metadata{Command: protocol.CmdConnectR, Address: target}.AppendTo(make([]byte, 0, 512))
	return binary.BigEndian.AppendUint64(hdr, id)
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
// returns dial=true when the caller should create a new session instead.
//
// Streams go to the least-loaded session. While the pool has room, a new
// connection is opened as soon as every live one carries mux.concurrency
// streams, so heavy long-lived streams (VPN users) are spread over many TCP
// connections: on a lossy or per-flow-policed international path the total
// throughput is roughly proportional to the number of flows, and one user's
// loss stalls only the few users sharing that flow. Retired sessions are
// never chosen.
func (c *Client) selectSession() (sess *muxSession, dial bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.sessions[:0]
	var least *muxSession
	leastN, active := 0, 0
	for _, s := range c.sessions {
		if s.IsClosed() {
			continue
		}
		live = append(live, s)
		if s.retired {
			continue
		}
		active++
		if n := s.NumStreams(); least == nil || n < leastN {
			least, leastN = s, n
		}
	}
	c.sessions = live
	if active < c.mux.Pool {
		return nil, true // spread: grow the pool before stacking streams up
	}
	if least != nil && leastN < c.mux.Concurrency*c.mux.Pool {
		return least, false
	}
	return least, least == nil
}

// dialSession creates a new authenticated smux session over TLS.
func (c *Client) dialSession(ctx context.Context) (*muxSession, error) {
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	ep := transport.EndpointOf(conn)
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
	ms := &muxSession{Session: sess, born: time.Now(), bytes: counter, ep: ep}
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

// wake makes rotate run now rather than at its next tick.
func (c *Client) wake() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// rotate keeps every stream on a healthy, young connection. It retires
// sessions past their age or byte budget, and sessions on which a stream has
// stalled, and moves streams off retired or dead sessions onto fresh ones, so
// no TLS connection lives long or carries much, a connection killed or
// black-holed by the network costs users a moment's pause instead of their
// VPN session, and users never notice any of it.
func (c *Client) rotate() {
	t := time.NewTicker(rotateTick.get())
	defer t.Stop()
	sem := make(chan struct{}, migrateParallel)
	for {
		select {
		case <-t.C:
		case <-c.kick:
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		now := time.Now()
		for _, s := range c.sessions {
			if s.IsClosed() {
				continue
			}
			if !s.retired && ((s.maxAge > 0 && now.Sub(s.born) > s.maxAge) || (s.maxBytes > 0 && s.bytes.Load() > s.maxBytes)) {
				s.retired = true
				logx.Debugf("client: retiring session after %s / %d MB", now.Sub(s.born).Round(time.Second), s.bytes.Load()/1e6)
			}
		}
		var moves []*rstream.Stream
		var stalled []*transport.Endpoint
		for rs, ref := range c.streams {
			s := ref.sess
			if c.migrating[rs] || now.Before(ref.nextTry) {
				continue
			}
			if !s.retired && !s.IsClosed() && rs.Stalled(stallTimeout.get()) {
				s.retired = true
				stalled = append(stalled, s.ep)
				logx.Warnf("client: connection via %v stalled after %s / %d MB; replacing it", s.ep, now.Sub(s.born).Round(time.Second), s.bytes.Load()/1e6)
			}
			if !s.retired && !s.IsClosed() && rs.Attached() {
				continue
			}
			if rs.Finished() {
				// Everything has been delivered and acknowledged in both
				// directions, so the server has already let the stream go.
				// Resuming it would fail and take from the application the
				// bytes it has not read yet.
				continue
			}
			c.migrating[rs] = true
			moves = append(moves, rs)
		}
		c.mu.Unlock()

		for _, ep := range stalled {
			c.dialer.ReportStall(ep)
		}
		for _, rs := range moves {
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				err := c.migrate(rs)
				c.mu.Lock()
				delete(c.migrating, rs)
				if err != nil {
					if ref := c.streams[rs]; ref != nil {
						ref.nextTry = time.Now().Add(migrateBackoff)
					}
				}
				c.mu.Unlock()
				if err != nil {
					// Fail-safe: the stream still holds its old carrier when
					// it had one, so this costs the user nothing. Otherwise it
					// buffers and waits, up to resumeTimeout.
					logx.Warnf("client: move stream: %v", err)
				}
			}()
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
//
// It is deliberately prove-then-swap: a new carrier is adopted only once the
// server has confirmed the stream over it. Until then rs keeps whatever
// carrier it has, so a failed move costs a user nothing and a rotation can
// never drop a live connection. Offsets sampled before the swap can only be
// stale in the safe direction: the peer resends a little and rstream drops
// what it already has.
func (c *Client) migrate(rs *rstream.Stream) error {
	c.mu.Lock()
	ref := c.streams[rs]
	c.mu.Unlock()
	if ref == nil {
		return nil // closed while we queued
	}
	if rs.Finished() {
		// Nothing left to carry: everything has been delivered and
		// acknowledged both ways. Leave it alone — the application may still
		// have received bytes to read, and closing it here would throw them
		// away. It closes the stream itself when it is done.
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, carrier, err := c.openRaw(ctx)
	if err != nil {
		return err
	}

	// A stream that lost its carrier before either side confirmed a single
	// byte is cheaper to open again than to resume, and the server has
	// nothing to resume anyway.
	if !rs.Attached() && rs.Fresh() {
		if err := rs.Attach(newHeaderConn(carrier, connectHeader(ref.target, rs.ID())), 0); err != nil {
			carrier.Close()
			return ignoreClosed(err)
		}
		c.rebind(rs, sess)
		logx.Debugf("client: reopened stream %x to %v on a fresh connection", rs.ID(), ref.target)
		return nil
	}

	dummy := protocol.NewAddress("0.0.0.0", 0)
	hdr := protocol.Metadata{Command: protocol.CmdResume, Address: dummy}.AppendTo(make([]byte, 0, 64))
	hdr = binary.BigEndian.AppendUint64(hdr, rs.ID())
	hdr = binary.BigEndian.AppendUint64(hdr, rs.RecvOffset())
	_ = carrier.SetDeadline(time.Now().Add(resumeReplyTimeout))
	if _, err := carrier.Write(hdr); err != nil {
		carrier.Close()
		c.dropSession(sess)
		return err
	}
	var reply [9]byte
	if _, err := io.ReadFull(carrier, reply[:]); err != nil {
		// No answer over this connection. The usual cause is a pooled
		// connection the network dropped without telling us, so retire it
		// instead of opening more streams into a black hole, and hold it
		// against the route: a route that swallows resumes will swallow the
		// user traffic we are about to move onto it.
		carrier.Close()
		c.dropSession(sess)
		c.dialer.ReportStall(sess.ep)
		return fmt.Errorf("no resume reply over %v: %w", sess.ep, err)
	}
	_ = carrier.SetDeadline(time.Time{})
	if reply[0] != protocol.ResumeOK {
		carrier.Close()
		if rs.Finished() {
			// The application closed it while we were asking, so the server
			// was right to let it go.
			return nil
		}
		// The server has no such stream, and that answer is final: holding on
		// to the old carrier cannot bring it back, whether or not that
		// carrier still looks alive to us. (It often does: a connection the
		// network has dropped without a reset carries a stream's opening
		// header into nowhere, and nothing local ever notices.)
		if rs.Fresh() {
			// Nothing was ever confirmed in either direction, so there is
			// nothing to continue — open it again on this good connection.
			// The server replied over that smux stream and closed it, so take
			// a new one.
			again, err := sess.OpenStream()
			if err != nil {
				return err
			}
			if err := rs.Attach(newHeaderConn(again, connectHeader(ref.target, rs.ID())), 0); err != nil {
				again.Close()
				return ignoreClosed(err)
			}
			c.rebind(rs, sess)
			logx.Debugf("client: reopened stream %x to %v after the server had lost it", rs.ID(), ref.target)
			return nil
		}
		// It cannot be revived: end it as if the far end had hung up, which
		// still lets the application read what already arrived.
		closing := rs.Closing()
		rs.PeerGone()
		if closing {
			// The application had already finished with it, so there is
			// nothing here worth telling the operator about.
			return nil
		}
		return fmt.Errorf("server no longer has stream %x", rs.ID())
	}
	// Adopting the new carrier atomically drops the old one.
	if err := rs.Attach(carrier, binary.BigEndian.Uint64(reply[1:])); err != nil {
		carrier.Close()
		return ignoreClosed(err)
	}
	c.rebind(rs, sess)
	logx.Debugf("client: moved stream %x to a fresh connection", rs.ID())
	return nil
}

// ignoreClosed drops the error of a stream that ended while it was being
// moved: the application closed it, which is not a failure to report.
func ignoreClosed(err error) error {
	if errors.Is(err, rstream.ErrClosed) {
		return nil
	}
	return err
}

// rebind records which session now carries rs and clears its backoff.
func (c *Client) rebind(rs *rstream.Stream, sess *muxSession) {
	c.mu.Lock()
	if ref := c.streams[rs]; ref != nil {
		ref.sess = sess
		ref.nextTry = time.Time{}
	}
	c.mu.Unlock()
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
