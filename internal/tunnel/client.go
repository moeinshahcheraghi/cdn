package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
var rotateTick = newTunable(time.Second)

// stallTimeout is how long a connection may stay completely silent, while a
// stream on it waits for an acknowledgement, before it is declared dead and its
// streams are moved. It looks at the whole connection on purpose: users share a
// TCP connection, so on a full link one user's acknowledgement can wait seconds
// behind other users' data. That is a busy connection, not a dead one, and moving
// its users only adds load to the link that is already full.
var stallTimeout = newTunable(5 * time.Second)

// stallHardTimeout moves a stream unacknowledged this long even though its
// connection still delivers: the path towards the server may be the broken half.
const stallHardTimeout = 30 * time.Second

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

// suspectSilence is how long a connection through a suspect address may have
// said nothing and still be offered to a stream. A busy one speaks constantly.
const suspectSilence = time.Second

// silenceCheckMin is the least time between silence checks of one connection
// that keeps answering; each wait is this plus up to as much again at random.
const silenceCheckMin = 20 * time.Second

// silenceCheckTraffic is far more than a check itself moves.
const silenceCheckTraffic = 16 << 10

// resumeSilence ends the wait for that reply early when the whole connection
// has said nothing for this long. The reply queues behind everything else the
// server is sending on the connection, so a busy one gets the full timeout.
const resumeSilence = 3 * time.Second

// migrateBackoff is how long to wait before retrying a stream whose move
// failed, so a server that is briefly unreachable is not hammered.
const migrateBackoff = 2 * time.Second

// warmMaxAge is how long an empty session is trusted to be ready for the next
// stream. A carrier nobody is using can die without anyone noticing, so empty
// ones are replaced before they get old. It also stays under the 100 s a CDN
// may allow a silent origin response.
var warmMaxAge = newTunable(90 * time.Second)

// shareAfter is how long a new stream waits for a connection of its own when it
// could share a live one instead.
const shareAfter = time.Second

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

	// growPool's background dial. It stays out of dialMu, so a dial hanging
	// on a cut path cannot hold up a user who needs a connection now. A
	// failing one waits until growAfter before trying again.
	growing   bool
	growFails int
	auto      *autoIP // nil unless the config asks for it
	done      chan struct{}
	growAfter time.Time
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
	retired   bool          // no new streams; existing ones are being moved away
	lastRead  *atomic.Int64 // unix nanoseconds of the last bytes received
	pc        *pad.Conn
	checking  atomic.Bool // a silence check is running
	// Guarded by Client.mu: when a connection that answered may be asked again,
	// and how much traffic it had carried when it last answered.
	nextCheck    time.Time
	checkedBytes int64
	ep           *transport.Endpoint
}

// countConn counts bytes in both directions on a carrier connection.
type countConn struct {
	net.Conn
	n        *atomic.Int64
	lastRead *atomic.Int64
}

func (c countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
		c.lastRead.Store(time.Now().UnixNano())
	}
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
		done:      make(chan struct{}),
	}
	if c.Mux.Enabled {
		go cl.reapIdle()
		go cl.rotate()
	}
	if c.Mux.Enabled && c.AutoIP {
		cl.auto = newAutoIP(cl)
	}
	return cl
}

// Endpoints lists every route the config describes: the primary server(s)
// as tier 0 and each backup as tier 1.
func Endpoints(c *config.ClientConfig) []transport.Endpoint {
	var eps []transport.Endpoint
	add := func(tier int, server string, servers []string, sni, fp, fakeSNI string, r config.RealityClientConfig, ws, h config.WSClientConfig, ech string, insecure bool, frag *config.FragmentConfig) {
		if len(servers) == 0 {
			servers = []string{server}
		}
		// One key holder per route: keys a CDN sends back on one of its IPs
		// are good for all of them.
		var keys *transport.ECH
		if list, err := transport.ParseECHList(ech); ech != "" && err == nil {
			keys = transport.NewECH(list)
		}
		for _, srv := range servers {
			ep := transport.Endpoint{Server: srv, SNI: sni, FakeSNI: fakeSNI, Fingerprint: fp, AllowInsecure: insecure, Tier: tier}
			if r.PublicKey != "" {
				ep.Reality = &transport.RealityClient{PublicKey: r.PublicKey, ShortID: r.ShortID}
			}
			if ws.Path != "" {
				ep.WS = &transport.WSClient{Path: ws.Path, Host: ws.Host}
			}
			if h.Path != "" {
				ep.HTTP = &transport.WSClient{Path: h.Path, Host: h.Host}
			}
			ep.ECH = keys
			ep.Fragment = fragmentOf(frag)
			eps = append(eps, ep)
		}
	}
	add(0, c.Server, c.Servers, c.SNI, c.Fingerprint, c.FakeSNI, c.Reality, c.WS, c.HTTP, c.ECH, c.AllowInsecure, c.Fragment)
	for _, b := range c.Backups {
		add(1, b.Server, b.Servers, b.SNI, b.Fingerprint, b.FakeSNI, b.Reality, b.WS, b.HTTP, b.ECH, b.AllowInsecure, b.Fragment)
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
	sess, stream, err := c.openRaw(ctx, false)
	if err != nil {
		return nil, err
	}
	c.wake() // the ready session may just have been taken: replace it now
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

// openRaw returns a fresh smux stream on a session with capacity. share is as
// in selectSession.
func (c *Client) openRaw(ctx context.Context, share bool) (*muxSession, *smux.Stream, error) {
	sess, err := c.acquireSession(ctx, share)
	if err != nil {
		return nil, nil, err
	}
	stream, err := sess.OpenStream()
	if err != nil {
		// Session died between selection and use; drop it and retry once.
		c.dropSession(sess)
		sess, err = c.acquireSession(ctx, share)
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
//
// A user never queues behind a dial for longer than shareAfter, and never fails
// while a live session exists: the stream then shares the least-loaded session
// and rotation evens things out later.
func (c *Client) acquireSession(ctx context.Context, share bool) (*muxSession, error) {
	s, dial := c.selectSession(share)
	if !dial {
		return s, nil
	}
	if s == nil {
		c.dialMu.Lock()
		defer c.dialMu.Unlock()
		if again, dial := c.selectSession(share); !dial {
			return again, nil
		}
		return c.dialSession(ctx)
	}
	if !c.dialMu.TryLock() {
		return s, nil
	}
	// The dial carries on after this user has moved on, so it gets its own
	// time limit and still ends up in the pool.
	fresh := make(chan *muxSession, 1)
	go func() {
		defer c.dialMu.Unlock()
		dctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		ms, err := c.dialSession(dctx)
		if err != nil {
			logx.Debugf("client: dial while sharing a connection: %v", err)
		}
		fresh <- ms
	}()
	t := time.NewTimer(shareAfter)
	defer t.Stop()
	select {
	case ms := <-fresh:
		if ms != nil {
			return ms, nil
		}
	case <-t.C:
	}
	return s, nil
}

// selectSession picks an existing session to reuse, pruning closed ones. It
// returns dial=true when a new one is wanted; sess is then the least-loaded live
// session to fall back on, or nil if there is none.
//
// Streams go to the least-loaded session, the youngest on a tie. An empty
// session is used at once; growPool keeps one ready, because a dial crosses the
// CDN to the origin and can take seconds, which must not become the time a VPN
// takes to connect. While the pool has room and no session is empty, a new
// stream gets a connection of its own, so heavy long-lived streams (VPN users)
// spread over many TCP connections: on a lossy or per-flow-policed international
// path the total throughput is roughly proportional to the number of flows, and
// one user's loss stalls only the few users sharing that flow.
//
// share is for a stream that is being moved, whose user is already waiting: it
// takes a busy session up to mux.concurrency rather than wait for a dial, and
// rotation evens things out later. Retired sessions are never chosen.
func (c *Client) selectSession(share bool) (sess *muxSession, dial bool) {
	current := c.dialer.Active()
	suspect := current != nil && c.dialer.Suspected()
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.sessions[:0]
	var least, other *muxSession
	leastN, otherN, active := 0, 0, 0
	for _, s := range c.sessions {
		if s.IsClosed() {
			continue
		}
		live = append(live, s)
		if s.retired {
			continue
		}
		if suspect && s.ep == current && s.silentFor(now) > suspectSilence {
			// With the address in doubt, an idle connection through it proves
			// nothing: it may be as dead as the one this stream just left.
			continue
		}
		n := s.NumStreams()
		if current != nil && s.ep != current {
			// Left over from before a switch of address: only a last resort.
			if other == nil || n < otherN {
				other, otherN = s, n
			}
			continue
		}
		active++
		if least == nil || n < leastN || (n == leastN && s.born.After(least.born)) {
			least, leastN = s, n
		}
	}
	c.sessions = live
	if least == nil {
		return other, true
	}
	if active < c.mux.Pool && leastN > 0 && (!share || leastN >= c.mux.Concurrency) {
		return least, true
	}
	return least, false
}

// growPool keeps one young, empty session ready, so the next stream neither
// waits for a dial nor lands on a connection that died unnoticed. It never
// blocks: the dial runs in the background, one at a time.
func (c *Client) growPool() {
	now := time.Now()
	current := c.dialer.Active()
	c.mu.Lock()
	active, ready := 0, false
	for _, s := range c.sessions {
		if s.IsClosed() || s.retired || (current != nil && s.ep != current) {
			continue
		}
		active++
		if s.NumStreams() == 0 && now.Sub(s.born) < warmMaxAge.get() {
			ready = true
		}
	}
	if c.closed || c.growing || ready || active >= c.mux.Pool || now.Before(c.growAfter) {
		c.mu.Unlock()
		return
	}
	c.growing = true
	c.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		ms, err := c.newSession(ctx)
		if err == nil {
			// Offered to users only once data has crossed it both ways: a censor
			// may let the handshake through and then drop everything.
			if err = ms.probe(); err != nil {
				_ = ms.Close()
			} else {
				err = c.addSession(ms)
			}
		}
		// A session that landed elsewhere is usable, but the current address
		// is not working, so do not keep dialling for a ready one every tick.
		wrong := err == nil && current != nil && ms.ep != current
		if (err != nil || wrong) && c.auto != nil {
			c.auto.noteFailure()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.growing = false
		if err != nil || wrong {
			c.growFails++
			c.growAfter = time.Now().Add(min(5*time.Second<<min(c.growFails-1, 4), time.Minute))
			logx.Debugf("client: background dial: err=%v, on current address=%v", err, !wrong)
			return
		}
		c.growFails, c.growAfter = 0, time.Time{}
	}()
}

// retireStaleWarm retires empty sessions past warmMaxAge once a younger empty
// one can replace them, or when they are all that stops the pool growing.
// Callers hold c.mu.
func (c *Client) retireStaleWarm(now time.Time) {
	current := c.dialer.Active()
	active, ready := 0, false
	var stale []*muxSession
	for _, s := range c.sessions {
		if s.IsClosed() || s.retired {
			continue
		}
		onCurrent := current == nil || s.ep == current
		if onCurrent {
			active++
		}
		if s.NumStreams() == 0 {
			if onCurrent && now.Sub(s.born) < warmMaxAge.get() {
				ready = true
			} else {
				stale = append(stale, s)
			}
		}
	}
	if ready || active >= c.mux.Pool {
		for _, s := range stale {
			s.retired = true
		}
	}
}

// dialSession creates a new authenticated smux session and adds it to the pool.
func (c *Client) dialSession(ctx context.Context) (*muxSession, error) {
	ms, err := c.newSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.addSession(ms); err != nil {
		return nil, err
	}
	return ms, nil
}

// probe proves data crosses the session both ways, by asking the server to
// resume a stream that does not exist. That needs no change on the server.
func (s *muxSession) probe() error { return s.probeWithin(resumeSilence) }

// probeWithin never takes longer than d, even on a connection so stuck that
// merely opening or closing a stream would wait for smux's own long timeout.
func (s *muxSession) probeWithin(d time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- s.probeOnce(d) }()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return fmt.Errorf("client: no answer within %v", d)
	}
}

func (s *muxSession) probeOnce(d time.Duration) error {
	st, err := s.OpenStream()
	if err != nil {
		return err
	}
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(d))
	id := rand.Uint64()
	hdr := protocol.Metadata{Command: protocol.CmdResume, Address: protocol.NewAddress("0.0.0.0", 0)}.AppendTo(make([]byte, 0, 64))
	hdr = binary.BigEndian.AppendUint64(hdr, id)
	hdr = binary.BigEndian.AppendUint64(hdr, 0)
	if _, err := st.Write(hdr); err != nil {
		return err
	}
	var one [1]byte
	if _, err := st.Read(one[:]); err != nil {
		return fmt.Errorf("client: no data back over a new connection: %w", err)
	}
	return nil
}

// newSession creates an authenticated smux session outside the pool.
func (c *Client) newSession(ctx context.Context) (*muxSession, error) {
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return c.sessionOver(conn)
}

// sessionOver authenticates a smux session on an established connection.
func (c *Client) sessionOver(conn net.Conn) (*muxSession, error) {
	ep := transport.EndpointOf(conn)
	counter := new(atomic.Int64)
	lastRead := new(atomic.Int64)
	lastRead.Store(time.Now().UnixNano())
	pc := pad.New(countConn{conn, counter, lastRead})
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
	ms := &muxSession{Session: sess, born: time.Now(), bytes: counter, ep: ep, lastRead: lastRead, pc: pc}
	// Each session draws its own limits from [50%, 100%] of the configured
	// maxima, so sessions born together do not all rotate together.
	if c.mux.RotateSeconds > 0 {
		ms.maxAge = time.Duration(float64(c.mux.RotateSeconds)*(0.5+rand.Float64()*0.5)) * time.Second
	}
	if c.mux.RotateMB > 0 {
		ms.maxBytes = int64(float64(c.mux.RotateMB) * (0.5 + rand.Float64()*0.5) * 1e6)
	}
	return ms, nil
}

// addSession puts ms in the pool.
func (c *Client) addSession(ms *muxSession) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		ms.Close()
		return fmt.Errorf("tunnel: client closed")
	}
	c.sessions = append(c.sessions, ms)
	return nil
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
		c.retireStaleWarm(now)
		c.checkSilentLocked(now)
		var moves []*rstream.Stream
		var stalled []*transport.Endpoint
		for rs, ref := range c.streams {
			s := ref.sess
			if c.migrating[rs] || now.Before(ref.nextTry) {
				continue
			}
			if !s.retired && !s.IsClosed() && (rs.Stalled(stallHardTimeout) || (rs.Stalled(stallTimeout.get()) && s.silentFor(now) > stallTimeout.get())) {
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
			if c.auto != nil {
				c.auto.noteStall(ep)
			}
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
		c.growPool()
	}
}

// checkSilentLocked asks any connection carrying streams that has gone silent
// whether it is still there. Stalled sees only data we sent: a user who is purely
// downloading sends none, and would otherwise hang on a black-holed connection.
// A live but idle connection answers and is left alone for a while, at irregular
// intervals, so this is no metronome. Callers hold c.mu.
func (c *Client) checkSilentLocked(now time.Time) {
	for _, s := range c.sessions {
		if s.IsClosed() || s.retired || s.NumStreams() == 0 || s.silentFor(now) <= stallTimeout.get() {
			continue
		}
		// The wait is for connections that sit idle. One that has carried real
		// traffic since it last answered has a fresh silence to explain.
		if now.Before(s.nextCheck) && s.bytes.Load()-s.checkedBytes < silenceCheckTraffic {
			continue
		}
		if !s.checking.CompareAndSwap(false, true) {
			continue
		}
		s.nextCheck = now.Add(silenceCheckMin + rand.N(silenceCheckMin))
		go func() {
			defer s.checking.Store(false)
			err := s.probe()
			c.mu.Lock()
			if err == nil {
				s.checkedBytes = s.bytes.Load()
			}
			c.mu.Unlock()
			if err == nil || s.silentFor(time.Now()) < resumeSilence {
				return // it answered, or something else proved it alive meanwhile
			}
			c.mu.Lock()
			alreadyGone := s.retired || s.IsClosed()
			s.retired = true
			c.mu.Unlock()
			if alreadyGone {
				return
			}
			logx.Warnf("client: connection via %v went silent after %s / %d MB; replacing it", s.ep, time.Since(s.born).Round(time.Second), s.bytes.Load()/1e6)
			c.dialer.ReportStall(s.ep)
			if c.auto != nil {
				c.auto.noteStall(s.ep)
			}
			c.wake()
		}()
	}
}

// silentFor is how long nothing at all has arrived on this connection.
func (s *muxSession) silentFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, s.lastRead.Load()))
}

// readResumeReply fills reply from carrier, for up to resumeReplyTimeout, or
// until the connection it runs on has gone silent for resumeSilence.
func (s *muxSession) readResumeReply(carrier net.Conn, reply []byte) error {
	giveUp := time.Now().Add(resumeReplyTimeout)
	for got := 0; got < len(reply); {
		_ = carrier.SetReadDeadline(time.Now().Add(resumeSilence))
		n, err := carrier.Read(reply[got:])
		got += n
		if err == nil {
			continue
		}
		var ne net.Error
		now := time.Now()
		if !errors.As(err, &ne) || !ne.Timeout() || now.After(giveUp) || s.silentFor(now) >= resumeSilence {
			return err
		}
	}
	return nil
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
	sess, carrier, err := c.openRaw(ctx, true)
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
	if err := sess.readResumeReply(carrier, reply[:]); err != nil {
		carrier.Close()
		// Only a silent connection is dead. Dropping one that is merely busy
		// would throw every other user on it into a move of their own, and
		// those moves pile onto the remaining connections.
		if sess.silentFor(time.Now()) >= resumeSilence {
			c.dropSession(sess)
			c.dialer.ReportStall(sess.ep)
			if c.auto != nil {
				c.auto.noteStall(sess.ep)
			}
		}
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
		// Asking again cannot change the answer.
		c.mu.Lock()
		delete(c.streams, rs)
		c.mu.Unlock()
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
	if !c.closed {
		close(c.done)
	}
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
