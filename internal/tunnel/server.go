package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/moeinshah0/tunnel/internal/fallback"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/pad"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/relay"
	"github.com/moeinshah0/tunnel/internal/rstream"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/moeinshah0/tunnel/internal/wsconn"
	"github.com/xtaci/smux"
	"github.com/xtls/reality"
)

// authTimeout bounds the TLS handshake plus the wait for the client's first
// record. It is deliberately generous, like a web server's header timeout,
// so that a slow-but-real client is not misclassified; a probe that sends a
// complete request is answered immediately regardless (see Handle).
const authTimeout = 30 * time.Second

// dialTimeout bounds connecting to a requested destination.
const dialTimeout = 15 * time.Second

// resumeTimeout is how long a resumable stream survives without a carrier,
// waiting for the client to continue it over a new connection. It is generous
// because a client whose connection just died may need several attempts over
// a bad link, and losing the stream means dropping the user's session.
const resumeTimeout = 3 * time.Minute

// Server terminates TLS, authenticates clients, and relays their streams.
type Server struct {
	tlsConfig *tls.Config
	reality   *reality.Config // when set, REALITY replaces tlsConfig
	hashes    [][]byte        // accepted password digests
	fallback  *fallback.Handler
	wsPath    string // when set, a WebSocket upgrade to this path is a carrier

	// streams holds live resumable streams by id, across carriers — and
	// across listeners, so a stream opened on the main port can be resumed
	// through the CDN door when the direct route stops working.
	streams *streamTable
}

// streamTable is the registry of live resumable streams.
type streamTable struct {
	mu sync.Mutex
	m  map[uint64]*rstream.Stream
}

// SetReality switches the server to REALITY mode.
func (s *Server) SetReality(cfg *reality.Config) { s.reality = cfg }

// SetWebSocketPath accepts the tunnel inside a WebSocket upgrade to path, so
// clients can reach the server through a CDN. Every other request, and every
// other path, is still served by the fallback site.
func (s *Server) SetWebSocketPath(path string) { s.wsPath = path }

// CertHandler returns a view of this server that terminates ordinary
// certificate TLS instead of REALITY, for a second port a CDN connects to.
// Resumable streams are shared with the main listener, so a stream may be
// resumed over whichever door is reachable at the time.
func (s *Server) CertHandler() *Server {
	return &Server{
		tlsConfig: s.tlsConfig,
		hashes:    s.hashes,
		fallback:  s.fallback,
		wsPath:    s.wsPath,
		streams:   s.streams,
	}
}

// NewServer builds a Server from a TLS config, accepted passwords, and origin.
func NewServer(tlsConfig *tls.Config, passwords []string, fb *fallback.Handler) *Server {
	hashes := make([][]byte, len(passwords))
	for i, p := range passwords {
		hashes[i] = []byte(protocol.HashPassword(p))
	}
	return &Server{tlsConfig: tlsConfig, hashes: hashes, fallback: fb,
		streams: &streamTable{m: map[uint64]*rstream.Stream{}}}
}

// Handle processes one accepted TCP connection end to end.
func (s *Server) Handle(raw net.Conn) {
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	var conn net.Conn
	if s.reality != nil {
		// REALITY authenticates during the handshake; anyone who fails it has
		// already been spliced to the real site by the library.
		ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
		rc, err := transport.RealityHandshake(ctx, raw, s.reality)
		cancel()
		if err != nil {
			// The library says exactly why (dest unreachable, auth failed,
			// target sent an unexpected hello...); operators need to see it.
			logx.Warnf("server: %v", err)
			return
		}
		conn = rc
	} else {
		tc := tls.Server(raw, s.tlsConfig)
		_ = tc.SetDeadline(time.Now().Add(authTimeout))
		if err := tc.Handshake(); err != nil {
			logx.Debugf("server: tls handshake from %s: %v", raw.RemoteAddr(), err)
			tc.Close()
			return
		}
		if tc.ConnectionState().NegotiatedProtocol == transport.ACMEALPN {
			// A certificate-authority validation connection; the handshake
			// itself was the whole point.
			tc.Close()
			return
		}
		conn = tc
	}
	s.serveDecrypted(conn)
}

// serveDecrypted authenticates and serves one connection whose encryption
// layer is already established.
func (s *Server) serveDecrypted(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(authTimeout))

	// Read the client's first record with a single Read rather than
	// io.ReadFull: our client always puts the whole header in one record, and
	// a web browser's request is longer than the digest anyway. A probe that
	// sends a short but complete request must not be left hanging until the
	// deadline (a real web server would answer at once), so whatever arrived
	// is judged immediately and replayed verbatim to the fallback origin.
	prefix := make([]byte, protocol.HashLen)
	n, err := conn.Read(prefix)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		s.fallback.Serve(conn, prefix[:n])
		return
	}
	if s.wsPath != "" && looksHTTP(prefix[:n]) {
		s.serveWebSocket(conn, prefix[:n])
		return
	}
	if !s.authorized(prefix[:n]) {
		_ = conn.SetDeadline(time.Time{})
		s.fallback.Serve(conn, prefix[:n])
		return
	}

	// Consume the CRLF after the digest, then the request metadata. Keep the
	// bytes so that even a malformed-but-authenticated request is handed to
	// the fallback without revealing anything.
	var seen bytes.Buffer
	seen.Write(prefix)
	tee := io.TeeReader(conn, &seen)
	if err := expectCRLF(tee); err != nil {
		_ = conn.SetDeadline(time.Time{})
		s.fallback.Serve(conn, seen.Bytes())
		return
	}
	meta, err := protocol.ReadMetadata(tee)
	if err != nil {
		logx.Debugf("server: read metadata: %v", err)
		_ = conn.SetDeadline(time.Time{})
		s.fallback.Serve(conn, seen.Bytes())
		return
	}
	_ = conn.SetDeadline(time.Time{})

	// Everything after the header travels in padded frames.
	pc := pad.New(conn)
	switch meta.Command {
	case protocol.CmdMux:
		s.serveMux(pc)
	case protocol.CmdConnect:
		s.relayTCP(pc, meta.Address)
	default:
		logx.Debugf("server: unsupported command 0x%02x", byte(meta.Command))
		conn.Close()
	}
}

// looksHTTP reports whether b starts like an HTTP request line, which is
// what a WebSocket upgrade (or a probe with a browser) begins with.
func looksHTTP(b []byte) bool {
	return bytes.HasPrefix(b, []byte("GET ")) || bytes.HasPrefix(b, []byte("HEAD ")) ||
		bytes.HasPrefix(b, []byte("POST ")) || bytes.HasPrefix(b, []byte("OPTI"))
}

// serveWebSocket handles an HTTP request that arrived instead of a digest.
// A WebSocket upgrade to the secret path becomes a tunnel carrier; anything
// else is a visitor (or a probe) and goes to the fallback site untouched,
// bytes and all, so the port is a plain website to everyone but us.
func (s *Server) serveWebSocket(conn net.Conn, prefix []byte) {
	// seen records the bytes read, so a visitor can be handed to the
	// fallback untouched. Recording stops once the request is judged: an
	// accepted carrier must not copy its whole life into memory.
	rec := &recorder{}
	rec.buf.Write(prefix)
	br := bufio.NewReaderSize(io.TeeReader(conn, rec), 32*1024)
	// The request line already read is replayed ahead of the rest.
	full := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(prefix), br), 32*1024)
	req, err := http.ReadRequest(full)
	if err != nil || req.URL.Path != s.wsPath || !wsconn.IsUpgrade(req) {
		_ = conn.SetDeadline(time.Time{})
		s.fallback.Serve(conn, rec.stop())
		return
	}
	rec.stop()
	ws, err := wsconn.Accept(conn, full, req)
	if err != nil {
		conn.Close()
		return
	}
	logx.Debugf("server: websocket carrier from %s", conn.RemoteAddr())
	s.serveDecrypted(ws)
}

// recorder is a Writer that keeps what it is given until stopped.
type recorder struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	stopped bool
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	if !r.stopped {
		r.buf.Write(p)
	}
	r.mu.Unlock()
	return len(p), nil
}

// stop ends recording and returns what was recorded.
func (r *recorder) stop() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	b := r.buf.Bytes()
	r.buf = bytes.Buffer{}
	return b
}

// authorized reports whether prefix matches any accepted digest, in constant
// time so a probe cannot learn the secret by measuring response timing.
func (s *Server) authorized(prefix []byte) bool {
	if len(prefix) != protocol.HashLen {
		return false
	}
	ok := false
	for _, h := range s.hashes {
		if subtle.ConstantTimeCompare(prefix, h) == 1 {
			ok = true
		}
	}
	return ok
}

// serveMux runs a smux server session, relaying each accepted stream.
func (s *Server) serveMux(conn net.Conn) {
	sess, err := smux.Server(conn, smuxConfig(serverMuxStreams))
	if err != nil {
		logx.Debugf("server: smux: %v", err)
		conn.Close()
		return
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go s.serveMuxStream(stream)
	}
}

// serveMuxStream reads a per-stream metadata header and relays to the target.
func (s *Server) serveMuxStream(stream *smux.Stream) {
	_ = stream.SetReadDeadline(time.Now().Add(authTimeout))
	meta, err := protocol.ReadMetadata(stream)
	if err != nil {
		stream.Close()
		return
	}
	switch meta.Command {
	case protocol.CmdConnect:
		_ = stream.SetReadDeadline(time.Time{})
		s.relayTCP(stream, meta.Address)
	case protocol.CmdConnectR:
		var id [8]byte
		if _, err := io.ReadFull(stream, id[:]); err != nil {
			stream.Close()
			return
		}
		_ = stream.SetReadDeadline(time.Time{})
		rs := s.newStream(binary.BigEndian.Uint64(id[:]))
		if err := rs.Attach(stream, 0); err != nil {
			stream.Close()
			return
		}
		s.relayTCP(rs, meta.Address)
	case protocol.CmdResume:
		var req [16]byte
		if _, err := io.ReadFull(stream, req[:]); err != nil {
			stream.Close()
			return
		}
		_ = stream.SetReadDeadline(time.Time{})
		s.resume(stream, binary.BigEndian.Uint64(req[:8]), binary.BigEndian.Uint64(req[8:]))
	default:
		stream.Close()
	}
}

// newStream registers a resumable stream that unregisters itself on close.
func (s *Server) newStream(id uint64) *rstream.Stream {
	rs := rstream.New(id, resumeTimeout)
	t := s.streams
	t.mu.Lock()
	if old := t.m[id]; old != nil {
		old.Close()
	}
	t.m[id] = rs
	t.mu.Unlock()
	rs.SetOnClose(func() {
		t.mu.Lock()
		if t.m[id] == rs {
			delete(t.m, id)
		}
		t.mu.Unlock()
	})
	return rs
}

// resume continues stream id over carrier, replying with our received
// offset so the client can retransmit exactly what was lost.
func (s *Server) resume(carrier net.Conn, id, clientRecvOff uint64) {
	s.streams.mu.Lock()
	rs := s.streams.m[id]
	s.streams.mu.Unlock()
	var reply [9]byte
	if rs == nil {
		reply[0] = 1
		carrier.Write(reply[:])
		carrier.Close()
		logx.Debugf("server: resume of unknown stream %x", id)
		return
	}
	// Report our offset without detaching: if this resume does not complete,
	// the stream must keep running on whatever carrier it still has. Attach
	// below performs the swap atomically. A few bytes may arrive on the old
	// carrier in between, which only makes the client resend what we already
	// have, and duplicates are dropped by offset.
	reply[0] = protocol.ResumeOK
	binary.BigEndian.PutUint64(reply[1:], rs.RecvOffset())
	if _, err := carrier.Write(reply[:]); err != nil {
		carrier.Close()
		return
	}
	if err := rs.Attach(carrier, clientRecvOff); err != nil {
		logx.Debugf("server: resume %x: %v", id, err)
		carrier.Close()
		return
	}
	logx.Debugf("server: resumed stream %x at %d", id, clientRecvOff)
}

// relayTCP dials the destination and pipes bytes both ways.
func (s *Server) relayTCP(src net.Conn, target protocol.Address) {
	dst, err := net.DialTimeout("tcp", target.String(), dialTimeout)
	if err != nil {
		logx.Debugf("server: dial %s: %v", target, err)
		src.Close()
		return
	}
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	logx.Debugf("server: relay -> %s", target)
	relay.Pipe(src, dst)
	src.Close()
	dst.Close()
}

// expectCRLF reads and verifies a trailing CRLF.
func expectCRLF(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != 0x0d || b[1] != 0x0a {
		return io.ErrUnexpectedEOF
	}
	return nil
}
