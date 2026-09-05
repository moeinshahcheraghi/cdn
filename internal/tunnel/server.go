package tunnel

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/moeinshah0/tunnel/internal/fallback"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/pad"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/relay"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/xtaci/smux"
)

// authTimeout bounds the TLS handshake plus the wait for the client's first
// record. It is deliberately generous, like a web server's header timeout,
// so that a slow-but-real client is not misclassified; a probe that sends a
// complete request is answered immediately regardless (see Handle).
const authTimeout = 30 * time.Second

// dialTimeout bounds connecting to a requested destination.
const dialTimeout = 15 * time.Second

// Server terminates TLS, authenticates clients, and relays their streams.
type Server struct {
	tlsConfig *tls.Config
	hashes    [][]byte // accepted password digests
	fallback  *fallback.Handler
}

// NewServer builds a Server from a TLS config, accepted passwords, and origin.
func NewServer(tlsConfig *tls.Config, passwords []string, fb *fallback.Handler) *Server {
	hashes := make([][]byte, len(passwords))
	for i, p := range passwords {
		hashes[i] = []byte(protocol.HashPassword(p))
	}
	return &Server{tlsConfig: tlsConfig, hashes: hashes, fallback: fb}
}

// Handle processes one accepted TCP connection end to end.
func (s *Server) Handle(raw net.Conn) {
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	conn := tls.Server(raw, s.tlsConfig)
	_ = conn.SetDeadline(time.Now().Add(authTimeout))
	if err := conn.Handshake(); err != nil {
		logx.Debugf("server: tls handshake from %s: %v", raw.RemoteAddr(), err)
		conn.Close()
		return
	}
	if conn.ConnectionState().NegotiatedProtocol == transport.ACMEALPN {
		// A certificate-authority validation connection; the handshake itself
		// was the whole point.
		conn.Close()
		return
	}

	// Read the client's first record with a single Read rather than
	// io.ReadFull: our client always puts the whole header in one record, and
	// a web browser's request is longer than the digest anyway. A probe that
	// sends a short but complete request must not be left hanging until the
	// deadline (a real web server would answer at once), so whatever arrived
	// is judged immediately and replayed verbatim to the fallback origin.
	prefix := make([]byte, protocol.HashLen)
	n, err := conn.Read(prefix)
	if err != nil || !s.authorized(prefix[:n]) {
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
	sess, err := smux.Server(conn, smuxConfig())
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
	_ = stream.SetReadDeadline(time.Time{})
	if meta.Command != protocol.CmdConnect {
		stream.Close()
		return
	}
	s.relayTCP(stream, meta.Address)
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
