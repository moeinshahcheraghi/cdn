// Package socks implements the client-side local proxies (SOCKS5 and HTTP)
// that accept application traffic and describe the destination for the tunnel.
package socks

import (
	"bufio"
	"io"
	"net"

	"github.com/moeinshah0/tunnel/internal/protocol"
)

// Request is a fully-handshaked inbound connection ready to be tunneled.
type Request struct {
	// Target is where the application wants to go.
	Target protocol.Address
	// Conn is the local connection; reading it yields the application's bytes,
	// including any prefix buffered or synthesized during negotiation.
	Conn net.Conn
}

// prefixConn routes reads through a lead reader (synthetic bytes followed by
// the buffered reader over the real socket) while writes and metadata pass
// straight through. Bytes consumed or rewritten during negotiation thus still
// reach the origin in order.
type prefixConn struct {
	net.Conn
	lead io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.lead.Read(b) }

// withReadPrefix wraps c so reads yield lead, then anything buffered in br,
// then the live socket. If there is nothing pending, c is returned unwrapped.
func withReadPrefix(c net.Conn, br *bufio.Reader, lead []byte) net.Conn {
	if len(lead) == 0 && br.Buffered() == 0 {
		return c
	}
	readers := make([]io.Reader, 0, 2)
	if len(lead) > 0 {
		readers = append(readers, &sliceReader{b: lead})
	}
	readers = append(readers, br) // br reads buffered bytes then the socket
	return &prefixConn{Conn: c, lead: io.MultiReader(readers...)}
}

// sliceReader turns a slice into a one-shot io.Reader.
type sliceReader struct {
	b []byte
	i int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.i >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.i:])
	s.i += n
	return n, nil
}
