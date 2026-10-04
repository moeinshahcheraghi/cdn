package transport

import (
	"bytes"
	"math/rand/v2"
	"net"
	"time"
)

// Fragment splits the TLS ClientHello into small pieces sent in separate TCP
// segments, so a censor that reads the server name from a single packet (or
// a single TLS record) cannot classify the connection. Servers reassemble the
// hello as TLS requires; nothing after the hello is touched.
type Fragment struct {
	// Records cuts the hello into several TLS records as well; without it
	// the hello stays one record spread over several segments.
	Records            bool
	MinSize, MaxSize   int
	MinDelay, MaxDelay time.Duration
}

func (f *Fragment) String() string {
	mode := "tcp"
	if f.Records {
		mode = "records"
	}
	return mode
}

// fragConn applies f to the first write on the connection, which is where
// the TLS client puts its ClientHello.
type fragConn struct {
	net.Conn
	f    *Fragment
	sni  string
	done bool
}

func fragment(conn net.Conn, f *Fragment, sni string) net.Conn {
	if f == nil {
		return conn
	}
	return &fragConn{Conn: conn, f: f, sni: sni}
}

func (c *fragConn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.done = true
	for i, piece := range c.f.split(p, c.sni) {
		if i > 0 {
			time.Sleep(c.f.delay())
		}
		if _, err := c.Conn.Write(piece); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// SetNoDelay keeps the TCP option reachable through the wrapper: without
// it the kernel would coalesce the pieces back into one segment.
func (c *fragConn) SetNoDelay(on bool) error {
	if t, ok := c.Conn.(interface{ SetNoDelay(bool) error }); ok {
		return t.SetNoDelay(on)
	}
	return nil
}

func (c *fragConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

const recordHeaderLen = 5

// split returns the pieces to write for p. Anything that is not a whole
// handshake record is returned unchanged.
func (f *Fragment) split(p []byte, sni string) [][]byte {
	if len(p) < recordHeaderLen || p[0] != 0x16 {
		return [][]byte{p}
	}
	n := int(p[3])<<8 | int(p[4])
	if recordHeaderLen+n > len(p) {
		return [][]byte{p}
	}
	body, rest := p[recordHeaderLen:recordHeaderLen+n], p[recordHeaderLen+n:]
	cuts := f.cuts(len(body), bytes.Index(body, []byte(sni)), len(sni))

	var out [][]byte
	if f.Records {
		prev := 0
		for _, cut := range append(cuts, len(body)) {
			chunk := body[prev:cut]
			rec := make([]byte, 0, recordHeaderLen+len(chunk))
			rec = append(rec, p[0], p[1], p[2], byte(len(chunk)>>8), byte(len(chunk)))
			out = append(out, append(rec, chunk...))
			prev = cut
		}
	} else {
		// The header travels with the first piece, so cuts shift by it.
		prev := 0
		for _, cut := range append(cuts, len(body)) {
			end := recordHeaderLen + cut
			out = append(out, p[prev:end])
			prev = end
		}
	}
	if len(rest) > 0 {
		out = append(out, rest)
	}
	return out
}

// cuts returns increasing offsets in (0, n) at which to cut a body of n
// bytes: random piece sizes, plus one cut in the middle of the server name
// (found at sniAt) so no piece carries it whole.
func (f *Fragment) cuts(n, sniAt, sniLen int) []int {
	var cuts []int
	mid := -1
	if sniAt >= 0 && sniLen > 1 {
		mid = sniAt + sniLen/2
	}
	for at := f.size(); at < n; at += f.size() {
		if mid > 0 && mid < at {
			if len(cuts) == 0 || cuts[len(cuts)-1] < mid {
				cuts = append(cuts, mid)
			}
			mid = -1
		}
		if len(cuts) == 0 || cuts[len(cuts)-1] < at {
			cuts = append(cuts, at)
		}
	}
	if mid > 0 && mid < n && (len(cuts) == 0 || cuts[len(cuts)-1] < mid) {
		cuts = append(cuts, mid)
	}
	return cuts
}

func (f *Fragment) size() int {
	if f.MaxSize <= f.MinSize {
		return max(f.MinSize, 1)
	}
	return f.MinSize + rand.IntN(f.MaxSize-f.MinSize+1)
}

func (f *Fragment) delay() time.Duration {
	if f.MaxDelay <= f.MinDelay {
		return f.MinDelay
	}
	return f.MinDelay + rand.N(f.MaxDelay-f.MinDelay+1)
}
