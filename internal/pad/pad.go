// Package pad frames the tunnel payload and adds random padding so that the
// sizes of the TLS records carrying it do not reveal what is inside.
//
// Why this matters: TLS hides content but not record lengths. A censor's DPI
// can recognise a proxied HTTPS session purely from its shape: a ~520-byte
// client record (the inner ClientHello) answered by a 1-4 KB server burst
// (the inner certificate flight), then a small client record (Finished).
// This "TLS-in-TLS" signature is what modern DPI uses to flag Trojan/V2Ray
// style tunnels. Likewise, an 80-byte first record (a bare auth header) or a
// metronomic 8-byte keepalive every 15 s look like nothing a browser sends.
//
// The layer is deliberately cheap: only the first few writes of each burst
// (a burst starts after a short write-idle gap) are padded, which is exactly
// where handshakes live. Bulk transfer inside a burst is passed through with
// a 2-byte header per frame and no padding, so throughput is unaffected.
//
// Wire format: each frame is a 2-byte big-endian header followed by the body.
// Bit 15 of the header marks a padding-only frame whose body is discarded;
// the low 15 bits give the body length (0..32767).
package pad

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

const (
	hdrLen   = 2
	maxBody  = 0x7fff
	flagPad  = 0x8000
	padSmall = 1400 // writes below this are padded up to about one MTU
	padLarge = 4096 // writes below this are padded up to a few segments

	// burstWrites is how many leading writes of a burst get padding.
	burstWrites = 4
	// burstIdle is the write-idle gap after which a new burst begins.
	burstIdle = 250 * time.Millisecond
)

// bufPool holds scratch buffers for assembling a write in one syscall.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 64*1024); return &b }}

// Conn wraps a stream connection with the padded framing. Reads and writes
// may each be used from one goroutine at a time (as net.Conn requires).
type Conn struct {
	net.Conn

	rrem int // bytes of the current data frame not yet delivered to Read

	wmu       sync.Mutex
	lastWrite time.Time
	burst     int
}

// New wraps c. Both peers must wrap, starting at the same byte offset.
func New(c net.Conn) *Conn { return &Conn{Conn: c} }

// WriteHeader sends raw (unframed) bytes followed by a padding-only frame,
// all in one underlying write, so the tunnel's authentication header is
// carried in a record of random, browser-request-like size.
func (c *Conn) WriteHeader(raw []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := append((*bp)[:0], raw...)
	buf = appendPad(buf, padLen(len(raw)))
	c.lastWrite = time.Now()
	c.burst = 1
	_, err := c.Conn.Write(buf)
	return err
}

// Write frames p (splitting bodies larger than a frame) and, at the start of
// a burst, appends a padding frame; the whole thing goes out in one write so
// it shares a TLS record.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	now := time.Now()
	if now.Sub(c.lastWrite) > burstIdle {
		c.burst = 0
	}
	c.lastWrite = now
	pad := 0
	if c.burst < burstWrites {
		pad = padLen(len(p))
	}
	c.burst++

	bp := bufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	for off := 0; off < len(p); {
		n := min(len(p)-off, maxBody)
		buf = appendHdr(buf, n, false)
		buf = append(buf, p[off:off+n]...)
		off += n
	}
	buf = appendPad(buf, pad)
	_, err := c.Conn.Write(buf)
	if cap(buf) <= 256*1024 {
		*bp = buf[:0]
	}
	bufPool.Put(bp)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read delivers the body of data frames, skipping padding frames. Bytes are
// read straight into p, so there is no extra copy on the receive path.
func (c *Conn) Read(p []byte) (int, error) {
	for {
		if c.rrem > 0 {
			if len(p) > c.rrem {
				p = p[:c.rrem]
			}
			n, err := c.Conn.Read(p)
			c.rrem -= n
			return n, err
		}
		var h [hdrLen]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint16(h[:])
		n := int(v & maxBody)
		if v&flagPad != 0 {
			if n > 0 {
				if _, err := io.CopyN(io.Discard, c.Conn, int64(n)); err != nil {
					return 0, err
				}
			}
			continue
		}
		c.rrem = n
		if n == 0 {
			continue
		}
		if len(p) == 0 {
			return 0, nil
		}
	}
}

// CloseWrite half-closes the underlying connection when it supports that,
// so relays can drain the other direction.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// padLen picks how much padding to add to a write of n bytes. Small writes
// become a random size up to about an MTU (like a typical HTTP request);
// medium writes a random size up to a few segments (like a certificate
// flight); large writes are already indistinguishable from bulk data.
func padLen(n int) int {
	switch {
	case n < padSmall:
		return rand.IntN(padSmall - n + 1)
	case n < padLarge:
		return rand.IntN(padLarge - n + 1)
	default:
		return 0
	}
}

func appendHdr(buf []byte, n int, padding bool) []byte {
	v := uint16(n)
	if padding {
		v |= flagPad
	}
	return binary.BigEndian.AppendUint16(buf, v)
}

// appendPad appends a padding frame of n zero bytes (zeros are fine: TLS
// encrypts them, so only the length is observable).
func appendPad(buf []byte, n int) []byte {
	if n <= 0 {
		return buf
	}
	buf = appendHdr(buf, n, true)
	return append(buf, make([]byte, n)...)
}
