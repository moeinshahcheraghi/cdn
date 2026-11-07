// Package wsconn carries a byte stream inside a WebSocket (RFC 6455), so the
// tunnel can travel through a CDN.
//
// Why: a censor can block the exit server's IP, or a datacenter can refuse
// direct connections abroad altogether. A CDN such as Cloudflare is reachable
// from almost everywhere and too important to block wholesale; it forwards
// WebSocket connections for a domain to the origin server. The relay then
// talks to the CDN's IPs with the CDN's certificate, and the exit's address
// never appears on the censored link.
//
// Only what the tunnel needs is implemented: binary messages, ping/pong and
// close. One Write is one frame; Read hides frame boundaries.
package wsconn

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xa

	guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	// maxControl is the largest control-frame payload the RFC allows.
	maxControl = 125
)

// UserAgent is sent by the client handshake; it matches the default TLS
// fingerprint so the two do not contradict each other behind a CDN that
// looks at both.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 64*1024); return &b }}

// Conn is a net.Conn over an established WebSocket.
type Conn struct {
	net.Conn
	br     *bufio.Reader
	client bool // clients mask what they send

	rrem    int64 // payload bytes left in the current data frame
	rmask   [4]byte
	rmasked bool
	rpos    int

	wmu sync.Mutex
}

// Dial performs the client handshake on conn (normally a TLS connection
// negotiated with ALPN http/1.1) and returns the stream.
func Dial(conn net.Conn, host, path string, agent ...string) (*Conn, error) {
	ua := UserAgent
	if len(agent) > 0 {
		ua = agent[0]
	}
	if strings.ContainsAny(ua, "\r\n") {
		return nil, errors.New("wsconn: invalid User-Agent")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.5\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: https://" + host + "\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Pragma: no-cache\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Upgrade: websocket\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 32*1024)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, fmt.Errorf("wsconn: read response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("wsconn: server answered %s, not a websocket upgrade (wrong path/host, or the CDN has WebSockets off)", resp.Status)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, errors.New("wsconn: bad Sec-WebSocket-Accept")
	}
	return &Conn{Conn: conn, br: br, client: true}, nil
}

// IsUpgrade reports whether r asks for a WebSocket.
func IsUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

// Accept answers the upgrade request r, which was read from conn through br,
// and returns the stream.
func Accept(conn net.Conn, br *bufio.Reader, r *http.Request) (*Conn, error) {
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return nil, err
	}
	return &Conn{Conn: conn, br: br}, nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Read returns payload bytes of binary frames, answering pings on the way.
func (c *Conn) Read(p []byte) (int, error) {
	for c.rrem == 0 {
		if err := c.nextFrame(); err != nil {
			return 0, err
		}
	}
	if int64(len(p)) > c.rrem {
		p = p[:c.rrem]
	}
	n, err := c.br.Read(p)
	if c.rmasked {
		c.rpos = xor(p[:n], c.rmask, c.rpos)
	}
	c.rrem -= int64(n)
	return n, err
}

// nextFrame reads frame headers until a data frame with a payload begins.
func (c *Conn) nextFrame() error {
	var h [14]byte
	if _, err := io.ReadFull(c.br, h[:2]); err != nil {
		return err
	}
	op := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		if _, err := io.ReadFull(c.br, h[2:4]); err != nil {
			return err
		}
		n = int64(binary.BigEndian.Uint16(h[2:]))
	case 127:
		if _, err := io.ReadFull(c.br, h[2:10]); err != nil {
			return err
		}
		n = int64(binary.BigEndian.Uint64(h[2:]))
		if n < 0 {
			return errors.New("wsconn: bad frame length")
		}
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return err
		}
	}
	switch op {
	case opBinary, opText, opCont:
		c.rrem, c.rmask, c.rmasked, c.rpos = n, mask, masked, 0
		return nil
	case opPing, opPong, opClose:
		if n > maxControl {
			return errors.New("wsconn: oversized control frame")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(c.br, body); err != nil {
			return err
		}
		if masked {
			xor(body, mask, 0)
		}
		switch op {
		case opPing:
			if err := c.writeFrame(opPong, body); err != nil {
				return err
			}
		case opClose:
			_ = c.writeFrame(opClose, nil)
			return io.EOF
		}
		return nil
	default:
		return fmt.Errorf("wsconn: unknown opcode %#x", op)
	}
}

// Write sends p as one binary frame.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) writeFrame(op byte, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	bp := bufPool.Get().(*[]byte)
	buf := append((*bp)[:0], 0x80|op)
	maskBit := byte(0)
	if c.client {
		maskBit = 0x80
	}
	switch {
	case len(p) < 126:
		buf = append(buf, maskBit|byte(len(p)))
	case len(p) <= 0xffff:
		buf = append(buf, maskBit|126)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(p)))
	default:
		buf = append(buf, maskBit|127)
		buf = binary.BigEndian.AppendUint64(buf, uint64(len(p)))
	}
	if c.client {
		var mask [4]byte
		_, _ = rand.Read(mask[:])
		buf = append(buf, mask[:]...)
		start := len(buf)
		buf = append(buf, p...)
		xor(buf[start:], mask, 0)
	} else {
		buf = append(buf, p...)
	}
	_, err := c.Conn.Write(buf)
	if cap(buf) <= 256*1024 {
		*bp = buf[:0]
	}
	bufPool.Put(bp)
	return err
}

// CloseWrite ends this direction after the frames already written. The
// underlying TLS close_notify reaches the peer behind its buffered frames,
// so it drains everything and then sees a clean end of stream.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// xor applies the 4-byte mask to b, starting at mask position pos, eight
// bytes at a time, and returns the position after b.
func xor(b []byte, mask [4]byte, pos int) int {
	for len(b) > 0 && pos&3 != 0 {
		b[0] ^= mask[pos&3]
		b = b[1:]
		pos++
	}
	m32 := binary.LittleEndian.Uint32(mask[:])
	m64 := uint64(m32)<<32 | uint64(m32)
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, binary.LittleEndian.Uint64(b)^m64)
		b = b[8:]
	}
	for i := range b {
		b[i] ^= mask[(pos+i)&3]
	}
	return pos + len(b)
}
