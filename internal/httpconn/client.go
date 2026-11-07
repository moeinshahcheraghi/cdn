// Package httpconn carries a byte stream in ordinary HTTP requests, so the
// tunnel can pass a CDN without a WebSocket.
//
// Why: a WebSocket is one long-lived bidirectional flow, and to offer one the
// client must drop h2 from its ALPN, which no browser talking to a CDN does.
// Here the client keeps the browser's ClientHello untouched, speaks HTTP/2 to
// the CDN, and the tunnel is a download plus a series of uploads:
//
//	GET  {path}/{session}        one streamed response: server -> client
//	POST {path}/{session}/{seq}  one per batch of bytes: client -> server
//
// The CDN may deliver the POSTs over different connections to the origin and
// in any order; the server puts them back in sequence. An empty POST body
// marks the end of the client's direction.
package httpconn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// UserAgent matches the default TLS fingerprint (Firefox), so the request
// and the handshake do not contradict each other behind a CDN that sees both.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"

const (
	// maxPost bounds one upload request. Large enough for bulk throughput,
	// small enough to be an unremarkable request.
	maxPost = 256 << 10
	// maxInflight is how many uploads may be in flight at once; data that
	// arrives meanwhile is batched into the next one.
	maxInflight = 8
	// bufLimit bounds what each direction queues in memory.
	bufLimit = 1 << 20
)

// Conn is a net.Conn over one HTTP/2 connection to the server (or CDN).
type Conn struct {
	tls       net.Conn
	cc        *http2.ClientConn
	host      string
	userAgent string
	base      string // https://host/path/session

	ctx    context.Context // ends with the Conn; aborts every request
	cancel context.CancelFunc

	up   *buffer // Write -> uploads
	down *buffer // download -> Read

	closeOnce sync.Once
}

// Dial opens the tunnel over conn, a TLS connection that negotiated h2. It
// returns once the server has answered the download request, so a success
// means the whole path (CDN and origin) is up. ctx bounds only the setup.
func Dial(ctx context.Context, conn net.Conn, host, path string, agent ...string) (*Conn, error) {
	ua := UserAgent
	if len(agent) > 0 {
		ua = agent[0]
	}
	if strings.ContainsAny(ua, "\r\n") {
		return nil, fmt.Errorf("invalid User-Agent")
	}
	t := &http2.Transport{DisableCompression: true}
	cc, err := t.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("httpconn: http2: %w", err)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	life, cancel := context.WithCancel(context.Background())
	c := &Conn{
		tls: conn, cc: cc, host: host, userAgent: ua,
		base:   "https://" + host + strings.TrimSuffix(path, "/") + "/" + hex.EncodeToString(id[:]),
		ctx:    life,
		cancel: cancel,
		up:     newBuffer(bufLimit),
		down:   newBuffer(bufLimit),
	}

	req, err := http.NewRequestWithContext(life, http.MethodGet, c.base, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.headers(req)
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		done <- result{resp, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		c.Close()
		return nil, fmt.Errorf("httpconn: waiting for the server: %w", ctx.Err())
	}
	if res.err != nil {
		c.Close()
		return nil, fmt.Errorf("httpconn: download request: %w", res.err)
	}
	if res.resp.StatusCode != http.StatusOK {
		res.resp.Body.Close()
		c.Close()
		return nil, fmt.Errorf("httpconn: server answered %s (wrong path or host?)", res.resp.Status)
	}
	go c.download(res.resp.Body)
	go c.upload()
	return c, nil
}

func (c *Conn) headers(req *http.Request) {
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Cache-Control", "no-cache")
}

// download moves the response body into the read buffer.
func (c *Conn) download(body io.ReadCloser) {
	defer body.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := c.down.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err == io.EOF {
			c.down.CloseWrite()
			return
		}
		if err != nil {
			c.fail(fmt.Errorf("httpconn: download: %w", err))
			return
		}
	}
}

// upload sends what Write queued, one POST per batch, a few in flight.
func (c *Conn) upload() {
	slots := make(chan struct{}, maxInflight)
	for seq := uint64(0); ; seq++ {
		// Take a slot before the data: while every slot is busy, writes
		// pile up and leave together in the next request.
		select {
		case slots <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
		chunk, err := c.up.Next(maxPost)
		if err != nil && err != io.EOF {
			return
		}
		go func(seq uint64, chunk []byte) {
			defer func() { <-slots }()
			if err := c.post(seq, chunk); err != nil {
				c.fail(err)
			}
		}(seq, chunk)
		if err == io.EOF {
			return // the empty chunk just sent is the end marker
		}
	}
}

func (c *Conn) post(seq uint64, chunk []byte) error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost,
		c.base+"/"+strconv.FormatUint(seq, 10), bytes.NewReader(chunk))
	if err != nil {
		return err
	}
	c.headers(req)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(chunk))
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("httpconn: upload: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("httpconn: upload answered %s", resp.Status)
	}
	return nil
}

// fail tears the connection down after an error in either direction.
func (c *Conn) fail(err error) {
	c.up.Close(err)
	c.down.Close(err)
	c.Close()
}

func (c *Conn) Read(p []byte) (int, error)  { return c.down.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.up.Write(p) }

// CloseWrite ends the upload direction after the bytes already written.
func (c *Conn) CloseWrite() error {
	c.up.CloseWrite()
	return nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.up.Close(net.ErrClosed)
		c.down.Close(net.ErrClosed)
		c.cc.Close()
		c.tls.Close()
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.tls.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.tls.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	c.down.SetReadDeadline(t)
	c.up.SetWriteDeadline(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.down.SetReadDeadline(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.up.SetWriteDeadline(t)
	return nil
}

// errClosed is what a closed session's calls fail with; it matches
// net.ErrClosed like a closed socket's do.
var errClosed = fmt.Errorf("httpconn: session closed: %w", net.ErrClosed)
