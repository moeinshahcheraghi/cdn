package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/xtaci/smux"
)

// Client opens tunneled streams to the server for each inbound request.
type Client struct {
	dialer   *transport.Dialer
	authHash string
	mux      config.MuxConfig

	mu       sync.Mutex
	sessions []*smux.Session
}

// NewClient constructs a tunnel client from validated config.
func NewClient(c *config.ClientConfig) *Client {
	return &Client{
		dialer:   transport.NewDialer(c.Server, c.SNI, c.Fingerprint, c.AllowInsecure),
		authHash: protocol.HashPassword(c.Password),
		mux:      c.Mux,
	}
}

// OpenStream returns a stream already addressed to target and ready to relay.
func (c *Client) OpenStream(ctx context.Context, target protocol.Address) (net.Conn, error) {
	if c.mux.Enabled {
		return c.openMuxStream(ctx, target)
	}
	return c.openDirect(ctx, target)
}

// openDirect dials a fresh TLS connection carrying a single CONNECT stream.
func (c *Client) openDirect(ctx context.Context, target protocol.Address) (net.Conn, error) {
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, 128)
	hdr = append(hdr, c.authHash...)
	hdr = append(hdr, protocol.CRLF...)
	hdr = protocol.Metadata{Command: protocol.CmdConnect, Address: target}.AppendTo(hdr)
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: write header: %w", err)
	}
	return conn, nil
}

// openMuxStream returns a stream from a pooled smux session, creating a new
// authenticated session when existing ones are full or absent.
func (c *Client) openMuxStream(ctx context.Context, target protocol.Address) (net.Conn, error) {
	sess, err := c.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := sess.OpenStream()
	if err != nil {
		// Session died between selection and use; drop it and retry once.
		c.dropSession(sess)
		sess, err = c.acquireSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = sess.OpenStream()
		if err != nil {
			return nil, err
		}
	}
	// Per-stream metadata carries no password; the session is already authed.
	hdr := protocol.Metadata{Command: protocol.CmdConnect, Address: target}.AppendTo(nil)
	if _, err := stream.Write(hdr); err != nil {
		stream.Close()
		return nil, fmt.Errorf("tunnel: write stream header: %w", err)
	}
	return stream, nil
}

// acquireSession returns a session with spare capacity, dialing one if needed.
func (c *Client) acquireSession(ctx context.Context) (*smux.Session, error) {
	c.mu.Lock()
	live := c.sessions[:0]
	var chosen *smux.Session
	for _, s := range c.sessions {
		if s.IsClosed() {
			continue
		}
		live = append(live, s)
		if chosen == nil && s.NumStreams() < c.mux.Concurrency {
			chosen = s
		}
	}
	c.sessions = live
	needNew := chosen == nil && len(c.sessions) < c.mux.Pool
	c.mu.Unlock()

	if chosen != nil {
		return chosen, nil
	}
	if !needNew {
		// Pool is saturated; reuse the least-loaded session anyway.
		c.mu.Lock()
		for _, s := range c.sessions {
			if !s.IsClosed() {
				chosen = s
				break
			}
		}
		c.mu.Unlock()
		if chosen != nil {
			return chosen, nil
		}
	}
	return c.dialSession(ctx)
}

// dialSession creates a new authenticated smux session over TLS.
func (c *Client) dialSession(ctx context.Context) (*smux.Session, error) {
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, 128)
	hdr = append(hdr, c.authHash...)
	hdr = append(hdr, protocol.CRLF...)
	dummy := protocol.NewAddress("0.0.0.0", 0)
	hdr = protocol.Metadata{Command: protocol.CmdMux, Address: dummy}.AppendTo(hdr)
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: write mux header: %w", err)
	}
	sess, err := smux.Client(conn, smuxConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel: smux client: %w", err)
	}
	c.mu.Lock()
	c.sessions = append(c.sessions, sess)
	c.mu.Unlock()
	return sess, nil
}

func (c *Client) dropSession(dead *smux.Session) {
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

// Close tears down all pooled sessions.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		_ = s.Close()
	}
	c.sessions = nil
}
