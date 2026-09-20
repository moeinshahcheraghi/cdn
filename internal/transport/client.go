package transport

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Dialer establishes browser-looking TLS connections to the tunnel server.
type Dialer struct {
	Server        string   // host:port of the server
	Servers       []string // alternatives; each dial picks one at random
	SNI           string // ServerName to present
	Fingerprint   string // browser to mimic
	AllowInsecure bool   // skip cert verification (self-signed)
	// Reality, when set, replaces certificate-based TLS with the REALITY
	// handshake (see reality.go); SNI is then the imitated site's name.
	Reality *RealityClient
	tcp     net.Dialer
}

// NewDialer builds a Dialer with sensible TCP timeouts and keepalive.
func NewDialer(server, sni, fingerprint string, insecure bool) *Dialer {
	if sni == "" {
		if host, _, err := net.SplitHostPort(server); err == nil {
			sni = host
		}
	}
	return &Dialer{
		Server:        server,
		SNI:           sni,
		Fingerprint:   fingerprint,
		AllowInsecure: insecure,
		tcp:           net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: KeepAlive},
	}
}

// Dial opens a TCP connection and performs a uTLS handshake whose ClientHello
// matches a real browser, so DPI fingerprinting (JA3/JA4) cannot flag it.
func (d *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	server := d.Server
	if len(d.Servers) > 0 {
		server = d.Servers[rand.IntN(len(d.Servers))]
	}
	raw, err := d.tcp.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", server, err)
	}
	tcp := raw.(*net.TCPConn)
	_ = tcp.SetNoDelay(true) // low latency: don't wait to coalesce small writes

	if d.Reality != nil {
		if deadline, ok := ctx.Deadline(); ok {
			_ = raw.SetDeadline(deadline)
		} else {
			_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		}
		conn, err := d.realityDial(ctx, raw)
		if err != nil {
			raw.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}

	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         d.SNI,
		InsecureSkipVerify: d.AllowInsecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}, clientHelloID(d.Fingerprint))

	if deadline, ok := ctx.Deadline(); ok {
		_ = uconn.SetDeadline(deadline)
	} else {
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: tls handshake: %w", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	return uconn, nil
}

// clientHelloID maps a name to a uTLS fingerprint, defaulting to auto-Chrome.
// "random" builds a hello no real browser sends and is the weakest choice
// against fingerprint whitelisting; it exists only for experiments.
func clientHelloID(name string) utls.ClientHelloID {
	switch name {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloChrome_Auto
	}
}
