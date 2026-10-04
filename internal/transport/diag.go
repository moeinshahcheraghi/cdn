package transport

import (
	"context"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Fingerprints lists the selectable browser fingerprints.
var Fingerprints = []string{"firefox", "safari", "ios", "edge", "chrome"}

// HelloSize returns the size in bytes of the ClientHello record that
// fingerprint fp would send for sni. Hellos above ~1400 bytes span two TCP
// segments, which some censors drop.
func HelloSize(fp, sni string) int {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := utls.UClient(c1, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, clientHelloID(fp))
	if err := u.BuildHandshakeState(); err != nil {
		return 0
	}
	return len(u.HandshakeState.Hello.Raw) + 5
}

// Probe measures one endpoint: TCP connect, then the full handshake (TLS,
// REALITY or WebSocket) with fingerprint fp. It returns the duration of each
// stage and an error for the first stage that failed.
func (d *Dialer) Probe(ctx context.Context, ep *Endpoint, fp string) (tcp, hs time.Duration, err error) {
	t0 := time.Now()
	raw, err := d.dialRaw(ctx, ep)
	if err != nil {
		return time.Since(t0), 0, err
	}
	tcp = time.Since(t0)
	defer raw.Close()
	t1 := time.Now()
	conn, err := d.handshake(ctx, raw, ep, fp)
	hs = time.Since(t1)
	if err != nil {
		return tcp, hs, err
	}
	conn.Close()
	return tcp, hs, nil
}

// TCPDialer exposes the dialer's TCP settings for diagnostics.
func (d *Dialer) TCPDialer() *net.Dialer { return &d.tcp }
