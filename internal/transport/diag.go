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

// Probe measures one server: TCP connect and the TLS/REALITY handshake with
// the given fingerprint. It returns durations for each stage and an error for
// the first stage that failed.
func (d *Dialer) Probe(ctx context.Context, server, fp string) (tcp, tls time.Duration, err error) {
	dd := *d
	dd.Server = server
	dd.Servers = nil
	dd.Fingerprint = fp
	t0 := time.Now()
	raw, err := dd.tcp.DialContext(ctx, "tcp", server)
	if err != nil {
		return time.Since(t0), 0, err
	}
	tcp = time.Since(t0)
	_ = raw.(*net.TCPConn).SetNoDelay(true)
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	t1 := time.Now()
	var conn net.Conn
	if dd.Reality != nil {
		conn, err = dd.realityDial(ctx, raw)
	} else {
		u := utls.UClient(raw, &utls.Config{ServerName: dd.SNI, InsecureSkipVerify: dd.AllowInsecure, NextProtos: []string{"h2", "http/1.1"}}, clientHelloID(fp))
		err = u.HandshakeContext(ctx)
		conn = u
	}
	tls = time.Since(t1)
	if err != nil {
		raw.Close()
		return tcp, tls, err
	}
	conn.Close()
	return tcp, tls, nil
}
