package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/fallback"
	"github.com/moeinshah0/tunnel/internal/transport"
)

const realityDest = "www.microsoft.com:443"

func TestRealityEndToEnd(t *testing.T) {
	if c, err := net.DialTimeout("tcp", realityDest, 5*time.Second); err != nil {
		t.Skipf("no internet access to %s: %v", realityDest, err)
	} else {
		c.Close()
	}
	priv, pub, err := transport.GenerateRealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := transport.NewRealityConfig(&transport.RealityServer{
		Dest: realityDest, ServerNames: []string{"www.microsoft.com"},
		PrivateKey: priv, ShortIDs: []string{"a1b2c3d4"}, MaxTimeDiff: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	echo := listen(t)
	go serveEach(echo, func(c net.Conn) { io.Copy(c, c) })
	srv := NewServer(nil, []string{testPassword}, fallback.New("127.0.0.1:1"))
	srv.SetReality(rc)
	ln := listen(t)
	go serveEach(ln, srv.Handle)

	// 1) Authenticated client relays data.
	cfg := &config.ClientConfig{
		Server: ln.Addr().String(), Password: testPassword, SNI: "www.microsoft.com",
		Fingerprint: "firefox", Reality: config.RealityClientConfig{PublicKey: pub, ShortID: "a1b2c3d4"},
		Mux: config.MuxConfig{Enabled: true, Concurrency: 8, Pool: 2},
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := c.OpenStream(ctx, addrOf(t, echo.Addr().String()))
	if err != nil {
		t.Fatalf("reality client: %v", err)
	}
	payload := make([]byte, 1<<20)
	rand.Read(payload)
	go func() { stream.Write(payload); stream.(interface{ CloseWrite() error }).CloseWrite() }()
	got, _ := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %d bytes", len(got))
	}
	stream.Close()

	// 1b) A fragmented ClientHello still authenticates, in both modes.
	for _, mode := range []string{"records", "tcp"} {
		fc := *cfg
		fc.Fragment = &config.FragmentConfig{Enabled: true, Mode: mode, Size: "10-40", Delay: "1-3"}
		t.Run("fragment-"+mode, func(t *testing.T) { echoThrough(t, &fc, echo.Addr().String(), 256<<10) })
	}

	// 2) A prober with the right SNI but no key gets Microsoft's real chain.
	pc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "www.microsoft.com", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("probe handshake: %v (a real browser would have failed too)", err)
	}
	leaf := pc.ConnectionState().PeerCertificates[0]
	pc.Close()
	t.Logf("prober saw certificate for %v issued by %s", leaf.DNSNames[:min(3, len(leaf.DNSNames))], leaf.Issuer.CommonName)
	if err := leaf.VerifyHostname("www.microsoft.com"); err != nil {
		t.Fatalf("prober did not get a genuine certificate: %v", err)
	}

	// 3) Wrong key: our client must refuse (it would be talking to Microsoft).
	bad := &config.ClientConfig{
		Server: ln.Addr().String(), Password: testPassword, SNI: "www.microsoft.com",
		Fingerprint: "firefox", Reality: config.RealityClientConfig{PublicKey: pub, ShortID: "ffff"},
		Mux: config.MuxConfig{Enabled: false},
	}
	bc := NewClient(bad)
	t.Cleanup(bc.Close)
	if _, err := bc.OpenStream(ctx, addrOf(t, echo.Addr().String())); err == nil {
		t.Fatal("client with wrong short id was accepted")
	} else {
		t.Logf("wrong short id rejected: %v", err)
	}
}
