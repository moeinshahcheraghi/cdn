package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
)

// Observe only the encrypted Iran-facing leg. The inner TCP service is an
// echo workload, not OpenVPN. No TLS keys are supplied to this observer.
type wireSample struct {
	mu    sync.Mutex
	data  []byte
	total int
}

func (w *wireSample) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += len(p)
	room := 128*1024 - len(w.data)
	if room > 0 {
		w.data = append(w.data, p[:min(room, len(p))]...)
	}
	return len(p), nil
}
func (w *wireSample) snapshot() ([]byte, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.data...), w.total
}
func sampleRecords(b []byte) []int {
	var out []int
	for len(b) >= 5 && len(out) < 12 {
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			break
		}
		out = append(out, n)
		b = b[5+n:]
	}
	return out
}

func TestDPILabEncryptedRoutes(t *testing.T) {
	for _, mode := range []string{"direct-tls", "cdn-websocket", "cdn-http2"} {
		t.Run(mode, func(t *testing.T) {
			env := startEnv(t, func(s *Server) { s.SetWebSocketPath(wsPath) })
			upstream := env.server
			if mode == "cdn-websocket" {
				upstream = fakeCDN(t, env.server)
			}
			if mode == "cdn-http2" {
				upstream = fakeHTTPCDN(t, env.server)
			}
			ln := listen(t)
			up, down := new(wireSample), new(wireSample)
			done := make(chan struct{})
			go func() {
				defer close(done)
				client, err := ln.Accept()
				if err != nil {
					return
				}
				defer client.Close()
				origin, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer origin.Close()
				copied := make(chan struct{})
				go func() { defer close(copied); io.Copy(origin, io.TeeReader(client, up)); origin.Close() }()
				io.Copy(client, io.TeeReader(origin, down))
				client.Close()
				<-copied
			}()
			cfg := &config.ClientConfig{Server: ln.Addr().String(), Password: testPassword, SNI: "cdn.example", Fingerprint: "firefox", AllowInsecure: true}
			if mode == "cdn-websocket" {
				cfg.WS = config.WSClientConfig{Path: wsPath}
			}
			if mode == "cdn-http2" {
				cfg.HTTP = config.WSClientConfig{Path: wsPath}
			}
			c := NewClient(cfg)
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			st, err := c.OpenStream(ctx, addrOf(t, env.echo))
			if err != nil {
				t.Fatal(err)
			}
			st.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("OPENVPN-LAB-MARKER"), 65536)
			sent := make(chan error, 1)
			go func() { _, err := st.Write(payload); sent <- err }()
			got := make([]byte, len(payload))
			_, err = io.ReadFull(st, got)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("echo failed: %v", err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			st.Close()
			c.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("tap did not close")
			}
			tx, txTotal := up.snapshot()
			rx, rxTotal := down.snapshot()
			if !bytes.Contains(tx, []byte("cdn.example")) {
				t.Fatal("expected clear SNI in non-ECH test")
			}
			for _, secret := range []string{"OPENVPN-LAB-MARKER", wsPath, "Sec-WebSocket-Key"} {
				if bytes.Contains(tx, []byte(secret)) || bytes.Contains(rx, []byte(secret)) {
					t.Fatalf("plaintext %q visible to passive observer", secret)
				}
			}
			t.Logf("%s: clear server name visible; inner marker and HTTP path absent from bounded ciphertext sample; bytes up=%d down=%d; first TLS record lengths up=%v down=%v", mode, txTotal, rxTotal, sampleRecords(tx), sampleRecords(rx))
		})
	}
}
