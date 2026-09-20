package tunnel

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
)

// A "blaster" target writes unbounded data. A few client streams never read
// (slow users); the rest read as fast as they can. With a session receive
// bucket smaller than streams*per-stream buffer, the stalled streams fill the
// bucket and the fast streams starve.
func TestHeadOfLineBlocking(t *testing.T) {
	env := startEnv(t)
	blaster := listen(t)
	go serveEach(blaster, func(c net.Conn) {
		buf := make([]byte, 64*1024)
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	})
	cfg := &config.ClientConfig{
		Server: env.server, Password: testPassword, SNI: "localhost",
		Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: 1},
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)

	var fastBytes int64
	const stalled, fast = 6, 20
	for i := 0; i < stalled; i++ {
		s, err := c.OpenStream(context.Background(), addrOf(t, blaster.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		s.Write([]byte{1}) // flush header
		go func() {         // slow user: a trickle of reads, so the full window is advertised
			buf := make([]byte, 512)
			for {
				if _, err := s.Read(buf); err != nil {
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}
	for i := 0; i < fast; i++ {
		s, err := c.OpenStream(context.Background(), addrOf(t, blaster.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, err := s.Read(buf)
				atomic.AddInt64(&fastBytes, int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(2 * time.Second)
	before := atomic.LoadInt64(&fastBytes)
	time.Sleep(3 * time.Second)
	rate := float64(atomic.LoadInt64(&fastBytes)-before) / 3 / 1e6
	t.Logf("fast streams aggregate after warm-up: %.1f MB/s", rate)
	if rate < 5 {
		t.Fatalf("fast streams starved (%.2f MB/s): head-of-line blocking by %d stalled streams", rate, stalled)
	}
}

var _ = io.EOF
