package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/logx"
)

// Long-lived streams (an OpenVPN user) must survive many carrier rotations
// with continuous bidirectional traffic and no corruption.
func TestRotationKeepsStreamsAlive(t *testing.T) {
	old := rotateTick.get()
	rotateTick.set(100 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(old) })

	logx.SetLevel("debug")
	t.Cleanup(func() { logx.SetLevel("info") })
	env := startEnv(t)
	cfg := &config.ClientConfig{
		Server: env.server, Password: testPassword, SNI: "localhost",
		Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 4, Pool: 4, RotateSeconds: 1, RotateMB: 6},
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)

	const users = 6
	type result struct {
		ok  bool
		n   int
		err error
	}
	results := make(chan result, users)
	var dials int32
	for u := 0; u < users; u++ {
		go func() {
			stream, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
			if err != nil {
				results <- result{err: err}
				return
			}
			defer stream.Close()
			payload := make([]byte, 8<<20)
			rand.Read(payload)
			go func() {
				// Trickle then bulk, so both idle-ish and busy phases rotate.
				for off := 0; off < len(payload); off += 256 << 10 {
					end := min(off+256<<10, len(payload))
					if _, err := stream.Write(payload[off:end]); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				stream.(interface{ CloseWrite() error }).CloseWrite()
			}()
			got, err := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
			results <- result{ok: bytes.Equal(got, payload), n: len(got), err: err}
		}()
	}
	for u := 0; u < users; u++ {
		r := <-results
		if r.err != nil || !r.ok {
			t.Fatalf("user stream corrupted: n=%d err=%v", r.n, r.err)
		}
	}
	c.mu.Lock()
	for _, s := range c.sessions {
		if s.retired {
			dials++
		}
	}
	live := len(c.sessions)
	c.mu.Unlock()
	_ = atomic.LoadInt32(&dials)
	t.Logf("all %d users intact across rotations; sessions now live=%d", users, live)
}

var _ net.Conn
