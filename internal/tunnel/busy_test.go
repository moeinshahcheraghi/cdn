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

// busyLink runs many VPN-like users over a link they saturate together, so
// every user's share is small and data queues for seconds behind other users'
// data on the same TCP connections. It returns how many connections were
// dialled, and fails if any user lost their stream.
func busyLink(t *testing.T, users int, rate int64, d time.Duration) int64 {
	t.Helper()
	src := listen(t)
	go serveEach(src, func(c net.Conn) {
		go io.Copy(io.Discard, c)
		b := make([]byte, 16<<10)
		for {
			if _, err := c.Write(b); err != nil {
				return
			}
		}
	})
	env := startEnv(t)
	var dials atomic.Int64
	ln := listen(t)
	go serveEach(ln, func(c net.Conn) {
		dials.Add(1)
		u, err := net.Dial("tcp", env.server)
		if err != nil {
			c.Close()
			return
		}
		go io.Copy(u, c)
		defer c.Close()
		b := make([]byte, 4<<10)
		for {
			n, err := u.Read(b)
			if n > 0 {
				time.Sleep(time.Duration(n) * time.Second / time.Duration(rate))
				if _, werr := c.Write(b[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	c := NewClient(&config.ClientConfig{
		Server: ln.Addr().String(), Password: testPassword, SNI: "localhost",
		Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: 4, RotateSeconds: 0, RotateMB: 0},
	})
	t.Cleanup(c.Close)
	var lost atomic.Int64
	stop := make(chan struct{})
	for i := 0; i < users; i++ {
		st, err := c.OpenStream(context.Background(), addrOf(t, src.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		go func() { // inner TCP ACKs and keepalives going up
			b := make([]byte, 100)
			for {
				select {
				case <-stop:
					return
				case <-time.After(200 * time.Millisecond):
				}
				if _, err := st.Write(b); err != nil {
					lost.Add(1)
					return
				}
			}
		}()
		go func() {
			if _, err := io.Copy(io.Discard, st); err != nil {
				select {
				case <-stop:
				default:
					lost.Add(1)
				}
			}
		}()
	}
	time.Sleep(d)
	close(stop)
	if n := lost.Load(); n > 0 {
		t.Errorf("%d of %d users lost their stream", n, users)
	}
	return dials.Load()
}

// A saturated link is not a broken one. Users sharing it must stay where they
// are: moving them resends what was in flight and adds load to the very link
// that is full, which in the field fed on itself for half an hour.
func TestBusyLinkCausesNoMoves(t *testing.T) {
	dials := busyLink(t, 40, 400<<10, 25*time.Second)
	t.Logf("%d connections dialled", dials)
	if dials > 8 { // pool of 4, plus a replaced ready connection or two
		t.Fatalf("%d connections dialled: users are being moved off a working link", dials)
	}
}
