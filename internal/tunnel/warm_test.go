package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/rstream"
)

// gate forwards to target. freezeFirst silently drops everything on one
// connection, which is how a censor cuts a flow; hold makes new connections
// wait, like a slow path from a CDN to its origin.
type gate struct {
	ln   net.Listener
	hold atomic.Bool

	mu   sync.Mutex
	open []*atomic.Bool
}

func startGate(t *testing.T, target string) *gate {
	t.Helper()
	g := &gate{ln: listen(t)}
	go serveEach(g.ln, func(c net.Conn) {
		for g.hold.Load() {
			time.Sleep(10 * time.Millisecond)
		}
		up, err := net.Dial("tcp", target)
		if err != nil {
			c.Close()
			return
		}
		dropped := new(atomic.Bool)
		g.mu.Lock()
		g.open = append(g.open, dropped)
		g.mu.Unlock()
		go gatePipe(c, up, dropped)
		gatePipe(up, c, dropped)
	})
	return g
}

func gatePipe(dst, src net.Conn, dropped *atomic.Bool) {
	defer dst.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !dropped.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// freezeAll cuts every connection open now.
func (g *gate) freezeAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, d := range g.open {
		d.Store(true)
	}
}

// freezeFirst cuts only the oldest connection, once a second one is up: one
// flow being cut while the route stays good.
func (g *gate) freezeFirst(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		g.mu.Lock()
		if len(g.open) >= 2 {
			g.open[0].Store(true)
			g.mu.Unlock()
			return
		}
		g.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no second connection came up")
		}
	}
}

func warmClient(t *testing.T, server string) *Client {
	t.Helper()
	c := NewClient(&config.ClientConfig{
		Server: server, Password: testPassword, SNI: "localhost",
		Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: 32, RotateSeconds: 240, RotateMB: 192},
	})
	t.Cleanup(c.Close)
	return c
}

func roundTrip(t *testing.T, st net.Conn) {
	t.Helper()
	b := make([]byte, 1200)
	if _, err := st.Write(b); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st, b); err != nil {
		t.Fatal(err)
	}
}

// A carrier the network black-holes mid-flow must cost the user a few seconds,
// on the same stream, without the VPN being restarted.
func TestBlackholedCarrierRecoversQuickly(t *testing.T) {
	env := startEnv(t)
	g := startGate(t, env.server)
	c := warmClient(t, g.ln.Addr().String())
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	g.freezeFirst(t)
	t0 := time.Now()
	roundTrip(t, st)
	d := time.Since(t0)
	t.Logf("stream answered again after %v", d.Round(10*time.Millisecond))
	if d > 8*time.Second {
		t.Fatalf("recovery took %v", d)
	}
}

// Once the client is warm, a new connection must not wait for a dial: that
// wait, not the tunnel, is what a slow path to the origin would add.
func TestNewStreamDoesNotWaitForDial(t *testing.T) {
	old := rotateTick.get()
	rotateTick.set(50 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(old) })
	env := startEnv(t)
	g := startGate(t, env.server)
	c := warmClient(t, g.ln.Addr().String())
	c.Warm(context.Background())

	g.hold.Store(true)
	t.Cleanup(func() { g.hold.Store(false) })
	t0 := time.Now()
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	d := time.Since(t0)
	t.Logf("first round trip after %v", d.Round(time.Millisecond))
	if d > time.Second {
		t.Fatalf("new stream waited %v", d)
	}
}

// An idle client keeps one young session ready, without piling them up.
func TestWarmSessionIsReplacedBeforeItAges(t *testing.T) {
	oldTick, oldAge := rotateTick.get(), warmMaxAge.get()
	rotateTick.set(50 * time.Millisecond)
	warmMaxAge.set(300 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(oldTick); warmMaxAge.set(oldAge) })
	env := startEnv(t)
	c := warmClient(t, env.server)
	c.Warm(context.Background())
	first := func() *muxSession {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, s := range c.sessions {
			if !s.retired {
				return s
			}
		}
		return nil
	}
	s0 := first()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := first(); s != nil && s != s0 {
			c.mu.Lock()
			n := len(c.sessions)
			c.mu.Unlock()
			if n > 3 {
				t.Fatalf("idle client piled up %d sessions", n)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("empty session was never replaced")
}

// A new connection is only trusted once data has crossed it both ways.
func TestProbeTellsDeadConnectionFromLive(t *testing.T) {
	env := startEnv(t)
	g := startGate(t, env.server)
	c := warmClient(t, g.ln.Addr().String())
	ms, err := c.newSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	if err := ms.probe(); err != nil {
		t.Fatalf("live connection: %v", err)
	}
	g.freezeAll()
	if err := ms.probe(); err == nil {
		t.Fatal("a black-holed connection passed the probe")
	}
}

// One swallowed dial must not cost the user the full attempt timeout.
func TestSwallowedDialIsOvertaken(t *testing.T) {
	env := startEnv(t)
	var n atomic.Int32
	ln := listen(t)
	go serveEach(ln, func(c net.Conn) {
		if n.Add(1) == 1 {
			io.Copy(io.Discard, c) // accepted, then never answered
			return
		}
		up, err := net.Dial("tcp", env.server)
		if err != nil {
			c.Close()
			return
		}
		go io.Copy(up, c)
		io.Copy(c, up)
	})
	c := warmClient(t, ln.Addr().String())
	t0 := time.Now()
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	d := time.Since(t0)
	t.Logf("first round trip after %v", d.Round(10*time.Millisecond))
	if d > 5*time.Second {
		t.Fatalf("waited %v behind a swallowed dial", d)
	}
}

// A burst of new users must not queue behind one slow dial.
func TestBurstDoesNotQueueBehindDial(t *testing.T) {
	env := startEnv(t)
	g := startGate(t, env.server)
	c := warmClient(t, g.ln.Addr().String())
	first, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	g.hold.Store(true) // every new dial now hangs
	t.Cleanup(func() { g.hold.Store(false) })
	var wg sync.WaitGroup
	var slowest atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
			if err != nil {
				t.Error(err)
				return
			}
			defer st.Close()
			if d := int64(time.Since(t0)); d > slowest.Load() {
				slowest.Store(d)
			}
		}()
	}
	wg.Wait()
	d := time.Duration(slowest.Load())
	t.Logf("10 users opened; the slowest took %v", d.Round(time.Millisecond))
	if d > 2*time.Second {
		t.Fatalf("a user waited %v behind a hung dial", d)
	}
}

// stoppingGate forwards until stop is called, then stops reading altogether,
// like a real black hole: nothing gets acknowledged and buffers fill up.
type stoppingGate struct {
	ln      net.Listener
	stopped atomic.Bool
}

func startStoppingGate(t *testing.T, target string) *stoppingGate {
	t.Helper()
	g := &stoppingGate{ln: listen(t)}
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			for g.stopped.Load() {
				time.Sleep(10 * time.Millisecond)
			}
			n, err := src.Read(buf)
			for g.stopped.Load() { // a read that was in progress goes nowhere either
				time.Sleep(10 * time.Millisecond)
			}
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go serveEach(g.ln, func(c net.Conn) {
		for g.stopped.Load() {
			time.Sleep(10 * time.Millisecond)
		}
		up, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer up.Close()
		go pipe(up, c)
		pipe(c, up)
	})
	t.Cleanup(func() { g.stopped.Store(false) })
	return g
}

// A user who only downloads sends no data of their own, so nothing they sent is
// waiting to be acknowledged when the connection is black-holed.
func TestBlackholedDownloadRecovers(t *testing.T) {
	src := listen(t)
	go serveEach(src, func(c net.Conn) {
		b := make([]byte, 16<<10)
		for {
			if _, err := c.Write(b); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	env := startEnv(t)
	bad := startStoppingGate(t, env.server)
	good := startGate(t, env.server)
	c := NewClient(&config.ClientConfig{
		Server: bad.ln.Addr().String(), Servers: []string{bad.ln.Addr().String(), good.ln.Addr().String()}, AutoIP: true,
		Password: testPassword, SNI: "localhost", Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: 8, RotateSeconds: 240, RotateMB: 192},
	})
	t.Cleanup(c.Close)
	st, err := c.OpenStream(context.Background(), addrOf(t, src.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // so "go" is long since acknowledged and only silence is left
	bad.stopped.Store(true)
	var worst time.Duration
	end := time.Now().Add(25 * time.Second)
	for time.Now().Before(end) {
		t0 := time.Now()
		_ = st.SetReadDeadline(time.Now().Add(40 * time.Second))
		if _, err := st.Read(buf); err != nil {
			t.Fatalf("download did not recover: %v", err)
		}
		worst = max(worst, time.Since(t0))
	}
	t.Logf("longest gap in the download: %v", worst.Round(10*time.Millisecond))
	if worst > 12*time.Second {
		t.Fatalf("download hung for %v", worst)
	}
}

// Same black hole, for a user mostly uploading: the stuck connection's send
// buffers fill up, and nothing may wait on them.
func TestBlackholedUploadRecovers(t *testing.T) {
	sink := listen(t)
	got := new(atomic.Int64)
	go serveEach(sink, func(c net.Conn) {
		b := make([]byte, 64<<10)
		for {
			n, err := c.Read(b)
			got.Add(int64(n))
			if err != nil {
				return
			}
		}
	})
	env := startEnv(t)
	bad := startStoppingGate(t, env.server)
	good := startGate(t, env.server)
	c := NewClient(&config.ClientConfig{
		Server: bad.ln.Addr().String(), Servers: []string{bad.ln.Addr().String(), good.ln.Addr().String()}, AutoIP: true,
		Password: testPassword, SNI: "localhost", Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: 8, RotateSeconds: 240, RotateMB: 192},
	})
	t.Cleanup(c.Close)
	st, err := c.OpenStream(context.Background(), addrOf(t, sink.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	go func() {
		b := make([]byte, 16<<10)
		for {
			if _, err := st.Write(b); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	time.Sleep(time.Second)
	bad.stopped.Store(true)
	stoppedAt := time.Now()
	last := got.Load()
	lastAt := stoppedAt
	var worst time.Duration
	for time.Since(stoppedAt) < 25*time.Second {
		time.Sleep(20 * time.Millisecond)
		if n := got.Load(); n != last {
			worst = max(worst, time.Since(lastAt))
			last, lastAt = n, time.Now()
		}
	}
	worst = max(worst, time.Since(lastAt))
	t.Logf("longest gap in the upload: %v", worst.Round(10*time.Millisecond))
	if worst > 12*time.Second {
		t.Fatalf("upload hung for %v", worst)
	}
}

// A connection that is merely idle must be left alone: it answers, it stays.
func TestIdleStreamIsNotMoved(t *testing.T) {
	env := startEnv(t)
	c := warmClient(t, env.server)
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	c.mu.Lock()
	first := c.streams[st.(*rstream.Stream)].sess
	c.mu.Unlock()
	time.Sleep(12 * time.Second)
	c.mu.Lock()
	now, retired := c.streams[st.(*rstream.Stream)].sess, first.retired
	c.mu.Unlock()
	if now != first || retired {
		t.Fatal("an idle connection that still answers was replaced")
	}
	roundTrip(t, st)
}
