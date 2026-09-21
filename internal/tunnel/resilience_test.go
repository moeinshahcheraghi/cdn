package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/logx"
)

// netProxy forwards TCP to a target and can do to a flow what a censor does
// to one it dislikes: reset it, or silently swallow it while leaving it up.
// New connections through the proxy are unaffected, as on a real network
// where the next connection is judged afresh.
type netProxy struct {
	ln     net.Listener
	target string

	mu    sync.Mutex
	live  []net.Conn
	froze []*atomic.Bool
	deaf  atomic.Bool
	dials atomic.Int32
}

func startProxy(t *testing.T, target string) *netProxy {
	t.Helper()
	p := &netProxy{ln: listen(t), target: target}
	go func() {
		for {
			c, err := p.ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *netProxy) addr() string { return p.ln.Addr().String() }

func (p *netProxy) serve(c net.Conn) {
	if p.deaf.Load() {
		// Accepted, then nothing: the TCP connection comes up and everything
		// sent into it disappears, which is what a new connection looks like
		// once a censor has decided to swallow this route.
		p.mu.Lock()
		p.live = append(p.live, c)
		p.mu.Unlock()
		io.Copy(io.Discard, c)
		c.Close()
		return
	}
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		c.Close()
		return
	}
	p.dials.Add(1)
	frozen := new(atomic.Bool)
	p.mu.Lock()
	p.live = append(p.live, c, up)
	p.froze = append(p.froze, frozen)
	p.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.pipe(up, c, frozen) }()
	go func() { defer wg.Done(); p.pipe(c, up, frozen) }()
	wg.Wait()
	c.Close()
	up.Close()
}

// pipe copies until the connection ends, dropping everything once frozen:
// the sender's TCP keeps accepting data that never arrives.
func (p *netProxy) pipe(dst, src net.Conn, frozen *atomic.Bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 && !frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// cut resets every connection currently open through the proxy.
func (p *netProxy) cut() {
	p.mu.Lock()
	live := p.live
	p.live, p.froze = nil, nil
	p.mu.Unlock()
	for _, c := range live {
		c.Close()
	}
}

// deafen makes every connection opened from now on go nowhere, while the
// ones already up keep working.
func (p *netProxy) deafen() { p.deaf.Store(true) }

// blackhole silently swallows every connection currently open.
func (p *netProxy) blackhole() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.froze {
		f.Store(true)
	}
	p.froze = nil
}

// users runs n concurrent long streams through c, each echoing size bytes,
// and reports a failure unless every one of them comes back byte-perfect.
func users(t *testing.T, c *Client, target string, n, size int, disrupt func()) {
	usersPaced(t, c, target, n, size, 5*time.Millisecond, disrupt)
}

// usersPaced is users with an explicit gap between writes, so a test can
// keep streams running for as long as it needs.
func usersPaced(t *testing.T, c *Client, target string, n, size int, gap time.Duration, disrupt func()) {
	t.Helper()
	type result struct {
		ok  bool
		n   int
		err error
	}
	results := make(chan result, n)
	var started sync.WaitGroup
	started.Add(n)
	for u := 0; u < n; u++ {
		go func() {
			stream, err := c.OpenStream(context.Background(), addrOf(t, target))
			if err != nil {
				started.Done()
				results <- result{err: err}
				return
			}
			defer stream.Close()
			payload := make([]byte, size)
			rand.Read(payload)
			go func() {
				// Trickle, so the disruption lands mid-stream rather than
				// after everything is already buffered downstream.
				for off := 0; off < len(payload); off += 64 << 10 {
					end := min(off+64<<10, len(payload))
					if _, err := stream.Write(payload[off:end]); err != nil {
						return
					}
					time.Sleep(gap)
				}
				stream.(interface{ CloseWrite() error }).CloseWrite()
			}()
			started.Done()
			got, err := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
			results <- result{ok: bytes.Equal(got, payload), n: len(got), err: err}
		}()
	}
	started.Wait()
	time.Sleep(300 * time.Millisecond)
	disrupt()
	for u := 0; u < n; u++ {
		r := <-results
		if r.err != nil || !r.ok {
			t.Fatalf("user stream did not survive: got %d/%d bytes, err=%v", r.n, size, r.err)
		}
	}
}

func resilientClient(t *testing.T, server string, backup string) *Client {
	t.Helper()
	cfg := &config.ClientConfig{
		Server: server, Password: testPassword, SNI: "localhost",
		Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 4, Pool: 4, RotateSeconds: 300, RotateMB: 4096},
	}
	if backup != "" {
		cfg.Backups = []config.Backup{{Server: backup, SNI: "localhost", Fingerprint: "firefox", AllowInsecure: true}}
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)
	return c
}

// A censor (or a flaky international link) resetting the carrier must cost
// users a pause, not their session: every stream continues on a fresh
// connection from the byte the server last received.
func TestCarrierResetKeepsUsersAlive(t *testing.T) {
	old := rotateTick.get()
	rotateTick.set(200 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(old) })
	env := startEnv(t)
	proxy := startProxy(t, env.server)
	c := resilientClient(t, proxy.addr(), "")
	users(t, c, env.echo, 6, 4<<20, func() {
		for i := 0; i < 3; i++ {
			proxy.cut()
			time.Sleep(400 * time.Millisecond)
		}
	})
}

// The nastier case: the flow is not reset but throttled to nothing, which
// TCP itself would take many minutes to notice. Unacknowledged data must be
// detected and the streams moved to a new connection.
func TestBlackholedCarrierIsDetectedAndReplaced(t *testing.T) {
	oldTick, oldStall := rotateTick.get(), stallTimeout.get()
	rotateTick.set(200 * time.Millisecond)
	stallTimeout.set(1500 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(oldTick); stallTimeout.set(oldStall) })
	logx.SetLevel("debug")
	t.Cleanup(func() { logx.SetLevel("info") })

	env := startEnv(t)
	proxy := startProxy(t, env.server)
	c := resilientClient(t, proxy.addr(), "")
	users(t, c, env.echo, 4, 3<<20, proxy.blackhole)
}

// When the direct route stops working entirely, the backup route (in the
// field: a CDN) must take over without the user noticing.
func TestBackupRouteTakesOver(t *testing.T) {
	old := rotateTick.get()
	rotateTick.set(200 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(old) })
	env := startEnv(t)
	primary := startProxy(t, env.server)
	c := resilientClient(t, primary.addr(), env.server)

	stream, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	// The primary is dead from here on: its listener refuses and live
	// connections are cut.
	primary.ln.Close()
	primary.cut()

	msg := []byte("still here")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := stream.Write(msg); err != nil {
			t.Fatalf("write after primary died: %v", err)
		}
		stream.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(stream, buf); err == nil {
			if !bytes.Equal(buf, msg) {
				t.Fatalf("corrupted echo %q", buf)
			}
			return // the stream survived on the backup route
		}
		if time.Now().After(deadline) {
			t.Fatal("stream never recovered on the backup route")
		}
	}
}

// Long streams must be spread over several connections rather than piled
// onto one: on a policed international path, throughput follows the number
// of flows, and one flow's loss must not stall every user.
func TestStreamsSpreadOverConnections(t *testing.T) {
	env := startEnv(t)
	c := resilientClient(t, env.server, "")
	var streams []net.Conn
	for i := 0; i < 8; i++ {
		st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
	}
	defer func() {
		for _, st := range streams {
			st.Close()
		}
	}()
	c.mu.Lock()
	n := len(c.sessions)
	counts := make([]int, 0, n)
	for _, s := range c.sessions {
		counts = append(counts, s.NumStreams())
	}
	c.mu.Unlock()
	if n < 4 {
		t.Fatalf("8 streams landed on %d connections %v; pool is 4 and concurrency 4", n, counts)
	}
}

// A rotation whose resume cannot be completed must cost the user nothing.
// This is what the field logs showed: "resume reply: timeout" repeatedly,
// then "server does not know stream", and the user's VPN session died. The
// move is prove-then-swap, so while resumes are failing every stream keeps
// running on the connection it already has.

// A move that cannot be completed must never cost a user their connection:
// while every new connection goes nowhere, established streams have to keep
// running on the carriers they already have.
func TestFailedRotationNeverDropsUsers(t *testing.T) {
	oldTick := rotateTick.get()
	rotateTick.set(150 * time.Millisecond)
	t.Cleanup(func() { rotateTick.set(oldTick) })

	env := startEnv(t)
	proxy := startProxy(t, env.server)
	cfg := &config.ClientConfig{
		Server: proxy.addr(), Password: testPassword, SNI: "localhost",
		Fingerprint: "firefox", AllowInsecure: true,
		// Retire almost at once, so a move is attempted every tick and
		// every one of them fails once the route has gone deaf.
		Mux: config.MuxConfig{Enabled: true, Concurrency: 8, Pool: 8, RotateSeconds: 1, RotateMB: 1},
	}
	c := NewClient(cfg)
	t.Cleanup(c.Close)

	usersPaced(t, c, env.echo, 4, 6<<20, 8*time.Millisecond, proxy.deafen)
}
