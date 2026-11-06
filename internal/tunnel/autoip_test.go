package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/transport"
)

// fastAuto shortens the timers so a test takes seconds. The logic is the same.
func fastAuto(t *testing.T) {
	t.Helper()
	type setting struct {
		v *tunable
		d time.Duration
	}
	for _, s := range []setting{
		{stallTimeout, 1500 * time.Millisecond},
		{rotateTick, 100 * time.Millisecond},
		{autoEvalGap, 300 * time.Millisecond},
		{autoMaxEvalGap, 2 * time.Second},
		{autoConfirmGap, 100 * time.Millisecond},
		{autoTestTimeout, 1500 * time.Millisecond},
		{warmMaxAge, 2 * time.Second},
	} {
		old := s.v.get()
		s.v.set(s.d)
		t.Cleanup(func() { s.v.set(old) })
	}
}

func autoClient(t *testing.T, pool int, gates ...*gate) *Client {
	t.Helper()
	var servers []string
	for _, g := range gates {
		servers = append(servers, g.ln.Addr().String())
	}
	c := NewClient(&config.ClientConfig{
		Server: servers[0], Servers: servers, AutoIP: true,
		Password: testPassword, SNI: "localhost", Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: pool, RotateSeconds: 240, RotateMB: 192},
	})
	t.Cleanup(c.Close)
	return c
}

// kill makes an address go dark: open connections fall silent, new ones hang.
func (g *gate) kill(t *testing.T) {
	g.hold.Store(true)
	t.Cleanup(func() { g.hold.Store(false) })
	g.freezeAll()
}

func (g *gate) conns() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.open)
}

func activeOn(c *Client, g *gate) bool {
	return c.dialer.Active().Server == g.ln.Addr().String()
}

func waitActive(t *testing.T, c *Client, g *gate, within time.Duration) time.Duration {
	t.Helper()
	t0 := time.Now()
	for time.Since(t0) < within {
		if activeOn(c, g) {
			return time.Since(t0)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("still on %s after %v", c.dialer.Active().Server, within)
	return 0
}

// When the address dies, new connections must move, and a user already on it
// must carry on with the same stream.
func TestAutoIPMovesOffDeadAddress(t *testing.T) {
	fastAuto(t)
	env := startEnv(t)
	a, b := startGate(t, env.server), startGate(t, env.server)
	c := autoClient(t, 8, a, b)
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)

	a.kill(t)
	go func() {
		// A stall is what normally brings the problem to light.
		for i := 0; i < 400; i++ {
			if _, err := st.Write(make([]byte, 100)); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	d := waitActive(t, c, b, 20*time.Second)
	t.Logf("moved to the working address after %v", d.Round(10*time.Millisecond))

	before := b.conns()
	st2, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	roundTrip(t, st2)
	if b.conns() < before {
		t.Fatal("new stream did not use the new address")
	}

	// The old user's stream is still the same one, and it still works.
	t0 := time.Now()
	buf := make([]byte, 100)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("the user who was on the dead address lost their stream: %v", err)
	}
	t.Logf("old stream answered %v after the switch", time.Since(t0).Round(10*time.Millisecond))
}

// Many users on an address that dies mid-transfer: nobody may lose a byte.
func TestAutoIPUsersSurviveSwitch(t *testing.T) {
	fastAuto(t)
	env := startEnv(t)
	a, b := startGate(t, env.server), startGate(t, env.server)
	c := autoClient(t, 8, a, b)
	// Paced so the address dies with every user still in mid-transfer.
	usersPaced(t, c, env.echo, 200, 1<<20, 300*time.Millisecond, func() { a.kill(t) })
	waitActive(t, c, b, 20*time.Second)
}

// One flow being cut is not a problem with the address.
func TestAutoIPIgnoresOneCutFlow(t *testing.T) {
	fastAuto(t)
	env := startEnv(t)
	a, b := startGate(t, env.server), startGate(t, env.server)
	c := autoClient(t, 8, a, b)
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	a.freezeFirst(t)
	roundTrip(t, st) // stalls, moves, answers
	time.Sleep(5 * time.Second)
	if !activeOn(c, a) {
		t.Fatal("switched address because one flow was cut")
	}
}

// When every address fails the problem is not the address: stay, keep trying,
// and do not hammer anything meanwhile.
func TestAutoIPStaysWhenAllAreDown(t *testing.T) {
	fastAuto(t)
	env := startEnv(t)
	a, b := startGate(t, env.server), startGate(t, env.server)
	c := autoClient(t, 8, a, b)
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	a.kill(t)
	b.kill(t)
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := st.Write(make([]byte, 100)); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	time.Sleep(8 * time.Second)
	if !activeOn(c, a) {
		t.Fatal("switched to an address that does not work either")
	}
	// Everything comes back: the user carries on by themselves.
	a.hold.Store(false)
	b.hold.Store(false)
	buf := make([]byte, 100)
	_ = st.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("stream did not recover: %v", err)
	}
}

// Addresses can take turns failing; the second switch must not be held back.
func TestAutoIPMovesAgainWhenTheNewOneDies(t *testing.T) {
	fastAuto(t)
	env := startEnv(t)
	a, b := startGate(t, env.server), startGate(t, env.server)
	c := autoClient(t, 8, a, b)
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := st.Write(make([]byte, 100)); err != nil {
				return
			}
		}
	}()
	a.kill(t)
	waitActive(t, c, b, 20*time.Second)
	a.hold.Store(false)
	b.kill(t)
	waitActive(t, c, a, 20*time.Second)
}

// A full link is not a broken address, however many users are queueing on it.
func TestAutoIPStaysPutOnBusyLink(t *testing.T) {
	env := startEnv(t)
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
	const rate = 400 << 10
	var dials atomic.Int64
	limited := func() string {
		ln := listen(t)
		go serveEach(ln, func(c net.Conn) {
			dials.Add(1)
			u, err := net.Dial("tcp", env.server)
			if err != nil {
				return
			}
			defer u.Close()
			go io.Copy(u, c)
			b := make([]byte, 4<<10)
			for {
				n, err := u.Read(b)
				if n > 0 {
					time.Sleep(time.Duration(n) * time.Second / rate)
					if _, werr := c.Write(b[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		})
		return ln.Addr().String()
	}
	x, y := limited(), limited()
	c := NewClient(&config.ClientConfig{
		Server: x, Servers: []string{x, y}, AutoIP: true,
		Password: testPassword, SNI: "localhost", Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 32, Pool: 4},
	})
	t.Cleanup(c.Close)
	stop := make(chan struct{})
	var lost atomic.Int64
	for i := 0; i < 40; i++ {
		st, err := c.OpenStream(context.Background(), addrOf(t, src.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		go func() {
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
	time.Sleep(25 * time.Second)
	close(stop)
	if c.dialer.Active().Server != x {
		t.Error("switched address on a link that was only busy")
	}
	if n := lost.Load(); n > 0 {
		t.Errorf("%d users lost their stream", n)
	}
	t.Logf("%d connections dialled in 25 s", dials.Load())
	if dials.Load() > 12 { // pool of 4, ready connection, one startup test per address
		t.Errorf("%d connections dialled: too much churn", dials.Load())
	}
}

// With nothing wrong, testing must cost next to nothing.
func TestAutoIPIdleCostsAlmostNothing(t *testing.T) {
	env := startEnv(t)
	a, b, cc := startGate(t, env.server), startGate(t, env.server), startGate(t, env.server)
	c := autoClient(t, 8, a, b, cc)
	st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roundTrip(t, st)
	time.Sleep(3 * time.Second)
	counted := func() int { return b.conns() + cc.conns() }
	base := counted()
	if base > 2 { // the one test each got at startup
		t.Fatalf("%d test connections to the other addresses at startup", base)
	}
	time.Sleep(10 * time.Second)
	if n := counted() - base; n > 0 {
		t.Fatalf("%d more test connections while nothing was wrong", n)
	}
	if !activeOn(c, a) {
		t.Fatal("moved without cause")
	}
}

// Off by default: no sticky address, exactly the old behaviour.
func TestAutoIPOffByDefault(t *testing.T) {
	env := startEnv(t)
	c := NewClient(&config.ClientConfig{
		Server: env.server, Servers: []string{env.server, env.server},
		Password: testPassword, SNI: "localhost", Fingerprint: "firefox", AllowInsecure: true,
		Mux: config.MuxConfig{Enabled: true, Concurrency: 4, Pool: 2},
	})
	t.Cleanup(c.Close)
	if c.dialer.Active() != nil || c.auto != nil {
		t.Fatal("auto ip on without being asked for")
	}
}

func TestAutoIPDecide(t *testing.T) {
	ep := &transport.Endpoint{}
	ok := func(ms int) testResult { return testResult{ep: ep, took: time.Duration(ms) * time.Millisecond} }
	bad := testResult{ep: ep, err: errors.New("x")}
	for _, tc := range []struct {
		name               string
		first, again, best testResult
		found, heavy, held bool
		want               verdict
	}{
		{"all fine", ok(300), ok(300), ok(100), true, false, false, keep},
		{"failing, elsewhere works", bad, bad, ok(300), true, false, false, switchFailing},
		{"failing, elsewhere works, held", bad, bad, ok(300), true, true, true, switchFailing},
		{"failing, nowhere to go", bad, bad, testResult{}, false, true, false, keep},
		{"one failure only", bad, ok(300), ok(300), true, false, false, keep},
		{"second failure only", ok(300), bad, ok(300), true, false, false, keep},
		{"stalling, other as good", ok(300), ok(300), ok(350), true, true, false, switchStalling},
		{"stalling, other far slower", ok(300), ok(300), ok(900), true, true, false, keep},
		{"stalling, held", ok(300), ok(300), ok(300), true, true, true, keep},
		{"stalling, nowhere to go", ok(300), ok(300), testResult{}, false, true, false, keep},
	} {
		if got := decide(tc.first, tc.again, tc.best, tc.found, tc.heavy, tc.held); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
