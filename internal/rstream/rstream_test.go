package rstream

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a, <-ch
}

// Echo through a pair of streams while the carrier is replaced repeatedly.
func TestMigrationPreservesData(t *testing.T) {
	const size = 12 << 20
	payload := make([]byte, size)
	rand.Read(payload)

	a := New(1, 10*time.Second)
	b := New(1, 10*time.Second)
	attach := func() {
		ca, cb := tcpPair(t)
		if err := a.Attach(ca, b.RecvOffset()); err != nil {
			t.Fatal(err)
		}
		if err := b.Attach(cb, a.RecvOffset()); err != nil {
			t.Fatal(err)
		}
	}
	attach()

	// b echoes.
	go func() {
		io.Copy(b, b)
		b.CloseWrite()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.Write(payload)
		a.CloseWrite()
	}()

	// Migrate the carrier many times mid-transfer.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 40; i++ {
			select {
			case <-done:
				return
			case <-time.After(15 * time.Millisecond):
			}
			a.Detach()
			b.Detach()
			attach()
		}
	}()

	got, err := io.ReadAll(a)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("mismatch: got %d bytes, want %d", len(got), size)
	}
	a.Close()
	b.Close()
}

// A carrier that dies (not a clean detach) must be survivable too: bytes in
// flight on it are retransmitted.
func TestCarrierDeathRetransmits(t *testing.T) {
	payload := make([]byte, 3<<20)
	rand.Read(payload)
	a := New(7, 5*time.Second)
	b := New(7, 5*time.Second)
	ca, cb := tcpPair(t)
	a.Attach(ca, 0)
	b.Attach(cb, 0)
	go func() { a.Write(payload); a.CloseWrite() }()

	buf := make([]byte, 700*1024)
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatal(err)
	}
	ca.Close() // kill the carrier under a's feet; cb sees EOF
	// Wait for the condition rather than a fixed time: under the race
	// detector on a busy machine the read loops can take a while to run.
	for deadline := time.Now().Add(2 * time.Second); a.Attached() || b.Attached(); {
		if time.Now().After(deadline) {
			t.Fatal("streams should be detached after carrier death")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ca2, cb2 := tcpPair(t)
	a.Attach(ca2, b.RecvOffset())
	b.Attach(cb2, a.RecvOffset())
	rest, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(buf, rest...), payload) {
		t.Fatalf("mismatch after retransmit: %d+%d bytes", len(buf), len(rest))
	}
}

func TestResumeTimeout(t *testing.T) {
	a := New(9, 200*time.Millisecond)
	ca, _ := tcpPair(t)
	a.Attach(ca, 0)
	a.Detach()
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err != ErrResumeTimeout {
		t.Fatalf("got %v, want ErrResumeTimeout", err)
	}
}

func TestCloseDeliversTail(t *testing.T) {
	a := New(3, time.Second)
	b := New(3, time.Second)
	ca, cb := tcpPair(t)
	a.Attach(ca, 0)
	b.Attach(cb, 0)
	msg := bytes.Repeat([]byte("x"), 100000)
	a.Write(msg)
	a.Close() // must not lose the 100 KB just written
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("got %d bytes err=%v", len(got), err)
	}
}

// A reader that does not read must stop the writer after one window, across
// resumes too; nothing may buffer without bound.
func TestSlowReaderBoundsBuffers(t *testing.T) {
	a := New(1, 10*time.Second)
	b := New(1, 10*time.Second)
	defer a.Close()
	defer b.Close()
	var wrote int64
	var mu sync.Mutex
	attach := func() {
		a.Detach()
		b.Detach()
		ca, cb := tcpPair(t)
		if err := a.Attach(ca, b.RecvOffset()); err != nil {
			t.Fatalf("a: %v (a.err=%v b.err=%v)", err, a.err, b.err)
		}
		if err := b.Attach(cb, a.RecvOffset()); err != nil {
			t.Fatalf("b: %v (b.err=%v)", err, b.err)
		}
	}
	attach()
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			n, err := a.Write(chunk)
			mu.Lock()
			wrote += int64(n)
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	for i := 0; i < 3; i++ {
		time.Sleep(300 * time.Millisecond)
		attach()
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	w := wrote
	mu.Unlock()
	if w > window+64<<10 {
		t.Fatalf("writer got %d bytes past a reader that never read; window is %d", w, window)
	}
	b.mu.Lock()
	held := len(b.recvBuf)
	b.mu.Unlock()
	if held > window {
		t.Fatalf("receiver buffered %d > window", held)
	}
	// Reading releases the writer again.
	if _, err := io.CopyN(io.Discard, b, window); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	w2 := wrote
	mu.Unlock()
	if w2 <= w {
		t.Fatalf("writer did not resume after the reader consumed (%d -> %d)", w, w2)
	}
}

// blackhole accepts writes and never delivers them, like a censor dropping a
// flow's packets without resetting it.
type blackhole struct{ net.Conn }

func (blackhole) Write(p []byte) (int, error) { return len(p), nil }

func TestStalledDetectsBlackhole(t *testing.T) {
	a := New(1, 10*time.Second)
	b := New(1, 10*time.Second)
	defer a.Close()
	defer b.Close()
	ca, cb := tcpPair(t)
	a.Attach(ca, 0)
	b.Attach(cb, 0)
	go io.Copy(io.Discard, b)
	a.Write(make([]byte, 100<<10))
	time.Sleep(400 * time.Millisecond)
	if a.Stalled(200 * time.Millisecond) {
		t.Fatal("healthy idle stream reported stalled")
	}
	// Same stream, but the path now swallows everything.
	a.Detach()
	b.Detach()
	ca, cb = tcpPair(t)
	a.Attach(blackhole{ca}, b.RecvOffset())
	b.Attach(cb, a.RecvOffset())
	a.Write(make([]byte, 100<<10))
	time.Sleep(400 * time.Millisecond)
	if !a.Stalled(200 * time.Millisecond) {
		t.Fatal("black-holed stream not reported stalled")
	}
}

func TestCarrierLostCallback(t *testing.T) {
	a := New(1, 10*time.Second)
	defer a.Close()
	lost := make(chan struct{}, 1)
	a.SetOnCarrierLost(func() { lost <- struct{}{} })
	ca, cb := tcpPair(t)
	a.Attach(ca, 0)
	cb.Close()
	select {
	case <-lost:
	case <-time.After(3 * time.Second):
		t.Fatal("no carrier-lost callback")
	}
}
