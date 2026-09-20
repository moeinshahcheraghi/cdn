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
	time.Sleep(50 * time.Millisecond)
	if a.Attached() || b.Attached() {
		t.Fatal("streams should be detached after carrier death")
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
