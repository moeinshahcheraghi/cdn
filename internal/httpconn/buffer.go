package httpconn

import (
	"io"
	"os"
	"sync"
	"time"
)

// buffer is a bounded in-memory byte queue between one producer and one
// consumer, with deadlines on both sides. It is what turns HTTP requests and
// responses back into a plain bidirectional byte stream.
type buffer struct {
	mu      sync.Mutex
	data    []byte
	limit   int   // Write blocks while this many bytes are queued
	eof     bool  // producer finished: reads drain, then io.EOF
	err     error // hard close: every call fails with err
	rdl     time.Time
	wdl     time.Time
	changed chan struct{} // closed and replaced on every state change
}

func newBuffer(limit int) *buffer {
	return &buffer{limit: limit, changed: make(chan struct{})}
}

// notify wakes every waiter; callers hold b.mu.
func (b *buffer) notify() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// wait releases b.mu until the state changes or deadline passes, and
// reports whether the deadline passed. Callers hold b.mu.
func (b *buffer) wait(deadline time.Time) bool {
	ch := b.changed
	b.mu.Unlock()
	defer b.mu.Lock()
	if deadline.IsZero() {
		<-ch
		return false
	}
	d := time.Until(deadline)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return false
	case <-t.C:
		return true
	}
}

// Write queues all of p, blocking while the buffer is full.
func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		switch {
		case b.err != nil:
			return 0, b.err
		case b.eof:
			return 0, io.ErrClosedPipe
		case len(b.data) < b.limit:
			b.data = append(b.data, p...)
			b.notify()
			return len(p), nil
		}
		if b.wait(b.wdl) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Read copies queued bytes into p, blocking until there are some.
func (b *buffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		switch {
		case len(b.data) > 0 && b.err == nil:
			n := copy(p, b.data)
			b.consume(n)
			return n, nil
		case b.err != nil:
			return 0, b.err
		case b.eof:
			return 0, io.EOF
		}
		if b.wait(b.rdl) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Next removes and returns up to max queued bytes, blocking until there are
// some. It is the batching read: whatever piled up while the previous batch
// was in flight goes out together.
func (b *buffer) Next(max int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		switch {
		case len(b.data) > 0 && b.err == nil:
			n := min(len(b.data), max)
			out := append([]byte(nil), b.data[:n]...)
			b.consume(n)
			return out, nil
		case b.err != nil:
			return nil, b.err
		case b.eof:
			return nil, io.EOF
		}
		b.wait(time.Time{})
	}
}

// consume drops the first n bytes; callers hold b.mu.
func (b *buffer) consume(n int) {
	b.data = b.data[n:]
	if len(b.data) == 0 {
		b.data = b.data[:0:0] // let a large backing array go
	}
	b.notify()
}

// CloseWrite marks the end of the stream after what is already queued.
func (b *buffer) CloseWrite() {
	b.mu.Lock()
	b.eof = true
	b.notify()
	b.mu.Unlock()
}

// Close fails every pending and future call with err.
func (b *buffer) Close(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
		b.data = nil
		b.notify()
	}
	b.mu.Unlock()
}

func (b *buffer) SetReadDeadline(t time.Time) {
	b.mu.Lock()
	b.rdl = t
	b.notify()
	b.mu.Unlock()
}

func (b *buffer) SetWriteDeadline(t time.Time) {
	b.mu.Lock()
	b.wdl = t
	b.notify()
	b.mu.Unlock()
}
