package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

type probeResult struct{ sent, received int64 }

type countWriter struct {
	dst io.Writer
	n   *atomic.Int64
}

func (w countWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.n.Add(int64(n))
	return n, err
}

// probeEcho requires an explicitly selected, operator-controlled TCP echo
// service. Read and write concurrently to exercise transfers above flow-control
// windows without deadlocking on the returning data. Counters measure locally
// accepted and returned bytes; only matching hashes establish a successful probe.
func probeEcho(ctx context.Context, conn net.Conn, size int64) (probeResult, error) {
	defer conn.Close()
	if size <= 0 {
		return probeResult{}, fmt.Errorf("probe size must be positive")
	}
	var sent, received atomic.Int64
	snapshot := func() probeResult { return probeResult{sent.Load(), received.Load()} }
	type outcome struct {
		sum []byte
		err error
	}
	written, read := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		h := sha256.New()
		_, err := io.CopyN(io.MultiWriter(countWriter{conn, &sent}, h), rand.Reader, size)
		written <- outcome{h.Sum(nil), err}
	}()
	go func() {
		h := sha256.New()
		_, err := io.CopyN(io.MultiWriter(countWriter{io.Discard, &received}, h), conn, size)
		read <- outcome{h.Sum(nil), err}
	}()
	var tx, rx []byte
	for written != nil || read != nil {
		select {
		case <-ctx.Done():
			return snapshot(), ctx.Err()
		case result := <-written:
			if result.err != nil {
				return snapshot(), fmt.Errorf("send: %w", result.err)
			}
			tx, written = result.sum, nil
		case result := <-read:
			if result.err != nil {
				return snapshot(), fmt.Errorf("receive: %w", result.err)
			}
			rx, read = result.sum, nil
		}
	}
	if !bytes.Equal(tx, rx) {
		return snapshot(), fmt.Errorf("echoed payload differs from sent payload")
	}
	return snapshot(), nil
}
