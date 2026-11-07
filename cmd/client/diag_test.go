package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type corruptWriter struct{ io.Writer }

func (w corruptWriter) Write(p []byte) (int, error) {
	b := append([]byte(nil), p...)
	for i := range b {
		b[i] ^= 1
	}
	return w.Writer.Write(b)
}

func TestProbeEcho(t *testing.T) {
	for _, tc := range []struct {
		name      string
		serve     func(net.Conn)
		wantError string
	}{
		{"complete", func(c net.Conn) { io.Copy(c, c) }, ""},
		{"corrupted", func(c net.Conn) { io.Copy(corruptWriter{c}, c) }, "differs"},
		{"closed-after-64KiB", func(c net.Conn) { io.CopyN(c, c, 64<<10) }, "closed"},
		{"stalled-after-64KiB", func(c net.Conn) {
			io.CopyN(c, c, 64<<10)
			io.Copy(io.Discard, c)
		}, "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			done := make(chan struct{})
			go func() { defer close(done); defer server.Close(); tc.serve(server) }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			const size = 3 << 20 // exceeds both the reported cutoff and rstream's window
			result, err := probeEcho(ctx, client, size)
			if tc.wantError == "" {
				if err != nil || result.sent != size || result.received != size {
					t.Fatalf("result=%+v error=%v", result, err)
				}
			} else if err == nil || (tc.name != "closed-after-64KiB" && !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("got %v, expected %s (result=%+v)", err, tc.wantError, result)
			}
			if tc.name == "stalled-after-64KiB" {
				if !errors.Is(err, context.DeadlineExceeded) || result.received != 64<<10 {
					t.Fatalf("cutoff was not reported: result=%+v error=%v", result, err)
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("probe did not close its connection")
			}
		})
	}
}
