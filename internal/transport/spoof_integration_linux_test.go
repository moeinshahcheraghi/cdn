package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Explicitly enabled because raw socket creation requires CAP_NET_RAW. All
// traffic is loopback: no external host, routing or firewall changes are used.
func TestNativeFakeSNILoopback(t *testing.T) {
	if os.Getenv("TUNNEL_RAW_TEST") != "1" {
		t.Skip("set TUNNEL_RAW_TEST=1 with CAP_NET_RAW for the loopback injection test")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.Copy(c, c)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialWithFakeSNI(ctx, &net.Dialer{}, ln.Addr().String(), "chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("real-stream-after-fake-hello"), 4096)
	wrote := make(chan error, 1)
	go func() { _, err := c.Write(payload); wrote <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fake bytes reached the application or real stream was corrupted")
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
