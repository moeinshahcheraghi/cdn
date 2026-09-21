package wsconn

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"testing"
)

// pair returns a connected client and server WebSocket over loopback TCP.
func pair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srvCh := make(chan *Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			errCh <- err
			return
		}
		if !IsUpgrade(req) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		ws, err := Accept(c, br, req)
		if err != nil {
			errCh <- err
			return
		}
		srvCh <- ws
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := Dial(cc, "example.com", "/secret-path")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-srvCh:
		return client, s
	case err := <-errCh:
		t.Fatal(err)
	}
	return nil, nil
}

// Data must survive in both directions at every frame-length encoding, and
// the client's frames must be masked as RFC 6455 requires (a CDN rejects
// unmasked client frames).
func TestRoundTrip(t *testing.T) {
	client, server := pair(t)
	for _, size := range []int{1, 125, 126, 1000, 0xffff, 0x10000, 300000} {
		payload := make([]byte, size)
		rand.Read(payload)
		go func() {
			if _, err := client.Write(payload); err != nil {
				t.Errorf("write %d: %v", size, err)
			}
		}()
		got := make([]byte, size)
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("read %d: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: payload mismatch", size)
		}
		go func() {
			if _, err := server.Write(payload); err != nil {
				t.Errorf("server write %d: %v", size, err)
			}
		}()
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("client read %d: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: reverse payload mismatch", size)
		}
	}
}

func TestClientMasksAndServerDoesNot(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	client := &Conn{Conn: a, br: bufio.NewReader(a), client: true}
	go client.Write([]byte("hello"))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != 0x82 {
		t.Fatalf("opcode %#x, want a final binary frame", hdr[0])
	}
	if hdr[1]&0x80 == 0 {
		t.Fatal("client frame is not masked; a CDN would drop the connection")
	}
	if _, err := io.CopyN(io.Discard, b, 4+5); err != nil { // mask + payload
		t.Fatal(err)
	}
	srv := &Conn{Conn: a, br: bufio.NewReader(a)}
	go srv.Write([]byte("hello"))
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1]&0x80 != 0 {
		t.Fatal("server frame must not be masked")
	}
}

// A ping in the middle of a stream (CDNs send them) must be answered with a
// pong and must not disturb the data.
func TestPingIsAnsweredTransparently(t *testing.T) {
	client, server := pair(t)
	if err := server.writeFrame(opPing, []byte("are you there")); err != nil {
		t.Fatal(err)
	}
	go server.Write([]byte("payload"))
	got := make([]byte, 7)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Fatalf("got %q", got)
	}
	// The pong comes back as a control frame the server's Read skips over.
	go client.Write([]byte("more"))
	got = make([]byte, 4)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "more" {
		t.Fatalf("got %q", got)
	}
}

func TestRejectsWrongUpgrade(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
		c.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := Dial(c, "example.com", "/nope"); err == nil {
		t.Fatal("a 404 was accepted as a websocket")
	}
}
