package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"golang.org/x/crypto/cryptobyte"
	"io"
	"net"
	"testing"
	"time"
)

// Inspect the emitted outer ClientHello. This does not test live CDN acceptance.
func TestDPILabECHOuterHello(t *testing.T) {
	list, err := ParseECHList(cfECH)
	if err != nil {
		t.Fatal(err)
	}
	client, observer := net.Pipe()
	defer client.Close()
	defer observer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := tlsHandshake(ctx, client, &Endpoint{SNI: "private.example", ECH: NewECH(list)}, "firefox")
		done <- err
	}()
	observer.SetReadDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(observer, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(observer, body); err != nil {
		t.Fatal(err)
	}
	observer.Close()
	<-done
	wire := append(header, body...)
	outer := observedSNI(wire)
	if outer != "cloudflare-ech.com" || bytes.Contains(wire, []byte("private.example")) {
		t.Fatalf("inner name exposed or wrong outer SNI: %q", outer)
	}
	t.Logf("emitted ECH ClientHello exposes %q; private.example absent; live ECH acceptance and DNS privacy untested", outer)
}

// Lab model: a first-packet inspector versus a TCP-aware observer. This is
// a deliberately limited model, not an implementation of an ISP's classifier.
func observedSNI(records []byte) string {
	var handshake []byte
	for len(records) >= 5 {
		n := int(binary.BigEndian.Uint16(records[3:5]))
		if records[0] != 22 || n > len(records)-5 {
			return ""
		}
		handshake = append(handshake, records[5:5+n]...)
		records = records[5+n:]
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return ""
	}
	s := cryptobyte.String(handshake[4:])
	var session, ciphers, compression, extensions cryptobyte.String
	if !s.Skip(34) || !s.ReadUint8LengthPrefixed(&session) || !s.ReadUint16LengthPrefixed(&ciphers) || !s.ReadUint8LengthPrefixed(&compression) || !s.ReadUint16LengthPrefixed(&extensions) {
		return ""
	}
	for !extensions.Empty() {
		var kind uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&data) {
			return ""
		}
		if kind != 0 {
			continue
		}
		var names, name cryptobyte.String
		var typ uint8
		if data.ReadUint16LengthPrefixed(&names) && names.ReadUint8(&typ) && typ == 0 && names.ReadUint16LengthPrefixed(&name) {
			return string(name)
		}
	}
	return ""
}

func TestDPILabFakeSNIDoesNotHideRealName(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 20830}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443}
	ack := make([]byte, 54)
	binary.BigEndian.PutUint16(ack[12:14], 0x800)
	ip := ack[14:]
	ip[0], ip[9] = 0x45, 6
	binary.BigEndian.PutUint16(ip[2:4], 40)
	copy(ip[12:16], local.IP.To4())
	copy(ip[16:20], remote.IP.To4())
	tcp := ip[20:]
	tcp[12], tcp[13] = 0x50, 0x10
	binary.BigEndian.PutUint16(tcp[:2], uint16(local.Port))
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	const next = 10000
	binary.BigEndian.PutUint32(tcp[4:8], next)
	fake := clientHello(t, "firefox", "chatgpt.com")
	real := clientHello(t, "firefox", "cdn.example")
	packet := fakeFrame(ack, local, remote, fake)
	if len(packet) == 0 {
		t.Fatal("no fake packet constructed")
	}
	naive := observedSNI(packet[54:])
	seq := binary.BigEndian.Uint32(packet[38:42])
	// The whole fake segment ends at the expected receive offset. A receiver
	// or an observer following TCP sequence space discards it as old data.
	if seq+uint32(len(packet)-54) != next {
		t.Fatal("fake packet overlaps accepted sequence space")
	}
	stateful := observedSNI(real)
	if naive != "chatgpt.com" || stateful != "cdn.example" {
		t.Fatalf("naive=%q stateful=%q", naive, stateful)
	}
	t.Logf("first-ClientHello policy sees %q; TCP-aware policy discards old segment and sees %q; conflicting ClientHellos are observable", naive, stateful)
}

func TestDPILabFragmentationReassembly(t *testing.T) {
	for _, records := range []bool{false, true} {
		hello := clientHello(t, "firefox", "cdn.example")
		f := &Fragment{Records: records, MinSize: 10, MaxSize: 40}
		pieces := f.split(hello, "cdn.example")
		var stream []byte
		for _, p := range pieces {
			stream = append(stream, p...)
		}
		if got := observedSNI(stream); got != "cdn.example" {
			t.Fatalf("records=%v SNI=%q", records, got)
		}
		t.Logf("records=%v pieces=%d: TCP/TLS reassembly recovers cdn.example", records, len(pieces))
	}
}
