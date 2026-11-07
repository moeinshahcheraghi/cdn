package transport

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestFakeFrame(t *testing.T) {
	if got := checksum([]byte{0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7}); got != 0x220d {
		t.Fatalf("RFC 1071 checksum vector: %x", got)
	}
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443}
	frame := make([]byte, 54)
	binary.BigEndian.PutUint16(frame[12:14], 0x800)
	ip := frame[14:]
	ip[0], ip[9], ip[8] = 0x45, 6, 64
	binary.BigEndian.PutUint16(ip[2:4], 40)
	copy(ip[12:16], local.IP.To4())
	copy(ip[16:20], remote.IP.To4())
	tcp := ip[20:]
	tcp[12], tcp[13] = 0x50, 0x10
	binary.BigEndian.PutUint16(tcp[:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 10)
	binary.BigEndian.PutUint32(tcp[8:12], 999)
	payload := bytes.Repeat([]byte{23}, 101) // odd length checks checksum padding and sequence wrap
	original := append([]byte(nil), frame...)
	got := fakeFrame(frame, local, remote, payload)
	if len(got) != 155 || !bytes.Equal(got[54:], payload) {
		t.Fatal("incorrect payload")
	}
	if !bytes.Equal(frame, original) {
		t.Fatal("template mutated")
	}
	ip = got[14:]
	tcp = ip[20:]
	if checksum(ip[:20]) != 0 {
		t.Fatal("invalid IPv4 checksum")
	}
	pseudo := append([]byte(nil), ip[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, byte(len(tcp)))
	if checksum(append(pseudo, tcp...)) != 0 {
		t.Fatal("invalid TCP checksum")
	}
	if binary.BigEndian.Uint32(tcp[4:8])+uint32(len(payload)) != 10 || binary.BigEndian.Uint32(tcp[8:12]) != 999 {
		t.Fatal("incorrect sequence range or ACK")
	}
	if tcp[13] != 0x18 || int(binary.BigEndian.Uint16(ip[2:4])) != len(ip) {
		t.Fatal("incorrect header")
	}
	wrong := *remote
	wrong.Port = 8443
	if fakeFrame(frame, local, &wrong, payload) != nil {
		t.Fatal("matched different connection")
	}
	for n := 0; n < len(frame); n++ {
		if fakeFrame(frame[:n], local, remote, payload) != nil {
			t.Fatal("accepted truncated frame")
		}
	}
	frame[47] = 0x12
	if fakeFrame(frame, local, remote, payload) != nil {
		t.Fatal("accepted SYN ACK")
	}
}
