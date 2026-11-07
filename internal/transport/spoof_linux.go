package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/unix"
)

// dialWithFakeSNI captures this connection's initial ACK before TLS writes
// anything, then injects a ClientHello entirely below the TCP receive offset.
// The real TLS handshake and certificate verification are unchanged. This is
// an experimental middlebox compatibility technique, not an access guarantee.
func dialWithFakeSNI(ctx context.Context, d *net.Dialer, address, name string) (net.Conn, error) {
	if name == "" {
		return d.DialContext(ctx, "tcp", address)
	}
	if len(name) > 253 || net.ParseIP(name) != nil {
		return nil, fmt.Errorf("fake_sni must be a DNS hostname")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, fmt.Errorf("invalid fake_sni hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return nil, fmt.Errorf("invalid fake_sni hostname")
			}
		}
	}
	// AF_PACKET uses network byte order for its protocol argument.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("fake_sni needs Linux CAP_NET_RAW: %w", err)
	}
	defer unix.Close(fd)
	raw, err := d.DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	local, remote := raw.LocalAddr().(*net.TCPAddr), raw.RemoteAddr().(*net.TCPAddr)
	a, b := net.Pipe()
	u := utls.UClient(a, &utls.Config{ServerName: name}, utls.HelloFirefox_Auto)
	err = u.BuildHandshakeState()
	a.Close()
	b.Close()
	if err != nil {
		return nil, fmt.Errorf("fake ClientHello: %w", err)
	}
	hello := u.HandshakeState.Hello.Raw
	payload := append([]byte{22, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 50); err != nil && err != unix.EINTR {
			return nil, err
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		link, valid := from.(*unix.SockaddrLinklayer)
		if !valid || link.Pkttype != unix.PACKET_OUTGOING {
			continue
		}
		frame := fakeFrame(buf[:n], local, remote, payload)
		if frame == nil {
			continue
		}
		if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: link.Ifindex, Protocol: htons(unix.ETH_P_IP)}); err != nil {
			return nil, fmt.Errorf("inject fake ClientHello: %w", err)
		}
		ok = true
		return raw, nil
	}
	return nil, fmt.Errorf("fake_sni: initial Ethernet/IPv4 TCP ACK not captured; no TLS data sent")
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return ^uint16(sum)
}

// fakeFrame accepts only an empty outbound ACK belonging to the exact tuple.
// Preserve TCP options and Ethernet routing, replace lengths and checksums.
func fakeFrame(frame []byte, local, remote *net.TCPAddr, payload []byte) []byte {
	if len(frame) < 54 || binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
		return nil
	}
	ip := frame[14:]
	ihl := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return nil
	}
	if !bytes.Equal(ip[12:16], local.IP.To4()) || !bytes.Equal(ip[16:20], remote.IP.To4()) {
		return nil
	}
	tcp := ip[ihl:]
	thl := int(tcp[12]>>4) * 4
	if thl < 20 || len(tcp) < thl || tcp[13] != 0x10 || int(binary.BigEndian.Uint16(ip[2:4])) != ihl+thl {
		return nil
	}
	if int(binary.BigEndian.Uint16(tcp[:2])) != local.Port || int(binary.BigEndian.Uint16(tcp[2:4])) != remote.Port {
		return nil
	}
	if ihl+thl+len(payload) > 65535 {
		return nil
	}
	out := append([]byte(nil), frame[:14+ihl+thl]...)
	out = append(out, payload...)
	ip = out[14:]
	tcp = ip[ihl:]
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:ihl]))
	binary.BigEndian.PutUint32(tcp[4:8], binary.BigEndian.Uint32(tcp[4:8])-uint32(len(payload)))
	tcp[13] = 0x18
	tcp[16], tcp[17] = 0, 0
	pseudo := append([]byte(nil), ip[12:20]...)
	pseudo = append(pseudo, 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return out
}
