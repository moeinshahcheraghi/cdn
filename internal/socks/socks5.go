package socks

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/moeinshah0/tunnel/internal/protocol"
)

// handshakeSocks5 performs the SOCKS5 greeting and CONNECT request on c and
// returns the requested target. Only no-auth CONNECT is offered, which every
// browser and system proxy client supports.
func handshakeSocks5(c net.Conn, br *bufio.Reader) (protocol.Address, error) {

	// Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return protocol.Address{}, err
	}
	if hdr[0] != 0x05 {
		return protocol.Address{}, fmt.Errorf("socks5: bad version 0x%02x", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return protocol.Address{}, err
	}
	// Reply: VER=5, METHOD=0 (no auth).
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return protocol.Address{}, err
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return protocol.Address{}, err
	}
	if req[0] != 0x05 {
		return protocol.Address{}, fmt.Errorf("socks5: bad request version")
	}
	if req[1] != 0x01 { // CONNECT only
		replySocks5(c, 0x07)
		return protocol.Address{}, fmt.Errorf("socks5: unsupported command 0x%02x", req[1])
	}

	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return protocol.Address{}, err
		}
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return protocol.Address{}, err
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return protocol.Address{}, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(br, b); err != nil {
			return protocol.Address{}, err
		}
		host = string(b)
	default:
		replySocks5(c, 0x08)
		return protocol.Address{}, fmt.Errorf("socks5: bad atyp")
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return protocol.Address{}, err
	}
	port := int(binary.BigEndian.Uint16(pb[:]))

	// Success reply with a zero BND.ADDR; clients ignore it for CONNECT.
	replySocks5(c, 0x00)
	return protocol.NewAddress(host, port), nil
}

// replySocks5 sends a minimal reply with the given status code.
func replySocks5(c net.Conn, status byte) {
	_, _ = c.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
