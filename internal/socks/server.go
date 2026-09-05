package socks

import (
	"bufio"
	"fmt"
	"net"
)

// Accept negotiates one inbound connection, auto-detecting SOCKS5 versus HTTP
// by the first byte (SOCKS5 always starts with 0x05). One local port can thus
// serve both a SOCKS5 and an HTTP proxy simultaneously.
func Accept(c net.Conn) (Request, error) {
	br := bufio.NewReaderSize(c, 4096)
	first, err := br.Peek(1)
	if err != nil {
		return Request{}, err
	}
	if first[0] == 0x05 {
		target, err := handshakeSocks5(c, br)
		if err != nil {
			return Request{}, err
		}
		return Request{Target: target, Conn: withReadPrefix(c, br, nil)}, nil
	}
	if isHTTPMethodStart(first[0]) {
		target, conn, err := handshakeHTTP(c, br)
		if err != nil {
			return Request{}, err
		}
		return Request{Target: target, Conn: conn}, nil
	}
	return Request{}, fmt.Errorf("socks: unrecognized inbound (0x%02x)", first[0])
}

// isHTTPMethodStart reports whether b could begin an HTTP method token, used to
// reject obvious garbage before attempting a full HTTP parse.
func isHTTPMethodStart(b byte) bool {
	return (b >= 'A' && b <= 'Z')
}
