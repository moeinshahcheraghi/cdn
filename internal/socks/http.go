package socks

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/moeinshah0/tunnel/internal/protocol"
)

// handshakeHTTP handles an HTTP proxy connection. CONNECT is answered with a
// 200 and then relayed raw; a plain proxied request is rewritten into an
// origin-form request and replayed as the tunnel's first bytes, so the target
// web server receives an ordinary HTTP request. Only the head is rewritten;
// the body stays in the buffered reader and streams through untouched.
func handshakeHTTP(c net.Conn, br *bufio.Reader) (protocol.Address, net.Conn, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return protocol.Address{}, nil, err
	}

	if req.Method == http.MethodConnect {
		host, port, err := splitHostPort(req.Host, 443)
		if err != nil {
			return protocol.Address{}, nil, err
		}
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return protocol.Address{}, nil, err
		}
		return protocol.NewAddress(host, port), withReadPrefix(c, br, nil), nil
	}

	host, port, err := splitHostPort(req.Host, 80)
	if err != nil {
		return protocol.Address{}, nil, err
	}
	uri := "/"
	if req.URL != nil {
		if u := req.URL.RequestURI(); u != "" {
			uri = u
		}
	}
	// Proxy-* headers are for us, not the origin. Connection: close makes the
	// origin end the connection after one response, so a browser cannot reuse
	// this proxy connection for a different host (we relay raw after this).
	for k := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "proxy-") {
			delete(req.Header, k)
		}
	}
	req.Header.Set("Connection", "close")

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, uri, req.Host)
	if err := req.Header.Write(&buf); err != nil {
		return protocol.Address{}, nil, err
	}
	for _, te := range req.TransferEncoding {
		if te == "chunked" {
			buf.WriteString("Transfer-Encoding: chunked\r\n")
		}
	}
	buf.WriteString("\r\n")
	return protocol.NewAddress(host, port), withReadPrefix(c, br, buf.Bytes()), nil
}

// splitHostPort parses host[:port], applying a default port when absent.
func splitHostPort(hostport string, def int) (string, int, error) {
	if hostport == "" {
		return "", 0, fmt.Errorf("http: empty host")
	}
	if !strings.Contains(hostport, ":") {
		return hostport, def, nil
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
