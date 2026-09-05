// Package protocol implements the tunnel wire format.
//
// The design is inspired by Trojan: after a real TLS 1.3 handshake, an
// authenticated client sends a fixed-length password digest followed by a
// SOCKS-like request. A peer that does not present the correct digest is
// indistinguishable from an ordinary HTTPS client and is handed to the
// fallback website, which defeats active probing by a censor.
package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Command identifies what an authenticated stream wants to do.
type Command byte

const (
	// CmdConnect relays a single TCP stream to Address.
	CmdConnect Command = 0x01
	// CmdUDPAssociate relays UDP packets (framed) to arbitrary destinations.
	CmdUDPAssociate Command = 0x03
	// CmdMux turns the connection into a smux session carrying many streams.
	CmdMux Command = 0x7f
)

// Address atypes, matching SOCKS5 so translation is trivial.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// CRLF terminates each header section, exactly as HTTP does, so the framing
// looks unremarkable to anything peeking before encryption is considered.
var CRLF = []byte{0x0d, 0x0a}

// HashLen is the length in bytes of the hex-encoded SHA-224 password digest.
const HashLen = 56

// HashPassword returns the hex-encoded SHA-224 of the password. SHA-224 gives
// exactly 56 hex chars, matching Trojan so the auth prefix is a constant size.
func HashPassword(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Address is a network endpoint encoded SOCKS5-style.
type Address struct {
	Host string // domain or IP literal
	Port int
	atyp byte
}

// NewAddress builds an Address from host:port, preserving IP vs domain form.
func NewAddress(host string, port int) Address {
	a := Address{Host: host, Port: port, atyp: atypDomain}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			a.atyp = atypIPv4
		} else {
			a.atyp = atypIPv6
		}
	}
	return a
}

// String renders host:port for dialing and logging.
func (a Address) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

// ReadAddress decodes a SOCKS5-style address from r.
func ReadAddress(r io.Reader) (Address, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Address{}, err
	}
	var a Address
	a.atyp = atyp[0]
	switch atyp[0] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Address{}, err
		}
		a.Host = net.IP(b[:]).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Address{}, err
		}
		a.Host = net.IP(b[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Address{}, err
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return Address{}, err
		}
		a.Host = string(buf)
	default:
		return Address{}, fmt.Errorf("protocol: unknown atyp 0x%02x", atyp[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Address{}, err
	}
	a.Port = int(binary.BigEndian.Uint16(p[:]))
	return a, nil
}

// WriteTo appends the SOCKS5-style encoding of a to buf.
func (a Address) AppendTo(buf []byte) []byte {
	switch a.atyp {
	case atypIPv4:
		buf = append(buf, atypIPv4)
		buf = append(buf, net.ParseIP(a.Host).To4()...)
	case atypIPv6:
		buf = append(buf, atypIPv6)
		buf = append(buf, net.ParseIP(a.Host).To16()...)
	default:
		buf = append(buf, atypDomain, byte(len(a.Host)))
		buf = append(buf, a.Host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(a.Port))
	return append(buf, p[:]...)
}

// Metadata is the per-stream request header: a command plus a destination.
type Metadata struct {
	Command Command
	Address Address
}

// AppendTo serializes the metadata (command + address + CRLF) onto buf.
func (m Metadata) AppendTo(buf []byte) []byte {
	buf = append(buf, byte(m.Command))
	buf = m.Address.AppendTo(buf)
	return append(buf, CRLF...)
}

// ReadMetadata decodes a metadata header from r.
func ReadMetadata(r io.Reader) (Metadata, error) {
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return Metadata{}, err
	}
	addr, err := ReadAddress(r)
	if err != nil {
		return Metadata{}, err
	}
	if err := expectCRLF(r); err != nil {
		return Metadata{}, err
	}
	return Metadata{Command: Command(cmd[0]), Address: addr}, nil
}

func expectCRLF(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != 0x0d || b[1] != 0x0a {
		return errors.New("protocol: expected CRLF")
	}
	return nil
}
