package transport

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// REALITY mode borrows a real, popular website's identity. The client's
// ClientHello carries the SNI of that site and, hidden inside the 32-byte
// session-id field, an AEAD-sealed authentication token derived from an
// X25519 exchange with the server's key. An authenticated client gets a
// certificate the server mints on the fly, whose signature the client checks
// with the shared key; anyone else (a censor's active probe, a curious
// browser) is spliced byte-for-byte to the real site and receives its genuine
// certificate. The server therefore needs no domain, no certificate and no
// website of its own, and the observable SNI is one the censor already allows.
//
// The wire protocol matches XTLS/REALITY so the audited server library can
// be used unchanged; the client side below is an independent implementation
// of that protocol on top of uTLS.

// RealityServer configures the server side of REALITY.
type RealityServer struct {
	Dest        string   // host:port of the real site to imitate / forward to
	ServerNames []string // SNIs accepted (must be served by Dest)
	PrivateKey  string   // base64url X25519 private key (see GenerateRealityKeys)
	ShortIDs    []string // hex, 0..16 chars each; "" allows an empty short id
	MaxTimeDiff time.Duration
}

// RealityClient configures the client side of REALITY.
type RealityClient struct {
	PublicKey string // base64url X25519 public key of the server
	ShortID   string // hex, must be in the server's list
}

// clientVersion is written into the auth token; the server may bound it.
var clientVersion = [4]byte{25, 0, 0, 0}

// GenerateRealityKeys returns a fresh X25519 key pair, base64url-encoded
// without padding, the same format Xray uses.
func GenerateRealityKeys() (private, public string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv), enc.EncodeToString(pub), nil
}

func decodeKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != 32 {
		return nil, errors.New("transport: reality key must be a base64url X25519 key (32 bytes)")
	}
	return b, nil
}

func decodeShortID(s string) ([8]byte, error) {
	var id [8]byte
	if len(s) > 16 || len(s)%2 != 0 {
		return id, fmt.Errorf("transport: short id %q must be 0-16 hex chars, even length", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("transport: short id %q: %w", s, err)
	}
	copy(id[:], b)
	return id, nil
}

// NewRealityConfig validates rs and builds the library config. It also starts
// the library's background probe of Dest, which learns the sizes of the real
// site's post-handshake records so they can be imitated.
func NewRealityConfig(rs *RealityServer) (*reality.Config, error) {
	if rs.Dest == "" || len(rs.ServerNames) == 0 || rs.PrivateKey == "" {
		return nil, errors.New("transport: reality needs dest, server_names and private_key")
	}
	priv, err := decodeKey(rs.PrivateKey)
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(rs.ServerNames))
	for _, n := range rs.ServerNames {
		names[n] = true
	}
	ids := make(map[[8]byte]bool, len(rs.ShortIDs))
	if len(rs.ShortIDs) == 0 {
		ids[[8]byte{}] = true
	}
	for _, s := range rs.ShortIDs {
		id, err := decodeShortID(s)
		if err != nil {
			return nil, err
		}
		ids[id] = true
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	cfg := &reality.Config{
		DialContext:            d.DialContext,
		Type:                   "tcp",
		Dest:                   rs.Dest,
		ServerNames:            names,
		PrivateKey:             priv,
		ShortIds:               ids,
		MaxTimeDiff:            rs.MaxTimeDiff,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
	}
	reality.DetectPostHandshakeRecordsLens(cfg)
	return cfg, nil
}

// RealityHandshake performs the server-side REALITY handshake on raw. For an
// authenticated client it returns the established connection. For anyone
// else the library has already served the real site's handshake and spliced
// the connection through to Dest; it returns an error and the caller is done.
func RealityHandshake(ctx context.Context, raw net.Conn, cfg *reality.Config) (net.Conn, error) {
	return reality.Server(ctx, raw, cfg)
}

// realityDial performs the client-side REALITY handshake over raw.
func (d *Dialer) realityDial(ctx context.Context, raw net.Conn) (net.Conn, error) {
	serverPub, err := decodeKey(d.Reality.PublicKey)
	if err != nil {
		return nil, err
	}
	shortID, err := decodeShortID(d.Reality.ShortID)
	if err != nil {
		return nil, err
	}
	var authKey []byte
	verified := false
	cfg := &utls.Config{
		ServerName:             d.SNI,
		InsecureSkipVerify:     true, // we verify with the shared key below
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok {
				h := hmac.New(sha512.New, authKey)
				h.Write(pub)
				if hmac.Equal(h.Sum(nil), leaf.Signature) {
					verified = true
					return nil
				}
			}
			// Not ours: it is the real site's chain, meaning the server did
			// not accept our token (wrong key/short id/clock) or something in
			// the path is impersonating it. Report clearly either way.
			return errors.New("transport: reality: server did not authenticate us (check public_key, short_id, server clock)")
		},
	}
	uconn := utls.UClient(raw, cfg, clientHelloID(d.Fingerprint))
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("transport: build hello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	if len(hello.Raw) < 39+32 {
		return nil, errors.New("transport: reality: unexpected ClientHello layout")
	}
	keys := uconn.HandshakeState.State13.KeyShareKeys
	var ecdhe *ecdh.PrivateKey
	if keys != nil {
		ecdhe = keys.Ecdhe
		if ecdhe == nil {
			ecdhe = keys.MlkemEcdhe
		}
	}
	if ecdhe == nil || ecdhe.Curve() != ecdh.X25519() {
		return nil, errors.New("transport: reality: fingerprint has no X25519 key share")
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, err
	}
	shared, err := ecdhe.ECDH(peer)
	if err != nil {
		return nil, err
	}
	authKey = make([]byte, 32)
	if _, err := hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)

	// Token: version(4) | unix time(4) | short id(8), sealed with the hello
	// (session id zeroed) as associated data, so it cannot be transplanted.
	sid := make([]byte, 32)
	copy(sid, clientVersion[:])
	binary.BigEndian.PutUint32(sid[4:], uint32(time.Now().Unix()))
	copy(sid[8:], shortID[:])
	copy(hello.Raw[39:], make([]byte, 32))
	sealed := aead.Seal(nil, hello.Random[20:], sid[:16], hello.Raw)
	copy(hello.Raw[39:], sealed)
	hello.SessionId = sealed

	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("transport: reality handshake: %w", err)
	}
	if !verified {
		uconn.Close()
		return nil, errors.New("transport: reality: certificate not verified")
	}
	return uconn, nil
}

var _ = bytes.Equal
