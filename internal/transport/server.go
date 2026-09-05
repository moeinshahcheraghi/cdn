// Package transport provides the TLS carrier for the tunnel: a standard TLS
// server listener and a browser-mimicking (uTLS) client dialer.
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACMEALPN is the ALPN protocol a certificate authority uses for the
// TLS-ALPN-01 challenge; connections negotiating it carry no tunnel traffic.
const ACMEALPN = acme.ALPNProto

// KeepAlive is the kernel TCP keepalive used on every tunnel connection, on
// both ends. It detects dead peers and refreshes NAT state without emitting
// any application-layer bytes, so idle tunnel sessions stay as silent as an
// idle browser connection.
var KeepAlive = net.KeepAliveConfig{
	Enable:   true,
	Idle:     30 * time.Second,
	Interval: 15 * time.Second,
	Count:    4,
}

// ACME configures automatic certificates from Let's Encrypt (or any ACME CA)
// via the TLS-ALPN-01 challenge, which works on the tunnel's own :443.
type ACME struct {
	Domain   string
	Email    string
	CacheDir string
}

// NewServerTLSConfig builds a TLS config from PEM files, from ACME when a
// domain is given, or from a generated self-signed certificate otherwise.
//
// ALPN advertises only http/1.1. The negotiated protocol is encrypted in
// TLS 1.3 so passive DPI cannot see it, but an active prober that connects
// with a real browser must get a working website back; the fallback origin
// speaks HTTP/1.1, so offering h2 would break that illusion.
func NewServerTLSConfig(certFile, keyFile, sni string, ac *ACME) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	switch {
	case ac != nil && ac.Domain != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(ac.Domain),
			Email:      ac.Email,
		}
		if ac.CacheDir != "" {
			m.Cache = autocert.DirCache(ac.CacheDir)
		}
		cfg.GetCertificate = m.GetCertificate
		cfg.NextProtos = append(cfg.NextProtos, ACMEALPN)
	case certFile != "" && keyFile != "":
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("transport: load cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	default:
		cert, err := selfSigned(sni)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// Listen opens a plain TCP listener; TLS is applied per-connection by the
// caller so that a failed/short handshake can still be handed to the fallback.
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reuseControl, KeepAliveConfig: KeepAlive}
	return lc.Listen(listenCtx(), "tcp", addr)
}

// selfSigned creates an in-memory ECDSA certificate for the given name.
func selfSigned(name string) (tls.Certificate, error) {
	if name == "" {
		name = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
