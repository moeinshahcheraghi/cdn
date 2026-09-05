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
)

// NewServerTLSConfig builds a TLS config from PEM files, or a generated
// self-signed certificate when both paths are empty. ALPN advertises h2 and
// http/1.1 so the handshake matches a modern web server.
func NewServerTLSConfig(certFile, keyFile, sni string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("transport: load cert: %w", err)
		}
	} else {
		cert, err = selfSigned(sni)
		if err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// Listen opens a plain TCP listener; TLS is applied per-connection by the
// caller so that a failed/short handshake can still be handed to the fallback.
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reuseControl}
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
