// Package config loads and validates JSON configuration for both roles.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// ServerConfig configures the tunnel server (the exit node).
type ServerConfig struct {
	// Listen is the public address, normally ":443" to blend with HTTPS.
	Listen string `json:"listen"`
	// Passwords accepted from clients. Any match authenticates.
	Passwords []string `json:"passwords"`
	// TLSCert / TLSKey are PEM paths for a real certificate. If empty a
	// self-signed cert is generated for SNI (fine for testing, weaker cover).
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// ACME obtains and renews a real certificate automatically (Let's Encrypt)
	// using the TLS-ALPN-01 challenge on this same listener, which therefore
	// must be reachable on port 443 of Domain. Takes precedence over TLSCert.
	ACME ACMEConfig `json:"acme"`
	// Fallback is a real HTTP(S) origin that unauthenticated / probe traffic is
	// reverse-proxied to, so the server is indistinguishable from a web server.
	Fallback string `json:"fallback"`
	// Log level: error|warn|info|debug.
	Log string `json:"log"`
}

// ACMEConfig enables automatic certificates.
type ACMEConfig struct {
	Domain   string `json:"domain"`    // hostname the certificate is for
	Email    string `json:"email"`     // optional contact for the CA
	CacheDir string `json:"cache_dir"` // where certs/keys are persisted
}

// ClientConfig configures the local proxy that tunnels to the server.
type ClientConfig struct {
	// Server is the tunnel server's host:port.
	Server string `json:"server"`
	// Password must match one server password.
	Password string `json:"password"`
	// SNI presented in the TLS handshake; should match the server cert's name.
	SNI string `json:"sni"`
	// Fingerprint mimics a browser's TLS ClientHello: chrome|firefox|safari|ios|edge|random.
	Fingerprint string `json:"fingerprint"`
	// SocksListen / HTTPListen are local proxy addresses (either may be empty).
	SocksListen string `json:"socks_listen"`
	HTTPListen  string `json:"http_listen"`
	// Mux multiplexes many streams over few TLS connections for low latency.
	Mux MuxConfig `json:"mux"`
	// AllowInsecure skips certificate verification (needed for self-signed).
	AllowInsecure bool `json:"allow_insecure"`
	// Log level: error|warn|info|debug.
	Log string `json:"log"`
}

// MuxConfig tunes stream multiplexing.
type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"` // max streams per physical connection
	Pool        int  `json:"pool"`        // max idle physical connections
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*ServerConfig, error) {
	var c ServerConfig
	if err := readJSON(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if len(c.Passwords) == 0 {
		return nil, fmt.Errorf("config: at least one password is required")
	}
	if c.Fallback == "" {
		c.Fallback = "example.com:443"
	}
	if c.ACME.Domain != "" {
		if c.TLSCert != "" || c.TLSKey != "" {
			return nil, fmt.Errorf("config: use either acme or tls_cert/tls_key, not both")
		}
		if c.ACME.CacheDir == "" {
			c.ACME.CacheDir = "/var/lib/tunnel/acme"
		}
	}
	if c.Log == "" {
		c.Log = "info"
	}
	return &c, nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*ClientConfig, error) {
	var c ClientConfig
	if err := readJSON(path, &c); err != nil {
		return nil, err
	}
	if c.Server == "" {
		return nil, fmt.Errorf("config: server is required")
	}
	if c.Password == "" {
		return nil, fmt.Errorf("config: password is required")
	}
	if c.Fingerprint == "" {
		c.Fingerprint = "chrome"
	}
	if c.SocksListen == "" && c.HTTPListen == "" {
		c.SocksListen = "127.0.0.1:1080"
	}
	if c.Mux.Enabled {
		if c.Mux.Concurrency <= 0 {
			c.Mux.Concurrency = 8
		}
		if c.Mux.Pool <= 0 {
			c.Mux.Pool = 4
		}
	}
	if c.Log == "" {
		c.Log = "info"
	}
	return &c, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(newCommentStripper(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}
