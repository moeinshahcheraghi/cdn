// Package config loads and validates JSON configuration for both roles.
package config

import (
	"encoding/json"
	"fmt"
	"net"
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
	// Reality enables REALITY mode: the server imitates a real website whose
	// name the censor already permits, needs no domain or certificate of its
	// own, and hands probes the genuine site. When dest is set, acme/tls_cert
	// are ignored. Generate keys with: tunnel-server -keygen
	Reality RealityServerConfig `json:"reality"`
	// Fallback is a real HTTP(S) origin that unauthenticated / probe traffic is
	// reverse-proxied to, so the server is indistinguishable from a web server.
	Fallback string `json:"fallback"`
	// Log level: error|warn|info|debug.
	Log string `json:"log"`
}

// RealityServerConfig is the server half of REALITY.
type RealityServerConfig struct {
	Dest        string   `json:"dest"`          // real site to imitate, host:443
	ServerNames []string `json:"server_names"`  // SNIs to accept; served by dest
	PrivateKey  string   `json:"private_key"`   // from tunnel-server -keygen
	ShortIDs    []string `json:"short_ids"`     // hex, per-client tags
	MaxTimeDiff int      `json:"max_time_diff"` // seconds, 0 = unchecked
}

// RealityClientConfig is the client half of REALITY.
type RealityClientConfig struct {
	PublicKey string `json:"public_key"` // server's public key
	ShortID   string `json:"short_id"`   // one of the server's short_ids
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
	// Servers optionally lists several exit servers (same password/keys);
	// each new connection picks one at random, spreading traffic over more
	// than one IP so no single one carries a suspicious volume.
	Servers []string `json:"servers"`
	// Password must match one server password.
	Password string `json:"password"`
	// SNI presented in the TLS handshake; should match the server cert's name,
	// or in REALITY mode one of the server's server_names.
	SNI string `json:"sni"`
	// Reality, when public_key is set, uses the REALITY handshake instead of
	// certificate verification. Server may then be a bare IP:port.
	Reality RealityClientConfig `json:"reality"`
	// Fingerprint mimics a browser's TLS ClientHello: chrome|firefox|safari|ios|edge|random.
	Fingerprint string `json:"fingerprint"`
	// SocksListen / HTTPListen are local proxy addresses (either may be empty).
	SocksListen string `json:"socks_listen"`
	HTTPListen  string `json:"http_listen"`
	// Forwards are raw TCP port forwards: anything connecting to Listen is
	// tunneled to Target, which is resolved on the server side. This is how
	// you put a whole service (OpenVPN in TCP mode, SSH, a game server) behind
	// the tunnel without the application knowing about a proxy.
	Forwards []Forward `json:"forwards"`
	// Mux multiplexes many streams over few TLS connections for low latency.
	Mux MuxConfig `json:"mux"`
	// AllowInsecure skips certificate verification (needed for self-signed).
	AllowInsecure bool `json:"allow_insecure"`
	// Log level: error|warn|info|debug.
	Log string `json:"log"`
}

// Forward is one raw TCP port forward through the tunnel.
type Forward struct {
	Listen string `json:"listen"` // local address to accept on, e.g. "0.0.0.0:2083"
	Target string `json:"target"` // host:port as seen from the server, e.g. "127.0.0.1:1194"
}

// MuxConfig tunes stream multiplexing.
type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"` // max streams per physical connection
	Pool        int  `json:"pool"`        // max idle physical connections
	// RotateSeconds / RotateMB retire each TLS connection after at most this
	// age or traffic (each connection draws a random fraction of both), and
	// move its streams to a fresh connection without interrupting them. A
	// censor sees only short, modest HTTPS sessions instead of one hours-long
	// high-volume flow to throttle or flag. 0 disables that dimension.
	RotateSeconds int `json:"rotate_seconds"`
	RotateMB      int `json:"rotate_mb"`
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
	if c.Reality.Dest != "" {
		if len(c.Reality.ServerNames) == 0 || c.Reality.PrivateKey == "" {
			return nil, fmt.Errorf("config: reality needs server_names and private_key")
		}
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
	if c.Server == "" && len(c.Servers) > 0 {
		c.Server = c.Servers[0]
	}
	if c.Server == "" {
		return nil, fmt.Errorf("config: server is required")
	}
	if c.Password == "" {
		return nil, fmt.Errorf("config: password is required")
	}
	if c.Fingerprint == "" {
		// firefox, not chrome: modern Chrome's ClientHello carries a post-quantum
		// (ML-KEM) key share (~1.7 KB) that spans two TCP packets, and censors
		// (notably Iran's DPI) drop the split ClientHello. firefox's hello fits in
		// a single packet and handshakes reliably.
		c.Fingerprint = "firefox"
	}
	if c.SocksListen == "" && c.HTTPListen == "" && len(c.Forwards) == 0 {
		c.SocksListen = "127.0.0.1:1080"
	}
	for i, f := range c.Forwards {
		if f.Listen == "" || f.Target == "" {
			return nil, fmt.Errorf("config: forwards[%d]: listen and target are required", i)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return nil, fmt.Errorf("config: forwards[%d]: target must be host:port: %w", i, err)
		}
	}
	if c.Mux.Enabled {
		if c.Mux.Concurrency <= 0 {
			c.Mux.Concurrency = 8
		}
		if c.Mux.Pool <= 0 {
			c.Mux.Pool = 4
		}
		if c.Mux.RotateSeconds == 0 {
			c.Mux.RotateSeconds = 300
		}
		if c.Mux.RotateMB == 0 {
			c.Mux.RotateMB = 256
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
