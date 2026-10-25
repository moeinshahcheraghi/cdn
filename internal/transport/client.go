package transport

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/moeinshah0/tunnel/internal/httpconn"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/wsconn"
)

// Endpoint is one way of reaching the tunnel server: an address plus how to
// dress the connection (plain TLS, REALITY, or a WebSocket through a CDN).
type Endpoint struct {
	Server        string // host:port to connect to
	SNI           string // ServerName to present
	Fingerprint   string // browser to mimic
	AllowInsecure bool   // skip cert verification (self-signed)
	// Reality, when set, replaces certificate-based TLS with the REALITY
	// handshake (see reality.go); SNI is then the imitated site's name.
	Reality *RealityClient
	// WS, when set, wraps the stream in a WebSocket so it can pass a CDN.
	WS *WSClient
	// HTTP, when set, carries the stream in plain HTTP/2 requests through a
	// CDN instead (see package httpconn); its fields mean the same as WS's.
	HTTP *WSClient
	// ECH, when set, encrypts the server name (see ech.go); the censor then
	// sees only the CDN's public name. Certificate TLS routes only.
	ECH *ECH
	// Fragment, when set, splits the ClientHello (see fragment.go).
	Fragment *Fragment
	// Tier orders endpoints: a higher tier is used only while every endpoint
	// of the lower tiers is failing (0 = primary, 1 = backup).
	Tier int

	// health, guarded by Dialer.mu
	fails     int
	downUntil time.Time
	probing   bool
}

// WSClient configures the WebSocket (or HTTP) wrapping of an endpoint.
type WSClient struct {
	Path string // must equal the server's ws.path
	Host string // Host header; defaults to the SNI
}

func (e *Endpoint) String() string {
	mode := "tls"
	switch {
	case e.Reality != nil:
		mode = "reality"
	case e.WS != nil:
		mode = "ws"
	case e.HTTP != nil:
		mode = "http"
	}
	if e.ECH != nil {
		mode += ", ech"
	}
	if e.Fragment != nil {
		mode += ", fragment"
	}
	return fmt.Sprintf("%s (%s, sni %s)", e.Server, mode, e.SNI)
}

// attemptTimeout bounds one endpoint attempt so a black-holed endpoint does
// not use up the caller's whole budget before the next one is tried.
const attemptTimeout = 8 * time.Second

// Dialer establishes browser-looking connections to the tunnel server over
// whichever endpoint currently works.
type Dialer struct {
	mu  sync.Mutex
	eps []*Endpoint
	tcp net.Dialer
}

// NewDialer builds a Dialer over eps with sensible TCP timeouts and keepalive.
func NewDialer(eps []Endpoint) *Dialer {
	d := &Dialer{tcp: net.Dialer{Timeout: attemptTimeout, KeepAliveConfig: KeepAlive, Control: clientControl}}
	for i := range eps {
		ep := eps[i]
		if ep.SNI == "" {
			if host, _, err := net.SplitHostPort(ep.Server); err == nil {
				ep.SNI = host
			}
		}
		d.eps = append(d.eps, &ep)
	}
	return d
}

// Endpoints returns the configured endpoints, for diagnostics.
func (d *Dialer) Endpoints() []*Endpoint { return d.eps }

// Dial connects over the best available endpoint: a random healthy one of
// the lowest tier, falling through to the others when it fails. Endpoints
// that fail are set aside with exponential backoff and re-tested in the
// background, so neither a blocked exit IP nor its recovery costs users more
// than one slow connection attempt.
func (d *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	var errs []error
	for _, ep := range d.order() {
		if ctx.Err() != nil {
			break
		}
		actx, cancel := context.WithTimeout(ctx, attemptTimeout)
		conn, err := d.DialEndpoint(actx, ep, "")
		cancel()
		if err == nil {
			d.report(ep, nil)
			return conn, nil
		}
		d.report(ep, err)
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, ctx.Err()
	}
	return nil, errors.Join(errs...)
}

// order returns the endpoints to try: healthy ones by tier (shuffled within
// a tier, which is what spreads load over several exits), then the ones in
// backoff as a last resort. Endpoints whose backoff just ended are re-tested
// off the request path.
func (d *Dialer) order() []*Endpoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	var up, down []*Endpoint
	for _, ep := range d.eps {
		switch {
		case ep.fails == 0:
			up = append(up, ep)
		case now.After(ep.downUntil) && !ep.probing:
			ep.probing = true
			go d.reprobe(ep)
			down = append(down, ep)
		default:
			down = append(down, ep)
		}
	}
	rand.Shuffle(len(up), func(i, j int) { up[i], up[j] = up[j], up[i] })
	rand.Shuffle(len(down), func(i, j int) { down[i], down[j] = down[j], down[i] })
	byTier := func(s []*Endpoint) {
		// stable insertion sort; the lists are tiny
		for i := 1; i < len(s); i++ {
			for j := i; j > 0 && s[j].Tier < s[j-1].Tier; j-- {
				s[j], s[j-1] = s[j-1], s[j]
			}
		}
	}
	byTier(up)
	byTier(down)
	return append(up, down...)
}

// reprobe tests a failed endpoint with a handshake of its own.
func (d *Dialer) reprobe(ep *Endpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
	conn, err := d.DialEndpoint(ctx, ep, "")
	cancel()
	if err == nil {
		conn.Close()
	}
	d.mu.Lock()
	ep.probing = false
	d.mu.Unlock()
	d.report(ep, err)
}

// ReportStall records that connections over ep stopped moving data after
// the handshake, which counts against it like a failed dial.
func (d *Dialer) ReportStall(ep *Endpoint) {
	if ep != nil {
		d.report(ep, errors.New("connection stalled"))
	}
}

func (d *Dialer) report(ep *Endpoint, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		if ep.fails > 0 {
			logx.Infof("endpoint %s is back", ep)
		}
		ep.fails = 0
		return
	}
	ep.fails++
	backoff := 5 * time.Second << min(ep.fails-1, 5)
	if backoff > 2*time.Minute {
		backoff = 2 * time.Minute
	}
	ep.downUntil = time.Now().Add(backoff)
	if ep.fails == 1 {
		logx.Warnf("endpoint %s failing: %v", ep, err)
	}
}

// DialEndpoint connects over one specific endpoint. fp overrides the
// endpoint's fingerprint when not empty (diagnostics).
func (d *Dialer) DialEndpoint(ctx context.Context, ep *Endpoint, fp string) (net.Conn, error) {
	raw, err := d.dialRaw(ctx, ep)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", ep.Server, err)
	}
	conn, err := d.handshake(ctx, raw, ep, fp)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return &epConn{Conn: conn, ep: ep}, nil
}

// dialRaw opens the TCP connection to ep, with no Nagle delay (low latency,
// and it keeps fragmented hello pieces in separate segments).
func (d *Dialer) dialRaw(ctx context.Context, ep *Endpoint) (net.Conn, error) {
	raw, err := d.tcp.DialContext(ctx, "tcp", ep.Server)
	if err != nil {
		return nil, err
	}
	if t, ok := raw.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
	}
	return fragment(raw, ep.Fragment, ep.SNI), nil
}

// handshake dresses raw according to ep.
func (d *Dialer) handshake(ctx context.Context, raw net.Conn, ep *Endpoint, fp string) (net.Conn, error) {
	if fp == "" {
		fp = ep.Fingerprint
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	} else {
		_ = raw.SetDeadline(time.Now().Add(attemptTimeout))
	}
	defer raw.SetDeadline(time.Time{})

	if ep.Reality != nil {
		conn, err := realityDial(ctx, raw, ep, fp)
		if errors.Is(err, errRealityRejected) && syncClock(ctx, &d.tcp, ep) {
			// Our clock was wrong and is now compensated; the token is bound
			// to the time, so try once more on a fresh connection.
			raw2, derr := d.dialRaw(ctx, ep)
			if derr != nil {
				return nil, err
			}
			if deadline, ok := ctx.Deadline(); ok {
				_ = raw2.SetDeadline(deadline)
			}
			conn, err = realityDial(ctx, raw2, ep, fp)
			if err != nil {
				raw2.Close()
				return nil, err
			}
			raw.Close()
			_ = raw2.SetDeadline(time.Time{})
		}
		return conn, err
	}

	uconn, err := tlsHandshake(ctx, raw, ep, fp)
	if err != nil && ep.ECH != nil && ep.ECH.update(err) {
		// The CDN has rotated its ECH keys and sent the current ones; the
		// refused handshake cannot continue, so start over with them.
		raw2, derr := d.dialRaw(ctx, ep)
		if derr != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = raw2.SetDeadline(deadline)
		}
		if uconn, err = tlsHandshake(ctx, raw2, ep, fp); err != nil {
			raw2.Close()
			return nil, err
		}
		raw.Close()
		_ = raw2.SetDeadline(time.Time{})
	}
	if err != nil {
		return nil, err
	}
	if ep.HTTP != nil {
		// The browser's own hello, h2 and all, goes out unchanged; the CDN
		// must then pick h2, as every major one does.
		if p := uconn.ConnectionState().NegotiatedProtocol; p != "h2" {
			return nil, fmt.Errorf("transport: http route needs HTTP/2 from the CDN, got %q", p)
		}
		host := ep.HTTP.Host
		if host == "" {
			host = ep.SNI
		}
		hc, err := httpconn.Dial(ctx, uconn, host, ep.HTTP.Path)
		if err != nil {
			return nil, fmt.Errorf("transport: %w", err)
		}
		return hc, nil
	}
	if ep.WS == nil {
		return uconn, nil
	}
	host := ep.WS.Host
	if host == "" {
		host = ep.SNI
	}
	ws, err := wsconn.Dial(uconn, host, ep.WS.Path)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	return ws, nil
}

// tlsHandshake runs certificate TLS over raw with fingerprint fp, offering
// ECH when ep has keys for it.
func tlsHandshake(ctx context.Context, raw net.Conn, ep *Endpoint, fp string) (*utls.UConn, error) {
	cfg := &utls.Config{
		ServerName:         ep.SNI,
		InsecureSkipVerify: ep.AllowInsecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if ep.ECH != nil {
		cfg.EncryptedClientHelloConfigList = ep.ECH.get()
		cfg.EncryptedClientHelloRejectionVerify = deferRejection
	}
	var uconn *utls.UConn
	if ep.WS != nil {
		// A browser opening a WebSocket offers only http/1.1, and the upgrade
		// needs it: over h2 the CDN would expect an HTTP/2 request.
		cfg.NextProtos = []string{"http/1.1"}
		var err error
		if uconn, err = http1Client(raw, cfg, fp); err != nil {
			return nil, err
		}
	} else {
		uconn = utls.UClient(raw, cfg, clientHelloID(fp))
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		var rej *utls.ECHRejectionError
		if ep.ECH != nil && errors.As(err, &rej) {
			if verr := ep.ECH.checkRejection(uconn.ConnectionState().PeerCertificates); verr != nil {
				return nil, fmt.Errorf("transport: %w", verr)
			}
			return nil, err // verified: the caller may adopt the new keys
		}
		if ep.ECH != nil && strings.Contains(err.Error(), "EncryptedClientHelloExtension not present") {
			return nil, fmt.Errorf("transport: fingerprint %q cannot carry ech; use firefox", fp)
		}
		return nil, fmt.Errorf("transport: tls handshake: %w", err)
	}
	return uconn, nil
}

// http1Client is utls.UClient with the fingerprint's ALPN list reduced to
// http/1.1; everything else in the ClientHello stays the browser's.
func http1Client(raw net.Conn, cfg *utls.Config, fp string) (*utls.UConn, error) {
	spec, err := utls.UTLSIdToSpec(clientHelloID(fp))
	if err != nil {
		return nil, fmt.Errorf("transport: fingerprint %q: %w", fp, err)
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("transport: apply fingerprint: %w", err)
	}
	return uconn, nil
}

// epConn remembers which endpoint a connection used, so stalls on it can be
// held against that endpoint.
type epConn struct {
	net.Conn
	ep *Endpoint
}

// EndpointOf returns the endpoint conn was dialed over, or nil.
func EndpointOf(conn net.Conn) *Endpoint {
	if c, ok := conn.(*epConn); ok {
		return c.ep
	}
	return nil
}

func (c *epConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// clientHelloID maps a name to a uTLS fingerprint, defaulting to auto-Chrome.
// "random" builds a hello no real browser sends and is the weakest choice
// against fingerprint whitelisting; it exists only for experiments.
func clientHelloID(name string) utls.ClientHelloID {
	switch name {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloChrome_Auto
	}
}
