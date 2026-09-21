package transport

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/moeinshah0/tunnel/internal/logx"
)

// The REALITY token carries the client's time and the server rejects tokens
// too far from its own (max_time_diff). Relay servers inside a censored
// network often cannot reach NTP and drift by minutes, which silently turns
// every handshake into "not authenticated": the tunnel never connects from
// that datacenter although nothing is blocked. Rather than depend on the
// operator fixing the clock, the client measures the true time and applies
// the difference to its tokens.

// clockOffset is added to the local clock, in nanoseconds.
var clockOffset atomic.Int64

var (
	clockMu       sync.Mutex
	clockSyncedAt time.Time
)

// now is the local time corrected by the measured offset.
func now() time.Time { return time.Now().Add(time.Duration(clockOffset.Load())) }

// ClockOffset reports the correction currently applied.
func ClockOffset() time.Duration { return time.Duration(clockOffset.Load()) }

// syncClock measures the real time after a REALITY rejection and reports
// whether the correction changed enough for a retry to make sense.
func syncClock(ctx context.Context, tcp *net.Dialer, ep *Endpoint) bool {
	clockMu.Lock()
	defer clockMu.Unlock()
	if !clockSyncedAt.IsZero() && time.Since(clockSyncedAt) < 5*time.Minute {
		return false
	}
	clockSyncedAt = time.Now()
	remote, err := RemoteTime(ctx, tcp, ep)
	if err != nil {
		logx.Debugf("transport: clock check: %v", err)
		return false
	}
	off := time.Until(remote)
	change := off - time.Duration(clockOffset.Load())
	if change < 0 {
		change = -change
	}
	if change < 20*time.Second {
		return false // the clock is not the reason we were rejected
	}
	clockOffset.Store(int64(off))
	logx.Warnf("this machine's clock is off by %v; compensating. Fix it for good with: timedatectl set-ntp true", (-off).Round(time.Second))
	return true
}

// RemoteTime asks the imitated site for the time. A client without a valid
// token is spliced by the REALITY server to the real site, so an ordinary
// HTTPS request to the same address returns that site's Date header. The
// certificate is not verified: with a wrong clock verification cannot
// succeed, and a false answer can do no worse than another rejected token.
func RemoteTime(ctx context.Context, tcp *net.Dialer, ep *Endpoint) (time.Time, error) {
	raw, err := tcp.DialContext(ctx, "tcp", ep.Server)
	if err != nil {
		return time.Time{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(attemptTimeout))
	u, err := http1Client(raw, &utls.Config{ServerName: ep.SNI, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, ep.Fingerprint)
	if err != nil {
		return time.Time{}, err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		return time.Time{}, err
	}
	req := "HEAD / HTTP/1.1\r\nHost: " + ep.SNI + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := u.Write([]byte(req)); err != nil {
		return time.Time{}, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(u), &http.Request{Method: "HEAD"})
	if err != nil {
		return time.Time{}, err
	}
	resp.Body.Close()
	return http.ParseTime(resp.Header.Get("Date"))
}
