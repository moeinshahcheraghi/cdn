package transport

import (
	"context"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenCtx is a background context for the listener config.
func listenCtx() context.Context { return context.Background() }

// reuseControl sets SO_REUSEADDR/SO_REUSEPORT so restarts bind instantly and
// the server can scale across accept goroutines without bind conflicts.
func reuseControl(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			serr = e
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		// Inherited by accepted connections.
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, userTimeoutMs)
	})
	if err != nil {
		return err
	}
	return serr
}

// userTimeoutMs is TCP_USER_TIMEOUT: how long sent data may stay
// unacknowledged before the kernel gives the connection up. The default is
// about fifteen minutes, during which a flow whose packets a censor silently
// drops would hang every user on it; with this the failure surfaces quickly
// and the streams are resumed elsewhere.
const userTimeoutMs = 30000

// clientControl applies socket options to outgoing tunnel connections.
func clientControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, userTimeoutMs)
	})
}
