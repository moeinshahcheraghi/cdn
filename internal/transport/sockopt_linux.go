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
	})
	if err != nil {
		return err
	}
	return serr
}
