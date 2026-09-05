// Package relay copies bytes between two connections efficiently.
package relay

import (
	"io"
	"net"
	"sync"
	"time"
)

// bufPool holds 32 KiB buffers; large enough to keep throughput high without
// wasting memory per connection.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// Pipe copies data in both directions until either side closes, then returns.
// It half-closes writes so that a one-directional shutdown (e.g. an HTTP
// client done sending) still lets the response drain.
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyClose(a, b) }()
	go func() { defer wg.Done(); copyClose(b, a) }()
	wg.Wait()
}

// copyClose copies src->dst, then half-closes dst's write side if possible.
func copyClose(dst, src net.Conn) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	_, _ = io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *bp)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.SetReadDeadline(time.Now())
	}
}

// readerOnly/writerOnly stop io.CopyBuffer from taking ReadFrom/WriteTo
// shortcuts that would bypass our pooled buffer.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }
