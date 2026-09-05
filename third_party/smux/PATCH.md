# Vendored, patched smux

Source: github.com/xtaci/smux v1.5.57, wired in via a `replace` directive in
the repository go.mod. Only one behavioural change is applied, in `stream.go`
(`tryHalfCloseCleanup`); everything else is upstream verbatim. See LICENSE for
smux's MIT license.

## The bug

`tryHalfCloseCleanup` runs when a stream has both closed its own write side
(`CloseWrite`) and received the peer's FIN. It closed `s.die` and called
`s.sess.streamClosed`, whose `recycleTokens` **discards any bytes still sitting
in the stream's receive buffer that the application has not read yet**.

Because the peer sends its data frames and then its FIN, and the local reader
runs in a different goroutine than `recvLoop`, the FIN is frequently processed
while unread data is still buffered. That data is thrown away. In a proxy that
half-closes each direction on EOF (the normal relay pattern), this silently
truncates any transfer where one side finishes sending before the other, e.g.
a download whose client finished sending its request.

## The fix

Defer the teardown while unread data remains in the receive buffer. The FIN has
already been seen, so no more data can arrive for this stream; the reader will
drain the buffer and observe EOF, and the application's own `Close()` then
performs the teardown. No data is discarded.
