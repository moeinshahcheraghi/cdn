// Package rstream provides resumable streams: a reliable byte stream whose
// carrier connection can be replaced at any time without the application
// noticing.
//
// Why: a censor throttles or flags TCP flows that stay up for a long time and
// move a lot of data, which is exactly what a tunnel carrying VPN users
// produces. With resumable streams the tunnel can retire every TLS connection
// after a few minutes and a bounded number of bytes, and continue each user's
// stream over a fresh connection. To the censor each connection is a short,
// unremarkable HTTPS session; to the user nothing happens.
//
// Mechanism: every byte has an absolute offset. The sender keeps a window of
// unacknowledged bytes; the receiver acknowledges as it consumes. When a
// carrier is attached, transmission restarts from the offset the peer reports
// it has received, so bytes lost in flight on the old carrier are resent and
// duplicates are discarded by offset. Frames on the carrier are:
//
//	DATA  0x01 | offset u64 | length u16 | payload
//	ACK   0x02 | received u64 | consumed u64
//	FIN   0x03 | offset u64            (no more data after offset)
//
// An ACK carries two offsets. "received" lets the sender drop its
// retransmission copy and proves the carrier is moving (see Stalled).
// "consumed" is how far the peer's application has actually read, and it is
// what the send window is measured against: a slow reader therefore pushes
// back on the writer, and neither side ever buffers more than one window.
// Without that, a user on a slow link would make the relay queue an unbounded
// amount of data in memory and add seconds of latency (bufferbloat).
//
// Both peers run the same code; only who initiates a resume differs.
package rstream

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	frameData = 0x01
	frameAck  = 0x02
	frameFin  = 0x03

	hdrLen     = 1 + 8
	ackLen     = 1 + 8 + 8
	maxPayload = 16 * 1024

	// window bounds the bytes written but not yet consumed by the peer's
	// application; a writer blocks when it is full. It is also the most either
	// side ever buffers per direction.
	window = 2 << 20
	// ackEvery is how many received bytes trigger an acknowledgement; a
	// timer flushes the tail.
	ackEvery = 256 << 10
	ackDelay = 100 * time.Millisecond
)

// ErrResumeTimeout is returned when a detached stream is not resumed in time.
var ErrResumeTimeout = errors.New("rstream: carrier lost and not resumed")

// ErrClosed is returned by operations on a closed stream.
var ErrClosed = errors.New("rstream: closed")

var errProtocol = errors.New("rstream: protocol error")

// Stream is a resumable, reliable byte stream. It implements net.Conn.
type Stream struct {
	id uint64

	mu   sync.Mutex
	cond *sync.Cond // broadcast on any state change

	// send side; offsets are absolute.
	sendBuf      []byte // bytes [sendBase, sendBase+len) awaiting acknowledgement
	sendBase     uint64
	sentOff      uint64    // next offset to transmit on the current carrier
	peerConsumed uint64    // highest offset the peer's application has read
	progressAt   time.Time // last time anything arrived from the peer, or data became outstanding
	finOff       uint64    // valid when writeClosed
	finSent      bool      // FIN transmitted on the current carrier

	// receive side.
	recvBuf    []byte
	recvOff    uint64 // next expected offset
	peerFin    bool
	peerFinOff uint64
	lastAcked  uint64 // recvOff last acknowledged to the peer
	lastCons   uint64 // consumed offset last reported to the peer
	ackTimer   *time.Timer
	ackFlush   bool // delayed ACK is due

	writeClosed bool
	readClosed  bool
	closing     bool // Close called; lingering until the peer has everything
	lingerTimer *time.Timer
	closed      bool
	err         error

	carrier       net.Conn
	gen           int // incremented per attach; stale goroutines check it
	resumeTimeout time.Duration
	resumeTimer   *time.Timer

	readDeadline  time.Time
	onClose       func()
	onCarrierLost func()
}

// New creates a stream with the given id, starting at offset 0 on both
// sides. resumeTimeout bounds how long it survives without a carrier.
func New(id uint64, resumeTimeout time.Duration) *Stream {
	s := &Stream{id: id, resumeTimeout: resumeTimeout}
	s.cond = sync.NewCond(&s.mu)
	s.armResumeTimerLocked()
	return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint64 { return s.id }

// RecvOffset reports how many contiguous bytes have been received; it is
// what the peer needs to resume from.
func (s *Stream) RecvOffset() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recvOff
}

// SetOnClose registers a callback run once when the stream is torn down.
func (s *Stream) SetOnClose(f func()) {
	s.mu.Lock()
	s.onClose = f
	s.mu.Unlock()
}

// SetOnCarrierLost registers a callback run (on its own goroutine) whenever
// the carrier fails underneath a live stream, so the owner can resume it at
// once instead of waiting for a periodic check.
func (s *Stream) SetOnCarrierLost(f func()) {
	s.mu.Lock()
	s.onCarrierLost = f
	s.mu.Unlock()
}

// Acked reports how many of our bytes the peer has acknowledged receiving.
func (s *Stream) Acked() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendBase
}

// Fresh reports whether the peer has never confirmed anything on this
// stream: it acknowledged no byte we sent and we received none. Such a
// stream can be restarted from scratch rather than resumed — whatever we
// wrote went into a connection that died with it, so the far end either
// never saw it or is about to drop it unread.
func (s *Stream) Fresh() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendBase == 0 && s.recvOff == 0 && !s.closed
}

// Finished reports whether the stream no longer needs a carrier: everything
// the peer will ever send has arrived, and everything we sent, our FIN
// included, has been acknowledged. Such a stream must not be resumed — the
// peer has already forgotten it, and it may still hold data to be read.
func (s *Stream) Finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.finishedLocked()
}

// finishedLocked reports whether the stream has nothing left to carry.
func (s *Stream) finishedLocked() bool {
	recvDone := s.peerFin && s.recvOff == s.peerFinOff
	sendDone := s.writeClosed && s.finSent && s.sendBase >= s.finOff
	return recvDone && sendDone
}

// Closing reports whether the application has let this stream go, so a
// failure to keep it running is of no consequence to anyone.
func (s *Stream) Closing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing || s.closed
}

// PeerGone ends the stream as if the peer had closed it: data already
// received can still be read, Read then reports io.EOF, and writes fail.
// Unlike Close it never discards what the application has not read yet.
func (s *Stream) PeerGone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.peerFin = true
	s.peerFinOff = s.recvOff
	s.writeClosed = true
	s.armResumeTimerLocked()
	s.cond.Broadcast()
}

// Stalled reports whether data has been outstanding on the current carrier
// for longer than d with nothing at all arriving from the peer. The peer
// acknowledges receipt within ackDelay regardless of what its application
// does, so a long silence means the carrier is black-holed or throttled to
// nothing (censors drop packets far more often than they reset), a state TCP
// itself takes many minutes to report.
func (s *Stream) Stalled(d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.carrier == nil || s.closed {
		return false
	}
	return s.sentOff > s.sendBase && time.Since(s.progressAt) > d
}

// Attach starts carrying the stream over c, transmitting from peerRecvOff,
// the offset the peer reports having received. Any previous carrier is
// dropped. It fails if the peer asks for bytes no longer buffered.
func (s *Stream) Attach(c net.Conn, peerRecvOff uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if peerRecvOff < s.sendBase {
		// The peer is reporting an offset older than one it has already
		// acknowledged, because it sampled the offset before the last
		// acknowledgement crossed the old carrier. Everything below sendBase
		// is known to have arrived, so transmit from there; resending it is
		// impossible in any case, those bytes are long discarded.
		peerRecvOff = s.sendBase
	}
	if peerRecvOff > s.sendBase+uint64(len(s.sendBuf)) {
		return errors.New("rstream: peer claims bytes we never sent")
	}
	s.dropCarrierLocked()
	// Everything up to peerRecvOff is acknowledged by implication.
	s.trimLocked(peerRecvOff)
	s.carrier = c
	s.gen++
	s.sentOff = peerRecvOff
	s.finSent = false
	s.progressAt = time.Now()
	// Report our offsets again on the new carrier: an ACK in flight on the
	// old one may have been lost, and the peer's window depends on it.
	if s.recvOff > 0 {
		s.ackFlush = true
	}
	if s.resumeTimer != nil {
		s.resumeTimer.Stop()
		s.resumeTimer = nil
	}
	gen := s.gen
	go s.readLoop(c, gen)
	go s.writeLoop(c, gen)
	s.cond.Broadcast()
	return nil
}

// Detach drops the current carrier, if any. The stream stays alive and
// buffers until Attach is called again or the resume timeout expires.
func (s *Stream) Detach() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropCarrierLocked()
	s.armResumeTimerLocked()
	s.cond.Broadcast()
}

func (s *Stream) dropCarrierLocked() {
	if s.carrier != nil {
		old := s.carrier
		s.carrier = nil
		s.gen++ // invalidates loops
		// smux.Close sends a FIN and can wait for a blocked carrier for up
		// to 30 seconds. Invalidate it before closing, and never hold the
		// stream state lock during network cleanup: readers, writers and a
		// replacement carrier must remain able to make progress.
		go old.Close()
	}
}

func (s *Stream) armResumeTimerLocked() {
	if s.closed || s.carrier != nil || s.resumeTimer != nil {
		return
	}
	if s.finishedLocked() {
		// Nothing will ever need a carrier again, so losing one is not a
		// failure. The application still has whatever it has not read, and
		// tearing the stream down here would take it away.
		return
	}
	s.resumeTimer = time.AfterFunc(s.resumeTimeout, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.resumeTimer = nil
		if s.carrier == nil && !s.closed {
			s.failLocked(ErrResumeTimeout)
		}
	})
}

// trimLocked discards acknowledged bytes below off.
func (s *Stream) trimLocked(off uint64) {
	if off <= s.sendBase {
		return
	}
	n := off - s.sendBase
	if n > uint64(len(s.sendBuf)) {
		n = uint64(len(s.sendBuf))
	}
	s.sendBuf = s.sendBuf[n:]
	s.sendBase += n
	if s.sentOff < s.sendBase {
		// An acknowledgement overtook the transmit point. This happens right
		// after a resume: the peer told us where to restart, then an older
		// carrier delivered an acknowledgement for bytes beyond that. They
		// have arrived, so there is nothing left to retransmit.
		s.sentOff = s.sendBase
	}
	if len(s.sendBuf) == 0 {
		s.sendBuf = nil
	} else if cap(s.sendBuf) > 1<<20 && len(s.sendBuf) < cap(s.sendBuf)/4 {
		s.sendBuf = append([]byte(nil), s.sendBuf...) // release the big backing array
	}
	s.cond.Broadcast()
}

// Write appends p to the stream. It blocks while the unacknowledged window
// is full, which is how the peer's consumption rate flows back.
func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for len(p) > 0 {
		if s.closed || s.writeClosed {
			return n, s.errOr(io.ErrClosedPipe)
		}
		room := window - int(s.sendBase+uint64(len(s.sendBuf))-s.peerConsumed)
		if room <= 0 {
			s.cond.Wait()
			continue
		}
		if room > len(p) {
			room = len(p)
		}
		s.sendBuf = append(s.sendBuf, p[:room]...)
		p = p[room:]
		n += room
		s.cond.Broadcast()
	}
	return n, nil
}

// Read delivers received bytes in order, or io.EOF after the peer's FIN.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if len(s.recvBuf) > 0 {
			n := copy(p, s.recvBuf)
			s.recvBuf = s.recvBuf[n:]
			if len(s.recvBuf) == 0 {
				s.recvBuf = nil
			}
			// Consumption opens the peer's window; tell it.
			if s.ackReadyLocked() {
				s.cond.Broadcast()
			} else {
				s.scheduleAckLocked()
			}
			return n, nil
		}
		if s.readClosed || s.closed {
			return 0, s.errOr(io.ErrClosedPipe)
		}
		if s.peerFin && s.recvOff == s.peerFinOff {
			return 0, io.EOF
		}
		if s.err != nil {
			return 0, s.err
		}
		if !s.readDeadline.IsZero() {
			d := time.Until(s.readDeadline)
			if d <= 0 {
				return 0, timeoutError{}
			}
			t := time.AfterFunc(d, s.cond.Broadcast)
			s.cond.Wait()
			t.Stop()
			continue
		}
		s.cond.Wait()
	}
}

// CloseWrite signals the end of data; the peer sees io.EOF after draining.
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if !s.writeClosed {
		s.writeClosed = true
		s.finOff = s.sendBase + uint64(len(s.sendBuf))
		s.cond.Broadcast()
	}
	return nil
}

// Close ends the stream in both directions. It returns at once; data
// already written is still delivered. The stream lingers, resumable across
// carriers like any other, until the peer has acknowledged everything
// including the FIN, or the linger timeout expires.
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing {
		return nil
	}
	if !s.writeClosed {
		s.writeClosed = true
		s.finOff = s.sendBase + uint64(len(s.sendBuf))
	}
	s.readClosed = true
	s.recvBuf = nil
	s.closing = true
	s.cond.Broadcast()
	if s.maybeFinishLocked() {
		return nil
	}
	s.lingerTimer = time.AfterFunc(s.resumeTimeout, func() {
		s.mu.Lock()
		s.failLocked(ErrClosed)
		s.mu.Unlock()
	})
	return nil
}

// maybeFinishLocked completes a lingering close once the peer holds all our
// data and our FIN. It reports whether the stream was torn down.
func (s *Stream) maybeFinishLocked() bool {
	if s.closing && s.finSent && s.sendBase >= s.finOff {
		s.failLocked(ErrClosed)
		return true
	}
	return false
}

// failLocked tears the stream down with err.
func (s *Stream) failLocked(err error) {
	if s.closed {
		return
	}
	s.closed = true
	if s.err == nil {
		s.err = err
	}
	s.dropCarrierLocked()
	if s.resumeTimer != nil {
		s.resumeTimer.Stop()
		s.resumeTimer = nil
	}
	if s.lingerTimer != nil {
		s.lingerTimer.Stop()
		s.lingerTimer = nil
	}
	if s.ackTimer != nil {
		s.ackTimer.Stop()
		s.ackTimer = nil
	}
	s.sendBuf, s.recvBuf = nil, nil
	s.cond.Broadcast()
	if s.onClose != nil {
		f := s.onClose
		s.onClose = nil
		go f()
	}
}

func (s *Stream) errOr(def error) error {
	if s.err != nil && s.err != ErrClosed {
		return s.err
	}
	return def
}

// writeLoop transmits pending data, ACKs and FIN on carrier c while gen is
// current.
func (s *Stream) writeLoop(c net.Conn, gen int) {
	var hdr [ackLen]byte
	for {
		s.mu.Lock()
		for {
			if s.gen != gen || s.closed {
				s.mu.Unlock()
				return
			}
			if s.ackReadyLocked() {
				break
			}
			if s.sentOff < s.sendBase+uint64(len(s.sendBuf)) {
				break
			}
			if s.writeClosed && !s.finSent && s.sentOff == s.finOff {
				break
			}
			s.cond.Wait()
		}
		// Build one frame under the lock, send it outside.
		var frame []byte
		switch {
		case s.ackReadyLocked():
			hdr[0] = frameAck
			cons := s.consumedLocked()
			binary.BigEndian.PutUint64(hdr[1:], s.recvOff)
			binary.BigEndian.PutUint64(hdr[hdrLen:], cons)
			s.lastAcked = s.recvOff
			s.lastCons = cons
			s.ackFlush = false
			if s.ackTimer != nil {
				s.ackTimer.Stop()
				s.ackTimer = nil
			}
			frame = append([]byte(nil), hdr[:ackLen]...)
		case s.sentOff < s.sendBase+uint64(len(s.sendBuf)):
			start := s.sentOff - s.sendBase
			n := uint64(len(s.sendBuf)) - start
			if n > maxPayload {
				n = maxPayload
			}
			hdr[0] = frameData
			binary.BigEndian.PutUint64(hdr[1:], s.sentOff)
			binary.BigEndian.PutUint16(hdr[hdrLen:], uint16(n))
			frame = make([]byte, 0, hdrLen+2+int(n))
			frame = append(frame, hdr[:hdrLen+2]...)
			frame = append(frame, s.sendBuf[start:start+n]...)
			if s.sentOff == s.sendBase {
				s.progressAt = time.Now() // nothing was outstanding until now
			}
			s.sentOff += n
		default: // FIN
			hdr[0] = frameFin
			binary.BigEndian.PutUint64(hdr[1:], s.finOff)
			s.finSent = true
			frame = append([]byte(nil), hdr[:hdrLen]...)
		}
		s.mu.Unlock()
		if _, err := c.Write(frame); err != nil {
			s.carrierLost(c, gen)
			return
		}
	}
}

// consumedLocked is how far the application has read. After Close nothing
// will ever be read, so everything received counts as consumed.
func (s *Stream) consumedLocked() uint64 {
	return s.recvOff - uint64(len(s.recvBuf))
}

// ackReadyLocked reports whether an ACK should go out now: a large amount
// of unreported progress, or the delayed-ACK timer fired.
func (s *Stream) ackReadyLocked() bool {
	if s.ackFlush {
		return true
	}
	return s.recvOff-s.lastAcked >= ackEvery || s.consumedLocked()-s.lastCons >= ackEvery
}

// scheduleAckLocked arms the delayed-ACK timer for the tail of a burst.
func (s *Stream) scheduleAckLocked() {
	if s.ackTimer != nil || s.closed || (s.recvOff == s.lastAcked && s.consumedLocked() == s.lastCons) {
		return
	}
	s.ackTimer = time.AfterFunc(ackDelay, func() {
		s.mu.Lock()
		s.ackTimer = nil
		s.ackFlush = true
		s.cond.Broadcast()
		s.mu.Unlock()
	})
}

// readLoop receives frames from carrier c while gen is current.
func (s *Stream) readLoop(c net.Conn, gen int) {
	var hdr [ackLen]byte
	payload := make([]byte, 1<<16)
	for {
		if _, err := io.ReadFull(c, hdr[:hdrLen]); err != nil {
			s.carrierLost(c, gen)
			return
		}
		off := binary.BigEndian.Uint64(hdr[1:])
		// Anything arriving proves the carrier is alive. The peer's ACKs queue
		// behind whatever it is sending us, so on a busy thin link they can be
		// seconds late without anything being wrong.
		s.mu.Lock()
		if s.gen == gen {
			s.progressAt = time.Now()
		}
		s.mu.Unlock()
		switch hdr[0] {
		case frameData:
			if _, err := io.ReadFull(c, hdr[hdrLen:hdrLen+2]); err != nil {
				s.carrierLost(c, gen)
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[hdrLen:]))
			if _, err := io.ReadFull(c, payload[:n]); err != nil {
				s.carrierLost(c, gen)
				return
			}
			s.mu.Lock()
			if s.gen != gen {
				s.mu.Unlock()
				return
			}
			end := off + uint64(n)
			switch {
			case end <= s.recvOff:
				// duplicate from before a resume; ignore
			case off > s.recvOff:
				s.failLocked(errProtocol)
				s.mu.Unlock()
				return
			default:
				fresh := payload[s.recvOff-off : n]
				if !s.readClosed {
					if len(s.recvBuf)+len(fresh) > 2*window {
						// The peer ignored the window; never buffer without bound.
						s.failLocked(errProtocol)
						s.mu.Unlock()
						return
					}
					s.recvBuf = append(s.recvBuf, fresh...)
				}
				s.recvOff = end
				if s.peerFin && s.recvOff == s.peerFinOff {
					s.ackFlush = true // let the peer finish promptly
				}
				s.scheduleAckLocked()
				s.cond.Broadcast()
			}
			s.mu.Unlock()
		case frameAck:
			if _, err := io.ReadFull(c, hdr[hdrLen:ackLen]); err != nil {
				s.carrierLost(c, gen)
				return
			}
			cons := binary.BigEndian.Uint64(hdr[hdrLen:])
			s.mu.Lock()
			if s.gen == gen {
				if off > s.sendBase {
					s.progressAt = time.Now()
				}
				s.trimLocked(off)
				if cons > s.peerConsumed && cons <= s.sendBase+uint64(len(s.sendBuf)) {
					s.peerConsumed = cons
					s.cond.Broadcast()
				}
				s.maybeFinishLocked()
			}
			s.mu.Unlock()
		case frameFin:
			s.mu.Lock()
			if s.gen == gen {
				s.peerFin = true
				s.peerFinOff = off
				if s.recvOff == off {
					s.ackFlush = true
				}
				s.scheduleAckLocked()
				s.cond.Broadcast()
			}
			s.mu.Unlock()
		default:
			s.mu.Lock()
			s.failLocked(errProtocol)
			s.mu.Unlock()
			return
		}
	}
}

// carrierLost handles an I/O failure on carrier c: if it is still current,
// detach and wait for a resume.
func (s *Stream) carrierLost(c net.Conn, gen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen || s.carrier != c {
		return
	}
	s.dropCarrierLocked()
	s.armResumeTimerLocked()
	s.cond.Broadcast()
	if s.onCarrierLost != nil && !s.closed {
		go s.onCarrierLost()
	}
}

// Attached reports whether a carrier is currently attached.
func (s *Stream) Attached() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.carrier != nil
}

// net.Conn plumbing.

func (s *Stream) LocalAddr() net.Addr  { return addr{} }
func (s *Stream) RemoteAddr() net.Addr { return addr{} }

func (s *Stream) SetDeadline(t time.Time) error { return s.SetReadDeadline(t) }
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}
func (s *Stream) SetWriteDeadline(time.Time) error { return nil }

type addr struct{}

func (addr) Network() string { return "rstream" }
func (addr) String() string  { return "rstream" }

type timeoutError struct{}

func (timeoutError) Error() string   { return "rstream: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
