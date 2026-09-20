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
//	ACK   0x02 | offset u64
//	FIN   0x03 | offset u64            (no more data after offset)
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
	maxPayload = 32 * 1024

	// window bounds unacknowledged bytes the sender holds for retransmission;
	// a writer blocks when it is full.
	window = 4 << 20
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
	sendBuf  []byte // bytes [sendBase, sendBase+len) awaiting acknowledgement
	sendBase uint64
	sentOff  uint64 // next offset to transmit on the current carrier
	finOff   uint64 // valid when writeClosed
	finSent  bool   // FIN transmitted on the current carrier

	// receive side.
	recvBuf    []byte
	recvOff    uint64 // next expected offset
	peerFin    bool
	peerFinOff uint64
	lastAcked  uint64 // recvOff last acknowledged to the peer
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

	readDeadline time.Time
	onClose      func()
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

// Attach starts carrying the stream over c, transmitting from peerRecvOff,
// the offset the peer reports having received. Any previous carrier is
// dropped. It fails if the peer asks for bytes no longer buffered.
func (s *Stream) Attach(c net.Conn, peerRecvOff uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if peerRecvOff < s.sendBase || peerRecvOff > s.sendBase+uint64(len(s.sendBuf)) {
		return errors.New("rstream: peer offset outside retransmit window")
	}
	s.dropCarrierLocked()
	// Everything up to peerRecvOff is acknowledged by implication.
	s.trimLocked(peerRecvOff)
	s.carrier = c
	s.gen++
	s.sentOff = peerRecvOff
	s.finSent = false
	s.lastAcked = 0 // resend our ACK too, so the peer can trim
	s.scheduleAckLocked()
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
		s.carrier.Close()
		s.carrier = nil
		s.gen++ // invalidates loops
	}
}

func (s *Stream) armResumeTimerLocked() {
	if s.closed || s.carrier != nil || s.resumeTimer != nil {
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
		room := window - len(s.sendBuf)
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
	var hdr [hdrLen + 2]byte
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
			binary.BigEndian.PutUint64(hdr[1:], s.recvOff)
			s.lastAcked = s.recvOff
			s.ackFlush = false
			if s.ackTimer != nil {
				s.ackTimer.Stop()
				s.ackTimer = nil
			}
			frame = append([]byte(nil), hdr[:hdrLen]...)
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

// ackReadyLocked reports whether an ACK should go out now: a large amount
// of unacknowledged data, or the delayed-ACK timer fired.
func (s *Stream) ackReadyLocked() bool {
	if s.recvOff <= s.lastAcked {
		return false
	}
	return s.recvOff-s.lastAcked >= ackEvery || s.ackFlush
}

// scheduleAckLocked arms the delayed-ACK timer for the tail of a burst.
func (s *Stream) scheduleAckLocked() {
	if s.ackTimer != nil || s.recvOff <= s.lastAcked || s.closed {
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
	var hdr [hdrLen + 2]byte
	payload := make([]byte, maxPayload)
	for {
		if _, err := io.ReadFull(c, hdr[:hdrLen]); err != nil {
			s.carrierLost(c, gen)
			return
		}
		off := binary.BigEndian.Uint64(hdr[1:])
		switch hdr[0] {
		case frameData:
			if _, err := io.ReadFull(c, hdr[hdrLen:]); err != nil {
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
			s.mu.Lock()
			if s.gen == gen {
				s.trimLocked(off)
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
