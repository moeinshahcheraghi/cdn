package httpconn

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxAhead is how far past the next expected upload a request may be. The
// client never has more than maxInflight outstanding, so anything further
// ahead is not ours.
const maxAhead = 4 * maxInflight

// Hub tracks the server side of HTTP sessions. Every new session is handed
// to serve as a net.Conn, exactly like an accepted connection.
type Hub struct {
	serve func(net.Conn)

	mu       sync.Mutex
	sessions map[string]*session
}

// NewHub returns a Hub that runs serve for each new session.
func NewHub(serve func(net.Conn)) *Hub {
	return &Hub{serve: serve, sessions: map[string]*session{}}
}

// Handle serves r if it is a tunnel request, rest being the part of the path
// after the secret path and its slash. It reports false, having written
// nothing, for anything else; the caller then serves its website.
func (h *Hub) Handle(w http.ResponseWriter, r *http.Request, rest string) bool {
	id, seq, hasSeq := strings.Cut(rest, "/")
	if !validID(id) {
		return false
	}
	switch {
	case r.Method == http.MethodGet && !hasSeq:
		s := h.open(id, r)
		if s == nil {
			return false
		}
		s.serveDownload(w, r)
		return true
	case r.Method == http.MethodPost && hasSeq:
		n, err := strconv.ParseUint(seq, 10, 64)
		if err != nil {
			return false
		}
		h.mu.Lock()
		s := h.sessions[id]
		h.mu.Unlock()
		if s == nil {
			return false
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPost+1))
		if err != nil {
			s.abort()
			http.Error(w, "", http.StatusBadRequest)
			return true
		}
		if len(body) > maxPost {
			s.abort()
			http.Error(w, "", http.StatusRequestEntityTooLarge)
			return true
		}
		if err := s.push(n, body); err != nil {
			s.abort()
			http.Error(w, "", http.StatusBadRequest)
			return true
		}
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

// validID accepts exactly the session ids our client makes: 32 hex digits.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// open registers a new session, or returns nil if id is already taken.
func (h *Hub) open(id string, r *http.Request) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions[id] != nil {
		return nil
	}
	remote := r.Header.Get("CF-Connecting-IP")
	if remote == "" {
		remote = r.RemoteAddr
	}
	s := &session{
		hub: h, id: id, remote: addr(remote),
		up:      newBuffer(bufLimit),
		down:    newBuffer(bufLimit),
		pending: map[uint64][]byte{},
	}
	h.sessions[id] = s
	return s
}

// session is one tunnel connection made of HTTP requests.
type session struct {
	hub    *Hub
	id     string
	remote addr

	up   *buffer // uploads, in order -> Read
	down *buffer // Write -> download

	rmu     sync.Mutex // orders uploads
	next    uint64
	pending map[uint64][]byte

	closeOnce sync.Once
}

// serveDownload streams the server's direction as the GET response for the
// life of the session.
func (s *session) serveDownload(w http.ResponseWriter, r *http.Request) {
	flusher, _ := w.(http.Flusher)
	h := w.Header()
	// An event stream is what CDNs pass through unbuffered; no-transform
	// keeps them from compressing it, which would buffer it too.
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	go s.hub.serve(s)

	// The client going away cancels the request; that ends the session.
	// Returning normally cancels it too, which must not count.
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		<-r.Context().Done()
		select {
		case <-finished:
		default:
			s.abort()
		}
	}()

	for {
		chunk, err := s.down.Next(64 << 10)
		if err != nil {
			return // io.EOF: CloseWrite; anything else: closed
		}
		if _, err := w.Write(chunk); err != nil {
			s.abort()
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// push delivers upload seq, holding it back until every earlier one has
// arrived. It blocks while the reader is behind, which is what slows the
// client down.
func (s *session) push(seq uint64, data []byte) error {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if seq < s.next {
		return nil // a duplicate; already delivered
	}
	if seq-s.next > maxAhead {
		return fmt.Errorf("httpconn: upload %d too far ahead of %d", seq, s.next)
	}
	s.pending[seq] = data
	for {
		d, ok := s.pending[s.next]
		if !ok {
			return nil
		}
		delete(s.pending, s.next)
		s.next++
		if len(d) == 0 {
			s.up.CloseWrite()
			continue
		}
		if _, err := s.up.Write(d); err != nil {
			return err
		}
	}
}

func (s *session) Read(p []byte) (int, error)  { return s.up.Read(p) }
func (s *session) Write(p []byte) (int, error) { return s.down.Write(p) }

// CloseWrite ends the download response after the bytes already written.
func (s *session) CloseWrite() error {
	s.down.CloseWrite()
	return nil
}

// Close ends the session the way closing a socket does: what was already
// written is still delivered, and the download then ends.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.up.Close(errClosed)
		s.down.CloseWrite()
		s.hub.mu.Lock()
		if s.hub.sessions[s.id] == s {
			delete(s.hub.sessions, s.id)
		}
		s.hub.mu.Unlock()
	})
	return nil
}

// abort ends the session at once, dropping anything not yet sent; for a
// client that is gone or a request stream that broke.
func (s *session) abort() {
	s.down.Close(errClosed)
	s.Close()
}

func (s *session) LocalAddr() net.Addr  { return addr("httpconn") }
func (s *session) RemoteAddr() net.Addr { return s.remote }

func (s *session) SetDeadline(t time.Time) error {
	s.up.SetReadDeadline(t)
	s.down.SetWriteDeadline(t)
	return nil
}

func (s *session) SetReadDeadline(t time.Time) error {
	s.up.SetReadDeadline(t)
	return nil
}

func (s *session) SetWriteDeadline(t time.Time) error {
	s.down.SetWriteDeadline(t)
	return nil
}

// addr is a net.Addr for a peer known only by a string.
type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }
