package tunnel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/transport"
)

// Auto IP keeps new connections on one CDN address and replaces it only when
// it has a real problem and another address does not. It is deliberately
// reluctant, because switching away from a working path for the wrong reason is
// worse than doing nothing:
//
//   - Users are never moved by it. A switch only changes where new connections
//     go; streams follow as their connections retire in the usual rotation, and
//     the existing stall handling still rescues any stream that gets stuck.
//   - Traffic signals only prompt a test. Nothing changes unless a fresh
//     connection through the current address fails while another succeeds, so
//     a problem shared by every address (the local link, the origin) and one
//     cut flow both leave it where it is.
//   - It costs almost nothing: one test connection per address every
//     autoRoundEvery, one through the current address when a connection stalls,
//     and the others only if that one fails or stalls keep coming.
var (
	autoRoundEvery  = newTunable(30 * time.Minute) // routine check of all addresses
	autoTestTimeout = newTunable(5 * time.Second)  // one test connection
	autoEvalGap     = newTunable(20 * time.Second) // least time between rounds
	autoMaxEvalGap  = newTunable(5 * time.Minute)  // when rounds keep changing nothing
	autoConfirmGap  = newTunable(time.Second)      // before retesting a failure
	autoHeavyWindow = newTunable(2 * time.Minute)
	autoMinHold     = newTunable(5 * time.Minute) // after switching for heavy stalls
)

const (
	autoHeavyStalls = 6 // within autoHeavyWindow
	autoMaxHold     = 30 * time.Minute
	// autoTestUpload is what a test sends before asking for its answer. Censors
	// have let handshakes and small requests through and cut uploads at 64 KB.
	autoTestUpload = 128 << 10
	// autoWorseFactor is how much slower a test may be than the current address
	// and still be worth switching to when the current address merely stalls.
	autoWorseFactor = 1.5
)

type autoIP struct {
	c   *Client
	eps []*transport.Endpoint

	kick chan struct{}

	mu        sync.Mutex
	stalls    []time.Time
	holdUntil time.Time // heavy-stall switches wait until then
	hold      time.Duration
}

// testResult is one test connection through one address.
type testResult struct {
	ep   *transport.Endpoint
	took time.Duration
	err  error
}

func (r testResult) ok() bool { return r.err == nil }

func newAutoIP(c *Client) *autoIP {
	a := &autoIP{c: c, kick: make(chan struct{}, 1)}
	for _, ep := range c.dialer.Endpoints() {
		if ep.Tier == 0 {
			a.eps = append(a.eps, ep)
		}
	}
	c.dialer.SetActive(a.eps[0])
	logx.Infof("auto ip: %d addresses, starting on %s", len(a.eps), a.eps[0].Server)
	go a.run()
	return a
}

// noteStall records that a connection through ep went silent.
func (a *autoIP) noteStall(ep *transport.Endpoint) {
	if ep != a.c.dialer.Active() {
		return
	}
	now := time.Now()
	a.mu.Lock()
	a.stalls = append(a.stalls, now)
	recent := a.stalls[:0]
	for _, t := range a.stalls {
		if now.Sub(t) <= autoHeavyWindow.get() {
			recent = append(recent, t)
		}
	}
	a.stalls = recent
	a.mu.Unlock()
	a.c.dialer.Suspect()
	a.wake()
}

// noteFailure records that a new connection could not be made or proven.
func (a *autoIP) noteFailure() { a.wake() }

func (a *autoIP) wake() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

func (a *autoIP) run() {
	routine := time.NewTimer(0) // once at start, so a bad address shows up in the log
	defer routine.Stop()
	gap := autoEvalGap.get()
	var last time.Time
	for {
		full := false
		select {
		case <-a.c.done:
			return
		case <-routine.C:
			routine.Reset(autoRoundEvery.get())
			full = true
		case <-a.kick:
		}
		if wait := time.Until(last.Add(gap)); !last.IsZero() && wait > 0 {
			// Too soon after the last round. Come back rather than forget: the
			// trouble that asked for this may still be there.
			select {
			case <-a.c.done:
				return
			case <-time.After(wait):
			}
		}
		ok := a.round(full)
		if !full { // the routine round must not delay one that is needed
			last = time.Now()
		}
		if ok {
			gap = autoEvalGap.get()
		} else {
			gap = min(2*gap, autoMaxEvalGap.get())
		}
	}
}

// round checks the current address and, if that is not enough to settle things,
// all the others, then switches if that is justified. It reports whether things
// are in order: the current address works, or was replaced.
func (a *autoIP) round(full bool) bool {
	current := a.c.dialer.Active()
	first := a.test(current)
	heavy, held := a.pressure()
	if first.ok() && !full && !heavy {
		return true
	}
	if !first.ok() {
		select { // a moment before looking again; flows get swallowed at random
		case <-a.c.done:
			return false
		case <-time.After(autoConfirmGap.get()):
		}
	}
	results := a.testAll(a.eps)
	logx.Infof("auto ip: tested %s", describe(results, current))
	var again testResult
	for _, r := range results {
		if r.ep == current {
			again = r
		}
	}
	best, found := bestOther(results, current)
	switch decide(first, again, best, found, heavy, held) {
	case switchFailing:
		a.switchTo(best.ep, fmt.Sprintf("%s failed two tests in a row (%v)", current.Server, again.err))
		return true
	case switchStalling:
		a.switchTo(best.ep, fmt.Sprintf("connections through %s keep stalling", current.Server))
		a.startHold()
		return true
	}
	return again.ok()
}

type verdict int

const (
	keep verdict = iota
	switchFailing
	switchStalling
)

// decide is the whole policy. first and again are two tests of the current
// address, best the best other one if found. heavy means connections through
// the current address keep stalling; held means a recent switch for that reason
// is still being given time to prove itself.
func decide(first, again, best testResult, found, heavy, held bool) verdict {
	if !found {
		return keep // nowhere better to go, whatever is wrong
	}
	if !first.ok() && !again.ok() {
		return switchFailing
	}
	if !again.ok() {
		return keep // one failure proves little
	}
	if heavy && !held && float64(best.took) <= autoWorseFactor*float64(again.took) {
		return switchStalling
	}
	return keep
}

// bestOther picks the fastest address other than current that passed.
func bestOther(results []testResult, current *transport.Endpoint) (testResult, bool) {
	var best testResult
	found := false
	for _, r := range results {
		if r.ep != current && r.ok() && (!found || r.took < best.took) {
			best, found = r, true
		}
	}
	return best, found
}

func (a *autoIP) pressure() (heavy, held bool) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, t := range a.stalls {
		if now.Sub(t) <= autoHeavyWindow.get() {
			n++
		}
	}
	return n >= autoHeavyStalls, now.Before(a.holdUntil)
}

// startHold keeps heavy stalls from causing another switch for a while, longer
// each time, since they evidently did not come from the address. A failing
// address can still be replaced at any time.
func (a *autoIP) startHold() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hold = min(max(2*a.hold, autoMinHold.get()), autoMaxHold)
	a.holdUntil = time.Now().Add(a.hold)
}

func (a *autoIP) switchTo(ep *transport.Endpoint, why string) {
	logx.Warnf("auto ip: moving new connections to %s: %s", ep.Server, why)
	a.c.dialer.SetActive(ep)
	a.mu.Lock()
	a.stalls = nil
	a.mu.Unlock()
	a.c.wake() // make a ready connection on the new address right away
}

func (a *autoIP) testAll(eps []*transport.Endpoint) []testResult {
	out := make([]testResult, len(eps))
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = a.test(ep)
		}()
	}
	wg.Wait()
	return out
}

// test makes a real connection through ep, the way a user's would be made, and
// proves data crosses it both ways. It never joins the pool.
func (a *autoIP) test(ep *transport.Endpoint) testResult {
	limit := autoTestTimeout.get()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	t0 := time.Now()
	fail := func(err error) testResult { return testResult{ep: ep, took: time.Since(t0), err: err} }
	conn, err := a.c.dialer.DialEndpoint(ctx, ep, "")
	if err != nil {
		return fail(err)
	}
	ms, err := a.c.sessionOver(conn)
	if err != nil {
		conn.Close()
		return fail(err)
	}
	defer ms.Close()
	_ = conn.SetDeadline(t0.Add(limit))
	if err := ms.pc.WritePadding(autoTestUpload); err != nil {
		return fail(err)
	}
	if err := ms.probeWithin(time.Until(t0.Add(limit))); err != nil {
		return fail(err)
	}
	return testResult{ep: ep, took: time.Since(t0)}
}

func describe(results []testResult, current *transport.Endpoint) string {
	var b strings.Builder
	for i, r := range results {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(r.ep.Server)
		if r.ep == current {
			b.WriteString(" (current)")
		}
		if r.ok() {
			fmt.Fprintf(&b, " ok %v", r.took.Round(time.Millisecond))
		} else {
			fmt.Fprintf(&b, " failed after %v", r.took.Round(time.Millisecond))
		}
	}
	return b.String()
}
