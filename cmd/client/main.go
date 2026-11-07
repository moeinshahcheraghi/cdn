// Command client runs local SOCKS5/HTTP proxies and tunnels their traffic to
// the server inside browser-looking TLS.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/protocol"
	"github.com/moeinshah0/tunnel/internal/relay"
	"github.com/moeinshah0/tunnel/internal/socks"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/moeinshah0/tunnel/internal/tunnel"
)

func main() {
	cfgPath := flag.String("c", "client.json", "path to client config JSON")
	diag := flag.Bool("diag", false, "test connectivity to the server(s) and exit")
	diagEcho := flag.String("diag-echo", "", "host:port of a TCP echo service you control on the exit side; enables verified bulk transfer with -diag")
	diagBytes := flag.Int64("diag-bytes", 1<<20, "bytes to send and verify with -diag-echo")
	diagTimeout := flag.Duration("diag-timeout", 30*time.Second, "time limit for opening and testing the bulk echo stream")
	flag.Parse()
	if *diagBytes <= 0 || *diagTimeout <= 0 || (*diagEcho != "" && !*diag) {
		fmt.Fprintln(os.Stderr, "diagnostic sizes and timeouts must be positive; -diag-echo requires -diag")
		os.Exit(2)
	}

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	logx.SetLevel(cfg.Log)
	if *diag {
		os.Exit(runDiag(cfg, *diagEcho, *diagBytes, *diagTimeout))
	}

	client := tunnel.NewClient(cfg)
	defer client.Close()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client.Warm(ctx)
	}()

	var listeners []net.Listener
	for _, addr := range dedupe(cfg.SocksListen, cfg.HTTPListen) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			logx.Errorf("listen %s: %v", addr, err)
			os.Exit(1)
		}
		listeners = append(listeners, ln)
		logx.Infof("local proxy (socks5+http) on %s -> %s", addr, cfg.Server)
		go acceptLoop(ln, client)
	}

	for _, f := range cfg.Forwards {
		target, err := parseTarget(f.Target)
		if err != nil {
			logx.Errorf("forward %s: %v", f.Listen, err)
			os.Exit(1)
		}
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			logx.Errorf("listen %s: %v", f.Listen, err)
			os.Exit(1)
		}
		listeners = append(listeners, ln)
		logx.Infof("port forward %s -> %s (via %s)", f.Listen, f.Target, cfg.Server)
		go forwardLoop(ln, client, target)
	}

	waitForSignal()
	logx.Infof("shutting down")
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

// acceptLoop negotiates each inbound connection and tunnels it.
func acceptLoop(ln net.Listener, client *tunnel.Client) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn, client)
	}
}

// runDiag reports, stage by stage, whether and how fast each route can be
// reached. Failures locate a stage; they do not establish filtering as the cause.
func runDiag(cfg *config.ClientConfig, echoTarget string, probeBytes int64, probeTimeout time.Duration) int {
	if echoTarget != "" {
		if _, err := parseTarget(echoTarget); err != nil {
			fmt.Printf("bulk echo: invalid target: %v\n", err)
			return 1
		}
	}
	eps := tunnel.Endpoints(cfg)
	fmt.Printf("clock: %s\n", time.Now().Format(time.RFC1123))
	for _, fp := range transport.Fingerprints {
		fmt.Printf("  clienthello %-8s %5d bytes%s\n", fp, transport.HelloSize(fp, cfg.SNI),
			map[bool]string{true: "  (over one packet: some censors drop it)"}[transport.HelloSize(fp, cfg.SNI) > 1400])
	}
	d := transport.NewDialer(eps)
	failed, worked := 0, 0
	for _, ep := range d.Endpoints() {
		fmt.Printf("endpoint %s tier=%d\n", ep, ep.Tier)
		if f := ep.Fragment; f != nil {
			fmt.Printf("  fragment: %s, pieces of %d-%d bytes, %v-%v apart\n", f, f.MinSize, f.MaxSize, f.MinDelay, f.MaxDelay)
		}
		fps := append([]string{ep.Fingerprint}, transport.Fingerprints...)
		seen := map[string]bool{}
		for _, fp := range fps {
			if seen[fp] {
				continue
			}
			seen[fp] = true
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			tcp, hs, err := d.Probe(ctx, ep, fp)
			cancel()
			switch {
			case err != nil && hs == 0:
				fmt.Printf("  %-8s TCP connect FAILED after %v: %v\n", fp, tcp.Round(time.Millisecond), err)
				failed++
			case err != nil:
				fmt.Printf("  %-8s tcp %v, handshake FAILED after %v: %v\n", fp, tcp.Round(time.Millisecond), hs.Round(time.Millisecond), err)
				failed++
			default:
				fmt.Printf("  %-8s tcp %v, handshake ok %v\n", fp, tcp.Round(time.Millisecond), hs.Round(time.Millisecond))
				worked++
			}
		}
		// A wrong local clock makes REALITY reject every handshake while
		// nothing is actually blocked; name it rather than leave it a mystery.
		if ep.Reality != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			remote, err := transport.RemoteTime(ctx, d.TCPDialer(), ep)
			cancel()
			if err == nil {
				if skew := time.Until(remote); skew > 30*time.Second || skew < -30*time.Second {
					fmt.Printf("  CLOCK is off by %v — REALITY tokens are time-bound; run: timedatectl set-ntp true\n", (-skew).Round(time.Second))
				} else {
					fmt.Printf("  clock agrees with %s (%v)\n", ep.SNI, skew.Round(time.Second))
				}
			} else {
				// This is a plain HTTPS request that the server splices to the
				// real site. Failing after a good handshake means data is cut.
				fmt.Printf("  plain HTTPS to %s through this route FAILED: %v\n", ep.SNI, err)
			}
		}
	}
	if worked == 0 {
		fmt.Printf("\nNo route completed a handshake. Check reachability, TLS settings, keys, and server logs; this does not establish IP blocking.\n")
		return 1
	}
	// Full tunnel check with the configured settings: a stream that the
	// server can open to its target stays up; a refused password or an
	// unreachable target closes it.
	target := "1.1.1.1:443"
	if len(cfg.Forwards) > 0 {
		target = cfg.Forwards[0].Target
	}
	if echoTarget != "" {
		target = echoTarget
	}
	addr, err := parseTarget(target)
	if err != nil {
		fmt.Printf("tunnel check: bad target %s\n", target)
		return 1
	}
	c := tunnel.NewClient(cfg)
	defer c.Close()
	openTimeout := 20 * time.Second
	if echoTarget != "" {
		openTimeout = probeTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	t0 := time.Now()
	st, err := c.OpenStream(ctx, addr)
	if err != nil {
		fmt.Printf("tunnel check: open stream to %s FAILED: %v\n", target, err)
		return 1
	}
	defer st.Close()
	if echoTarget != "" {
		result, err := probeEcho(ctx, st, probeBytes)
		fmt.Printf("bulk echo via configured routes (including failover): target=%s queued=%d echoed=%d expected=%d elapsed=%v\n",
			target, result.sent, result.received, probeBytes, time.Since(t0).Round(time.Millisecond))
		if err != nil {
			fmt.Printf("bulk echo FAILED: %v. Check the echo service, server logs, and route; this test does not identify DPI or a whitelist.\n", err)
			return 1
		}
		fmt.Printf("bulk echo PASSED: payload integrity verified in both directions for this transfer size. Larger or longer transfers may behave differently.\n")
		return failed
	}
	opened := time.Since(t0)
	// An open stream proves only the handshake. A censor that lets the
	// handshake through and then drops everything leaves the stream looking
	// open, so push real bytes and wait for the server to acknowledge them.
	if acker, ok := st.(interface{ Acked() uint64 }); ok {
		probe := make([]byte, 16<<10)
		_, _ = rand.Read(probe)
		t1 := time.Now()
		if _, err := st.Write(probe); err != nil {
			fmt.Printf("tunnel check: write FAILED: %v\n", err)
			return 1
		}
		for acker.Acked() < uint64(len(probe)) {
			if time.Since(t1) > 10*time.Second {
				fmt.Printf("tunnel check: 16 KB probe not fully acknowledged in 10s (acked=%d).\n", acker.Acked())
				fmt.Printf("  Possible causes include authentication, target availability, server faults, or route restrictions. Inspect server logs and use -diag-echo with a TCP echo service you control.\n")
				st.Close()
				return 1
			}
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Printf("tunnel check: only 16 KB acknowledged by the tunnel peer in %v; target delivery, downloads, and sustained transfer are unverified. Use -diag-echo for a bulk test.\n", time.Since(t1).Round(time.Millisecond))
		st.Close()
		return failed
	}
	_ = st.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, rerr := st.Read(buf)
	st.Close()
	if rerr != nil {
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			fmt.Printf("tunnel check: stream to %s idle for 3s (%v to open); data delivery is inconclusive. Use -diag-echo for a verified transfer.\n", target, opened.Round(time.Millisecond))
			return 1
		}
		fmt.Printf("tunnel check: stream to %s closed by server: %v (wrong password/keys, or target down)\n", target, rerr)
		return 1
	}
	fmt.Printf("tunnel check: stream to %s OK, target spoke first (%v to open)\n", target, opened.Round(time.Millisecond))
	return failed
}

// forwardLoop tunnels every connection accepted on ln to a fixed target.
func forwardLoop(ln net.Listener, client *tunnel.Client, target protocol.Address) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetNoDelay(true)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			stream, err := client.OpenStream(ctx, target)
			cancel()
			if err != nil {
				logx.Warnf("client: forward to %s: %v", target, err)
				conn.Close()
				return
			}
			logx.Debugf("client: forward %s -> %s", conn.RemoteAddr(), target)
			relay.Pipe(conn, stream)
			conn.Close()
			stream.Close()
		}()
	}
}

// parseTarget turns host:port into a tunnel address.
func parseTarget(hostport string) (protocol.Address, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return protocol.Address{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return protocol.Address{}, fmt.Errorf("bad port %q", portStr)
	}
	return protocol.NewAddress(host, port), nil
}

// handle turns one local connection into a tunneled stream.
func handle(conn net.Conn, client *tunnel.Client) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	req, err := socks.Accept(conn)
	if err != nil {
		logx.Debugf("client: inbound: %v", err)
		conn.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	stream, err := client.OpenStream(ctx, req.Target)
	cancel()
	if err != nil {
		logx.Warnf("client: open stream to %s: %v", req.Target, err)
		req.Conn.Close()
		return
	}
	logx.Debugf("client: %s -> %s", conn.RemoteAddr(), req.Target)
	relay.Pipe(req.Conn, stream)
	req.Conn.Close()
	stream.Close()
}

// dedupe returns the non-empty, unique addresses among the inputs.
func dedupe(addrs ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
