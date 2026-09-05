// Command client runs local SOCKS5/HTTP proxies and tunnels their traffic to
// the server inside browser-looking TLS.
package main

import (
	"context"
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
	"github.com/moeinshah0/tunnel/internal/tunnel"
)

func main() {
	cfgPath := flag.String("c", "client.json", "path to client config JSON")
	flag.Parse()

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	logx.SetLevel(cfg.Log)

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
