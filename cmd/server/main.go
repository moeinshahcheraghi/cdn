// Command server is the tunnel exit node. It terminates browser-looking TLS,
// authenticates clients, and relays their traffic; unauthenticated peers are
// transparently served a real website so the port looks like plain HTTPS.
package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/fallback"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/moeinshah0/tunnel/internal/tunnel"
)

func main() {
	cfgPath := flag.String("c", "server.json", "path to server config JSON")
	flag.Parse()

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	logx.SetLevel(cfg.Log)

	sni := ""
	if h, _, e := net.SplitHostPort(cfg.Listen); e == nil {
		sni = h
	}
	tlsCfg, err := transport.NewServerTLSConfig(cfg.TLSCert, cfg.TLSKey, sni)
	if err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}

	srv := tunnel.NewServer(tlsCfg, cfg.Passwords, fallback.New(cfg.Fallback))

	ln, err := transport.Listen(cfg.Listen)
	if err != nil {
		logx.Errorf("listen %s: %v", cfg.Listen, err)
		os.Exit(1)
	}
	logx.Infof("server listening on %s, fallback -> %s", cfg.Listen, cfg.Fallback)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				logx.Errorf("accept: %v", err)
				return
			}
			go srv.Handle(conn)
		}
	}()

	waitForSignal()
	logx.Infof("shutting down")
	_ = ln.Close()
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
