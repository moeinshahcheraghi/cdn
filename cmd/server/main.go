// Command server is the tunnel exit node. It terminates browser-looking TLS,
// authenticates clients, and relays their traffic; unauthenticated peers are
// transparently served a real website so the port looks like plain HTTPS.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moeinshah0/tunnel/internal/config"
	"github.com/moeinshah0/tunnel/internal/fallback"
	"github.com/moeinshah0/tunnel/internal/logx"
	"github.com/moeinshah0/tunnel/internal/transport"
	"github.com/moeinshah0/tunnel/internal/tunnel"
)

func main() {
	cfgPath := flag.String("c", "server.json", "path to server config JSON")
	keygen := flag.Bool("keygen", false, "print a new REALITY key pair and exit")
	flag.Parse()
	if *keygen {
		priv, pub, err := transport.GenerateRealityKeys()
		if err != nil {
			logx.Errorf("keygen: %v", err)
			os.Exit(1)
		}
		fmt.Printf("private_key (server): %s\npublic_key  (client): %s\n", priv, pub)
		return
	}

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	logx.SetLevel(cfg.Log)

	sni := cfg.ACME.Domain
	if sni == "" {
		if h, _, e := net.SplitHostPort(cfg.Listen); e == nil {
			sni = h
		}
	}
	acme := &transport.ACME{Domain: cfg.ACME.Domain, Email: cfg.ACME.Email, CacheDir: cfg.ACME.CacheDir}
	tlsCfg, err := transport.NewServerTLSConfig(cfg.TLSCert, cfg.TLSKey, sni, acme)
	if err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}

	srv := tunnel.NewServer(tlsCfg, cfg.Passwords, fallback.New(cfg.Fallback))
	if cfg.Reality.Dest != "" {
		rc, err := transport.NewRealityConfig(&transport.RealityServer{
			Dest: cfg.Reality.Dest, ServerNames: cfg.Reality.ServerNames,
			PrivateKey: cfg.Reality.PrivateKey, ShortIDs: cfg.Reality.ShortIDs,
			MaxTimeDiff: time.Duration(cfg.Reality.MaxTimeDiff) * time.Second,
		})
		if err != nil {
			logx.Errorf("%v", err)
			os.Exit(1)
		}
		srv.SetReality(rc)
		logx.Infof("reality mode: imitating %s (sni %v)", cfg.Reality.Dest, cfg.Reality.ServerNames)
	}

	ln, err := transport.Listen(cfg.Listen)
	if err != nil {
		logx.Errorf("listen %s: %v", cfg.Listen, err)
		os.Exit(1)
	}
	logx.Infof("server listening on %s, fallback -> %s", cfg.Listen, cfg.Fallback)
	if cfg.ACME.Domain != "" {
		logx.Infof("acme certificate for %s (cache %s)", cfg.ACME.Domain, cfg.ACME.CacheDir)
	}

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
