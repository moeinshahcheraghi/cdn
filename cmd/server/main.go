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
	"strings"
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
	if cfg.WS.Path != "" {
		srv.SetWebSocketPath(cfg.WS.Path)
		logx.Infof("websocket and http carriers on %s (for CDN clients)", cfg.WS.Path)
	}
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
		rc.Show = cfg.Log == "debug" // library-level trace of each handshake
		srv.SetReality(rc)
		logx.Infof("reality mode: imitating %s (sni %v)", cfg.Reality.Dest, cfg.Reality.ServerNames)
	}

	// The main address may list several ports ("443,8443"): a censor that
	// blocks one port, or a datacenter that filters it, does not take the
	// server down, and clients can be pointed at another without a redeploy.
	var listeners []net.Listener
	for _, addr := range splitAddrs(cfg.Listen) {
		ln, err := transport.Listen(addr)
		if err != nil {
			logx.Errorf("listen %s: %v", addr, err)
			os.Exit(1)
		}
		listeners = append(listeners, ln)
		logx.Infof("server listening on %s, fallback -> %s", addr, cfg.Fallback)
		go acceptLoop(ln, srv.Handle)
	}
	// In REALITY mode the main port cannot also serve a CDN, which needs a
	// real certificate for the domain. ws.listen is that second door.
	if cfg.WS.Listen != "" {
		cs := srv.CertHandler()
		for _, addr := range splitAddrs(cfg.WS.Listen) {
			ln, err := transport.Listen(addr)
			if err != nil {
				logx.Errorf("listen %s: %v", addr, err)
				os.Exit(1)
			}
			listeners = append(listeners, ln)
			logx.Infof("websocket/CDN listener on %s (certificate TLS)", addr)
			go acceptLoop(ln, cs.Handle)
		}
	}
	if cfg.ACME.Domain != "" {
		logx.Infof("acme certificate for %s (cache %s)", cfg.ACME.Domain, cfg.ACME.CacheDir)
	}

	waitForSignal()
	logx.Infof("shutting down")
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

// acceptLoop hands every accepted connection to handle.
func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn)
	}
}

// splitAddrs parses a comma-separated address list.
func splitAddrs(v string) []string {
	var out []string
	for _, a := range strings.Split(v, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
