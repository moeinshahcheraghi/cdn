# tunnel

A high-performance, DPI-resistant tunnel. Traffic travels inside a genuine
TLS 1.3 session whose ClientHello is copied from a real browser, so deep packet
inspection sees only ordinary HTTPS. The server behaves like a real web server
to anyone who is not an authenticated client, defeating active probing. There is
no bandwidth cap; multiplexing and NoDelay keep latency low.

یک تانل پرسرعت و مقاوم در برابر DPI. ترافیک داخل یک نشست واقعی TLS 1.3 حرکت می‌کند
که اثرانگشت آن دقیقاً مثل مرورگر کروم است، پس DPI فقط یک HTTPS معمولی می‌بیند.
سرور برای هر کسی که کلاینت معتبر نباشد مثل یک وب‌سایت واقعی رفتار می‌کند و
active probing را خنثی می‌کند. محدودیت پهنای‌باند وجود ندارد.

## How it resists DPI

| Censor technique | Countermeasure |
| --- | --- |
| TLS fingerprinting (JA3/JA4) | uTLS copies a real Chrome/Firefox/Safari ClientHello |
| SNI blocking | You set the SNI to your own (or an allowed) domain |
| Active probing | Wrong-auth connections are reverse-proxied to a real site |
| Protocol/entropy analysis | It *is* real TLS 1.3, not an obfuscated stream |
| Throughput/latency shaping | smux multiplexing, TCP NoDelay, BBR, no rate limit |
| TLS-in-TLS record-size shape | payload is framed and randomly padded, so the tell-tale handshake/keepalive record sizes are hidden |
| Long-flow keepalive fingerprint | no application-layer keepalive; liveness is kernel TCP keepalive, and idle sessions are retired |

The wire format follows the Trojan idea: after the TLS handshake, a client sends
a 56-byte SHA-224 password digest; a peer that does not is indistinguishable from
a browser and is handed to the fallback origin.

## Build

```
make            # builds bin/tunnel-server and bin/tunnel-client
make test vet
make linux-amd64   # or linux-arm64, for cross-compiling to your VPS
```

## Server (on your VPS)

1. Point a domain at the VPS. The simplest path is automatic certificates:
   set `acme.domain` to that hostname and leave `tls_cert`/`tls_key` empty, and
   the server obtains and renews a real Let's Encrypt certificate over its own
   :443 (TLS-ALPN-01), no separate web server needed. You can instead supply
   your own `tls_cert`/`tls_key`. Leaving all of them empty self-signs, which
   works but is weaker cover.
2. Run a real web server locally (nginx/Caddy on `127.0.0.1:80`) and set
   `fallback` to it, so probes see a real site.
3. `sudo ./scripts/tune-bbr.sh` once, to enable BBR and large buffers.
4. Copy `server.example.json` to `/etc/tunnel/server.json`, edit it, install the
   binary at `/usr/local/bin/tunnel-server`, then enable the systemd unit in
   `deploy/`.

```
cp server.example.json /etc/tunnel/server.json   # then edit passwords/fallback
tunnel-server -c /etc/tunnel/server.json
```

## Client (your machine)

```
cp client.example.json client.json               # set server, password, sni
tunnel-client -c client.json
```

Then point your browser or system at the local proxy:

- SOCKS5: `127.0.0.1:1080`
- HTTP:   `127.0.0.1:1081`

Both ports actually accept *either* protocol (auto-detected).

## Configuration

See `server.example.json` and `client.example.json`; every field is commented.
Key client options: `fingerprint` (chrome/firefox/safari/ios/edge/random),
`mux` (multiplexing for low latency), `sni` (must match the server cert),
`allow_insecure` (only for a self-signed server).

## Notes and limits

- Current build tunnels TCP (CONNECT). UDP-associate is not yet implemented, so
  QUIC/HTTP3 and some game/VoIP UDP will fall back to TCP in the browser.
- `fingerprint: chrome` (the default) is the safest choice. `random` builds a
  ClientHello no real browser sends and should only be used for experiments.
- smux is vendored under `third_party/` with one bug fix (see its `PATCH.md`):
  upstream discards unread received data when a multiplexed stream is
  half-closed, which truncated transfers. Keep the `replace` directive.
- For the strongest cover, use a real domain + valid certificate and a real
  fallback website, not the self-signed/testing defaults.
- Use a long random password. It is the only secret protecting the server.
