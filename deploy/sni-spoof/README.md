# Experimental fake SNI: native client and external forwarder

For Persian setup and usage, see the [main README](../../README.md#new-features-fa).

## Native v4 client (Linux, Ethernet/IPv4)

The tunnel client now implements an optional packet injection step itself.
Add `"fake_sni": "chatgpt.com"` to the client config, keeping `server` pointed
at the real CDN address and `sni` / `ws.host` or `http.host` set to your own
domain. No external forwarder is needed in this mode. Backups have their own
optional `fake_sni` field; it is not inherited automatically.

The client must run on the relay with `CAP_NET_RAW`, for example after an
administrator runs `sudo setcap cap_net_raw+ep ./bin/tunnel-client`. Rebuilding
or replacing the binary may require reapplying that capability. Use a dedicated
test config first. Disabling the feature is simply removing `fake_sni`.

This implementation opens a temporary packet socket before each TCP dial,
matches that connection's initial outgoing ACK, and injects a fake ClientHello
whose entire sequence range precedes the expected receive offset. It preserves
the real TLS handshake, certificate checks, WebSocket/HTTP carrier and ECH.
It currently requires Ethernet framing and IPv4; VLAN-tagged or other link
formats are unsupported. Missing privilege, capture timeout or send failure
fails that connection explicitly. Packet send success does not confirm the
destination's ACK, a DPI decision, or transfer success.

Packet construction/checksums are covered by automated tests. Raw injection
on the Iran network and survival beyond four hours remain unverified. This
cannot guarantee access through an IP allowlist or a middlebox that reconstructs
TCP correctly and examines the real ClientHello.

The loopback integration test is opt-in because it creates a raw socket:

```sh
TUNNEL_RAW_TEST=1 go test -v -run '^TestNativeFakeSNILoopback$' ./internal/transport
```

Run it only in a Linux test environment with `CAP_NET_RAW`. It checks that
the normal TCP application receives the real payload intact after injection.
It does not test ISP behavior. The ordinary managed process lacks raw-socket
privileges, but this test passed in an isolated user/network namespace with
only loopback enabled. Normal test runs skip this opt-in check. No external
packet injection was attempted. On hosts permitting unprivileged namespaces:

```sh
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && TUNNEL_RAW_TEST=1 go test -race -count=1 -v -run "^TestNativeFakeSNILoopback$" ./internal/transport'
```

The external-forwarder integration below remains an alternative. Do not enable
native `fake_sni` when pointing `server` at a local forwarder.

## External forwarder alternative

Reference reviewed: https://github.com/therealaleph/sni-spoofing-rust
commit `d2956025c31d96f0f0a341af4f1a8eda204857c7`.

The reference injects a fake ClientHello before forwarding the real TLS
connection. Its TCP sequence number precedes the server's expected byte offset.
This attempts to make a middlebox classify bytes the destination discards.
It does not hide the later real ClientHello, give access to another domain's
Cloudflare configuration, or prove that a destination restriction is bypassed.
Its ACK confirmation proves neither DPI acceptance nor sustained data delivery.

The existing tunnel client already supports this integration: use a local TCP
forwarder as `server`, while preserving the real certificate name in `sni` and
the real HTTP host in `ws.host`. No tunnel wire-format change is required.

On the Iran relay, build/install the reference tool using its documented steps.
Its raw packet injection needs root or suitable network capabilities and direct
access to the outgoing interface. Do not run it through an HTTP CONNECT proxy.
The managed development environment has no external TCP grants; injection and
Iran-path effectiveness have not been tested here.

Copy `forwarder.example.json` to a local configuration and replace
`CLOUDFLARE_IP` with an address serving your own proxied domain. The example
`fake_sni` is `chatgpt.com`; this is an experimental candidate, not a verified
working name. Start the reference CLI with that configuration per its README.

For a separate tunnel test configuration, set:

```json
{
  "server": "127.0.0.1:40443",
  "password": "YOUR_EXISTING_TUNNEL_PASSWORD",
  "sni": "YOUR_OWN_CDN_DOMAIN",
  "fingerprint": "firefox",
  "ws": {
    "host": "YOUR_OWN_CDN_DOMAIN",
    "path": "/YOUR_EXISTING_WEBSOCKET_PATH"
  },
  "allow_insecure": false,
  "socks_listen": "127.0.0.1:1080",
  "mux": {
    "enabled": true,
    "pool": 1,
    "concurrency": 8,
    "rotate_seconds": 300,
    "rotate_mb": 256
  }
}
```

Use the real existing password and path. Remove `servers` and `backups` from
this isolated test so they cannot bypass the local forwarder, and omit REALITY
settings for this WebSocket route. The server configuration stays the same.
Do not replace the real `sni` or `ws.host` with `chatgpt.com`.

Run the bulk echo check documented in the root README against an echo service
on your exit server. Compare the same domain/IP/path both directly and through
the forwarder. Repeat fresh connections and transfers beyond the reported
three-to-four-hour failure interval; log timestamps and server/Cloudflare
errors. A successful injection, TLS handshake, or WebSocket 101 is insufficient.
If both routes stop accepting new transfers, this experiment has not resolved
the restriction; do not report it as successful evasion.
