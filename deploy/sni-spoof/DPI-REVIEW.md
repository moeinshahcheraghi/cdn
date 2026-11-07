# DPI lab: v4 CDN and direct paths

This is a local observer experiment and code review, not a reproduction of an
Iranian ISP's equipment. A passing lab test verifies the stated observation,
not successful evasion. No three-to-four-hour field trial was performed.

## Observer positions

1. User -> Iran:2083: if users send ordinary OpenVPN TCP directly, that leg
   still carries OpenVPN. The onward tunnel cannot conceal packets already
   observed before they reach the Iran relay. Port 2083 does not turn them
   into HTTPS. The lab below does not run a real OpenVPN handshake.
2. Iran -> Cloudflare: the observer sees the Cloudflare address, TCP state,
   ClientHello (outer ClientHello with ECH), sizes, timing, volume and reconnects.
   It does not normally see encrypted HTTP Host, URL, WebSocket upgrade or
   OpenVPN payload. Cloudflare itself terminates TLS and has a different view.
3. Iran -> exit directly: the exit IP is exposed, even with REALITY or ECH.
   Destination-IP restrictions can act independently of TLS content.

## Experiments executed

Run from the repository with the Go toolchain activated:

```sh
go test -v -run '^TestDPILab' -timeout 60s ./internal/transport ./internal/tunnel
```

| Experiment | Observed result | Consequence under the specified model |
| --- | --- | --- |
| Fake `chatgpt.com` followed by real `cdn.example` | First-hello inspector selects fake name; sequence-aware observer discards the old segment and extracts real name | An allowlist containing only `chatgpt.com` permits the naive model's flow but rejects the TCP-aware model's flow |
| TCP fragmentation and TLS-record fragmentation | Reassembly recovers `cdn.example` in both modes | Fragmentation does not hide the name from a reassembling observer |
| Actual ECH ClientHello emitted using the repository's test key | Outer name is `cloudflare-ech.com`; `private.example` is absent in plaintext | Hides the inner name in this emitted hello; does not establish live CDN acceptance, DNS privacy, or permission for the outer name |
| Direct certificate TLS | Real name visible; known inner marker absent from bounded wire sample | Encryption protects sampled content but leaves name and exit IP observable |
| TLS + WebSocket through local CDN stand-in | Real name visible; HTTP path and inner marker absent from bounded wire sample | ISP cannot read the WS upgrade from this encrypted leg; the CDN can |
| TLS + HTTP/2 through local CDN stand-in | Real name visible; HTTP path and inner marker absent from bounded wire sample | Using HTTP/2 alone does not conceal SNI |

The three transfer runs sent and echoed 1,114,112 bytes of synthetic payload.
The tap counted about 1.18 MB per direction and stored only the first 128 KiB
per direction. It observed TLS record lengths, not actual Ethernet packet
sizes or WAN timing. Tests use local certificates with verification disabled
only in their fixtures, a transparent TCP tap, and an echo backend. They do
not emulate Cloudflare's production policy, congestion, or OpenVPN's workload.

The fake-SNI experiment constructs the same fake frame as the implementation
but models its sequence-space treatment offline. It does not inject packets
into a live network. The stateful model is intentionally narrow; it is not a
complete TCP stack or a trained traffic classifier.

## What could be flagged

* Two conflicting ClientHellos, with one wholly outside accepted sequence
  space, are observable anomalies. `fake_sni` is an experimental option, not
  the foundation for a guarantee against a stateful DPI.
* Without accepted ECH, the real SNI is a direct domain-policy input. In direct
  mode, the destination IP remains a direct policy input regardless of SNI.
* Connection lifetime, total volume, direction ratios, record lengths and
  correlated reconnects remain visible. A rule could act on them, but this lab
  has no normal-browser dataset and provides no false-positive rate. It cannot
  establish that a particular size pattern uniquely identifies this tunnel.
* The Cloudflare-facing HTTP carrier uses Go's HTTP/2 implementation, not the
  browser's HTTP/2 implementation. uTLS alone does not reproduce browser HTTP/2
  settings, header order or application behavior. This is visible to the TLS
  terminator, not automatically to a passive ISP.
* The HTTP and WS carriers now select User-Agent by the configured TLS browser
  profile. Tests inspect requests received over TLS for Firefox, Chrome,
  Safari, iOS and Edge, and check the pinned uTLS preset versions. This fixes
  the earlier unconditional Firefox User-Agent; it still does not reproduce
  an end-to-end browser identity or prove indistinguishability. The `random`
  fingerprint remains experimental and has no matching real browser profile.
* Active probing has a different view from passive observation. Certificate
  TLS fallback behavior and REALITY's real-site forwarding need independent
  checks. REALITY end-to-end was not validated in this restricted environment.

## Deployment implications

For the CDN path, test HTTP/2 with valid, accepted ECH and the correct real
domain/certificate. Keep verification enabled. Check DNS exposure as well:
using the private domain as the TCP destination can trigger system DNS lookups
even though ECH protects the ClientHello. An explicit known CDN address avoids
that particular lookup but does not guarantee routing or reachability. Keep
the public ECH name and CDN IP accessible; a whitelist can reject either.

Compare fake-SNI on and off using otherwise identical settings. Do not count
an injected packet, ACK, TLS handshake, or 101 response as successful transfer.
For direct mode, compare ordinary HTTPS to the same exit before concluding
that changing tunnel framing will help. REALITY does not conceal the exit IP.

If fresh connections also stop working after several hours, collect both
relay and exit logs and compare CDN errors, direct control traffic, DNS and
reachability at the same time. This is not established to be an idle timeout
or DPI learning event. Rotation cannot revive a destination already denied.

The present evidence supports encrypted transport with observable metadata.
It does not support calling either path undetectable or universally usable
under a whitelist.
