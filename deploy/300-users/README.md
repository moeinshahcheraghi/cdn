> **Recommended now: `deploy/reality-openvpn/`** (REALITY mode, no domain/cert, harder to detect). This directory is the older own-domain setup and still works.

# Deploying for ~300 concurrent OpenVPN users

Topology: many OpenVPN clients → **Iran relay** (`tunnel-client`, public
`193.176.243.31`) → one DPI-resistant tunnel → **exit** (`tunnel-server`,
`game.xirix.li` / `91.107.159.20`) → OpenVPN server on the exit's
`127.0.0.1:2083`.

All users share the single tunnel the relay opens; the tunnel multiplexes them.

## Steps

### Exit server (91.107.159.20)
1. Ensure `game.xirix.li` resolves to this host and `:443` is reachable.
2. OpenVPN (TCP mode) listening on `127.0.0.1:2083`.
3. Install binary + config:
   ```sh
   cp tunnel-server-linux-amd64 /usr/local/bin/tunnel-server
   mkdir -p /etc/tunnel && cp server.json.example /etc/tunnel/server.json   # set a real password
   cp ../tunnel-server.service /etc/systemd/system/
   ```
4. Apply kernel tuning (see below), then:
   ```sh
   systemctl enable --now tunnel-server
   ```

### Iran relay (193.176.243.31)
1. Install binary + config:
   ```sh
   cp tunnel-client-linux-amd64 /usr/local/bin/tunnel-client
   mkdir -p /etc/tunnel && cp client.json.example /etc/tunnel/client.json   # same password
   cp ../tunnel-client.service /etc/systemd/system/
   ```
2. Apply kernel tuning, then `systemctl enable --now tunnel-client`.
3. Point the OpenVPN users' `.ovpn` at `remote 193.176.243.31 2083 tcp`.

### Kernel tuning (BOTH servers — important)
```sh
cp sysctl-tuning.conf /etc/sysctl.d/99-tunnel.conf
modprobe tcp_bbr && echo tcp_bbr > /etc/modules-load.d/bbr.conf
sysctl --system
```
The systemd units already raise `LimitNOFILE` to 1048576 for many sockets.

## Measured behaviour (lab, 300 concurrent connections)

| metric | result |
| --- | --- |
| connections established | 300 / 300, 0 failed, 0 starved |
| connect latency (p95) | ~55 ms under emulated WAN (RTT 80 ms, 1% loss) |
| aggregate throughput (clean net) | ~5.2 Gbit/s |
| aggregate throughput (WAN, 1% loss) | ~1.1 Gbit/s |
| tunnel-client RAM (300 users) | ~50 MB |
| tunnel-server RAM (300 users) | ~66 MB |
| CPU | scales with bandwidth, not user count (~0.27 core per Gbit/s each side) |

**Takeaways**
- RAM is negligible (~0.15 MB/user); a 1–2 core VPS handles 300 users easily
  unless they collectively saturate multi-Gbit.
- The scaling limit is per-user throughput on a lossy WAN, because OpenVPN-TCP
  runs inside the tunnel's TCP (TCP-over-TCP). **BBR** (in the tuning file) is
  the biggest lever here; a larger mux `pool` reduces cross-user head-of-line
  blocking. The tunnel itself imposes no bandwidth cap.
