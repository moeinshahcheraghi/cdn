#!/usr/bin/env bash
# Enable BBR congestion control and raise buffer limits on the SERVER for
# maximum throughput and low latency. Run as root, once, on the exit node.
set -euo pipefail

cat >/etc/sysctl.d/99-tunnel.conf <<'SYS'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.somaxconn = 1024
SYS

sysctl --system
echo "BBR active: $(sysctl -n net.ipv4.tcp_congestion_control)"
