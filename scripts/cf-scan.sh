#!/bin/bash
# cf-scan.sh - find Cloudflare IPs that carry tunnel data from this network.
# Usage: bash cf-scan.sh [ips.txt] [port]
# ips.txt may be any pasted text: every IPv4 address in it is tested once.
LIST="${1:-}"
PORT="${2:-8443}"
JOBS=5

BIN=""; CFG=""
for d in "$(dirname "$0")" "$PWD" /root /opt/release /opt/tunnel; do
  [ -z "$BIN" ] && [ -x "$d/tunnel-client" ] && BIN="$d/tunnel-client"
  [ -z "$CFG" ] && [ -f "$d/client.json" ] && CFG="$d/client.json"
done
[ -z "$BIN" ] && { echo "tunnel-client not found"; exit 1; }
[ -z "$CFG" ] && { echo "client.json not found"; exit 1; }

if [ -n "$LIST" ]; then
  [ -f "$LIST" ] || { echo "ip list not found: $LIST"; exit 1; }
  IPS="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$LIST" | sort -u)"
else
  IPS="104.16.0.1 104.17.0.1 104.18.0.1 104.19.0.1 104.20.0.1 104.21.0.1
104.24.0.1 104.25.0.1 104.27.0.1 172.66.0.1 188.114.98.1 188.114.99.1"
fi
echo "binary: $BIN"
echo "config: $CFG"
echo "port:   $PORT   ips: $(echo $IPS | wc -w)"
echo

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {
  ip="$1"; c="$TMP/$ip.json"
  sed -E "s/\"server\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"server\": \"$ip:$PORT\"/" "$CFG" > "$c"
  out="$(timeout 60 "$BIN" -c "$c" -diag 2>&1)"
  if echo "$out" | grep -q "data path OK"; then
    t="$(echo "$out" | grep -o 'acknowledged in [0-9.a-z]*')"
    echo "OK   $ip   ($t)"
    echo "$ip" >> "$TMP/good"
  elif echo "$out" | grep -q "handshake ok"; then
    echo "--   $ip   (handshake ok, data blocked)"
  else
    echo "--   $ip   (no handshake)"
  fi
}

for ip in $IPS; do
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  check "$ip" &
done
wait

echo
if [ -s "$TMP/good" ]; then
  list="$(sed "s/.*/\"&:$PORT\"/" "$TMP/good" | paste -sd, -)"
  echo "Put these in client.json:"
  echo "  \"server\": \"$(head -1 "$TMP/good"):$PORT\","
  echo "  \"servers\": [$list],"
else
  echo "No IP passed data."
fi
