#!/bin/bash
# cf-scan.sh - find Cloudflare IPs that carry tunnel data from this network.
# Usage: DIAG_ECHO_TARGET=127.0.0.1:19090 bash cf-scan.sh [ips.txt] [port]
# The target must be a TCP echo service you control on the exit. Without it,
# only limited handshake/16 KiB observations are reported, never a bulk pass.
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
# Each candidate must be tested alone; otherwise servers overrides server,
# and a healthy backup can make a failing candidate appear to pass.
if sed '/^[[:space:]]*\/\//d' "$CFG" | grep -qE '"(servers|backups)"[[:space:]]*:'; then
  echo "Use a test config without servers or backups keys to isolate each candidate."
  exit 1
fi

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
[ -z "${DIAG_ECHO_TARGET:-}" ] && echo "No DIAG_ECHO_TARGET: bulk data transfer will not be verified."
echo

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {
  ip="$1"; c="$TMP/$ip.json"
  sed -E "s/\"server\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"server\": \"$ip:$PORT\"/" "$CFG" > "$c"
  extra=()
  if [ -n "${DIAG_ECHO_TARGET:-}" ]; then
    extra=(-diag-echo "$DIAG_ECHO_TARGET" -diag-bytes "${DIAG_BYTES:-1048576}" -diag-timeout "${DIAG_TIMEOUT:-30s}")
  fi
  out="$(timeout 120 "$BIN" -c "$c" -diag "${extra[@]}" 2>&1)"
  if echo "$out" | grep -q "bulk echo PASSED"; then
    echo "OK   $ip   (bulk echo verified for this candidate)"
    echo "$ip" >> "$TMP/good"
  elif echo "$out" | grep -q "only 16 KB acknowledged"; then
    echo "--   $ip   (16 KiB acknowledged; bulk transfer unverified)"
  elif echo "$out" | grep -q "handshake ok"; then
    echo "--   $ip   (handshake ok; bulk transfer failed or unverified)"
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
  echo "No candidate completed a verified bulk echo test."
fi
