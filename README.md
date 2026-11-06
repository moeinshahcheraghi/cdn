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
| SNI filtering | optional `fragment`: the ClientHello is cut into small TLS records / TCP segments, one cut inside the server name |
| SNI blocking | You set the SNI to your own (or an allowed) domain |
| Active probing | Wrong-auth connections are reverse-proxied to a real site |
| Protocol/entropy analysis | It *is* real TLS 1.3, not an obfuscated stream |
| Throughput/latency shaping | smux multiplexing, TCP NoDelay, BBR, no rate limit |
| TLS-in-TLS record-size shape | payload is framed and randomly padded, so the tell-tale handshake/keepalive record sizes are hidden; small records get size jitter |
| Long-flow keepalive fingerprint | no application-layer keepalive; liveness is kernel TCP keepalive, and idle sessions are retired |
| Unknown domain on a datacenter IP | **REALITY mode**: SNI and certificate of a big allowed site; probes are spliced to the real site and see its genuine chain; no domain/cert of your own |
| Long, high-volume flows throttled or flagged | **rotating carriers**: every TLS connection is retired after a random few minutes / few hundred MB and user streams continue seamlessly on a fresh one (resumable streams) |
| A flow silently throttled to nothing, or dropped without a reset | unacknowledged data is noticed within seconds and the connection replaced; the kernel would take ~90 s |
| One exit IP carrying everything | `servers`: several exits and ports, chosen at random, with automatic failover and background recovery |
| The exit IP blocked outright, or unreachable from one datacenter | `backups`: alternative routes, in particular **a WebSocket through a CDN** — the censored link then sees only Cloudflare's IPs and certificate |
| Per-flow throttling of a single heavy connection | users are spread over `pool` connections before any is stacked up |

All of it is transparent to the user: a connection that is moved, replaced or
rerouted continues from the exact byte the far end received, so an OpenVPN
session survives hundreds of rotations and the loss of a whole route.

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

## آموزش کامل راه‌اندازی (فارسی)

سناریوی اصلی: کاربر با OpenVPN به سرور ایران وصل می‌شود، سرور ایران ترافیک را
از داخل تانل به سرور خارج می‌رساند و OpenVPN روی سرور خارج آن را دریافت می‌کند.

```
کلاینت OpenVPN کاربر --> سرور ایران:2083 --> [تانل، شبیه HTTPS] --> سرور خارج:2083 (OpenVPN)
```

روی لینک ایران به خارج، فیلترینگ فقط یک HTTPS معمولی با اثرانگشت کروم می‌بیند.


### شروع سریع با هر دامنه‌ای

یک دامنه بردارید (مثلاً `example.com`) و رکورد A آن را به IP سرور خارج بزنید.
در همه‌ی نمونه‌ها این‌ها را با مقادیر خودتان عوض کنید:

- `DOMAIN` = دامنه‌ی شما، `SERVERIP` = IP سرور خارج
- `PORT` = پورت تونل: اگر ۴۴۳ آزاد است `443`، وگرنه یک پورت آزاد مثل `8443`
- `PASSWORD` = خروجی `openssl rand -hex 24` (همین یک رمز روی سرور و کلاینت یکی باشد)

**۱) سرور خارج — `/etc/tunnel/server.json`** (یکی از دو حالت گواهی):

حالت الف: پورت ۴۴۳ آزاد است، گواهی خودکار از Let's Encrypt:

```json
{
  "listen": ":443",
  "passwords": ["PASSWORD"],
  "acme": { "domain": "DOMAIN", "email": "you@DOMAIN", "cache_dir": "/var/lib/tunnel/acme" },
  "fallback": "www.wikipedia.org:443",
  "log": "info"
}
```

حالت ب: روی ۴۴۳ از قبل وب‌سرور/گواهی دارید، از همان گواهی و یک پورت دیگر استفاده کنید:

```json
{
  "listen": ":8443",
  "passwords": ["PASSWORD"],
  "tls_cert": "/etc/letsencrypt/live/DOMAIN/fullchain.pem",
  "tls_key":  "/etc/letsencrypt/live/DOMAIN/privkey.pem",
  "fallback": "DOMAIN:443",
  "log": "info"
}
```

اجرا:

```
sudo cp bin/tunnel-server-linux-amd64 /usr/local/bin/tunnel-server
sudo cp deploy/tunnel-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-server
sudo journalctl -u tunnel-server -f            # باید: server listening on :PORT
```

اگر پورتی غیر از ۴۴۳ گرفتید، آن پورت را در فایروال باز کنید.

**۲) باکس ایران — `/etc/tunnel/client.json`:**

```json
{
  "server": "DOMAIN:PORT",
  "password": "PASSWORD",
  "sni": "DOMAIN",
  "fingerprint": "chrome",
  "socks_listen": "", "http_listen": "",
  "forwards": [{ "listen": "0.0.0.0:2083", "target": "127.0.0.1:2083" }],
  "mux": { "enabled": true, "concurrency": 8, "pool": 4 },
  "allow_insecure": false,
  "log": "info"
}
```

```
sudo cp bin/tunnel-client-linux-amd64 /usr/local/bin/tunnel-client
sudo cp deploy/tunnel-client.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-client
sudo journalctl -u tunnel-client -f            # باید: port forward 0.0.0.0:2083 -> ...
```

**۳) کاربر OpenVPN** — در فایل `.ovpn` فقط این دو خط:

```
remote <IP-باکس-ایران> 2083
proto tcp
```

نکته‌ها:
- `server` و `sni` را با **نام دامنه** بدهید (نه IP) تا گواهی تأیید شود.
- OpenVPN سرور خارج باید TCP باشد (`proto tcp-server`) و `target` در کلاینت به همان پورت اشاره کند.
- اگر کلاینت OpenVPN روی همان باکس ایرانِ تونل اجرا می‌شود، این خط را به `.ovpn` بیفزایید تا حلقه‌ی مسیریابی رخ ندهد: `route SERVERIP 255.255.255.255 net_gateway`.

### ۰. پیش‌نیازها

- یک **سرور خارج** با یک **دامنه** که به IP آن اشاره می‌کند (رکورد A). دامنه لازم
  است تا گواهی واقعی بگیرید و SNI طبیعی باشد.
- یک **سرور ایران** (رله) که کاربران به آن وصل می‌شوند.
- OpenVPN روی سرور خارج در حالت **TCP** (مثلاً پورت 2083). تانل فقط TCP حمل می‌کند.

### ۱. ساخت باینری‌ها

روی هر ماشینی که Go دارد (نسخه 1.25 به بالا):

```
git clone <این مخزن> && cd tunnel
make                # bin/tunnel-server و bin/tunnel-client برای همین ماشین
make linux-amd64    # bin/*-linux-amd64 برای سرورهای معمولی
make linux-arm64    # bin/*-linux-arm64 برای سرورهای ARM
```

### ۲. سرور خارج (exit)

```
sudo mkdir -p /etc/tunnel /var/lib/tunnel
sudo cp bin/tunnel-server-linux-amd64 /usr/local/bin/tunnel-server
sudo cp server.example.json /etc/tunnel/server.json
sudo cp deploy/tunnel-server.service /etc/systemd/system/
sudo ./scripts/tune-bbr.sh           # یک بار: BBR و بافرهای بزرگ
```

`/etc/tunnel/server.json` را ویرایش کنید:

```json
{
  "listen": ":443",
  "passwords": ["یک-رمز-طولانی-و-تصادفی"],
  "acme": { "domain": "your-domain.example", "email": "you@example.com",
            "cache_dir": "/var/lib/tunnel/acme" },
  "tls_cert": "",
  "tls_key": "",
  "fallback": "www.wikipedia.org:443",
  "log": "info"
}
```

- `passwords`: با `openssl rand -base64 32` بسازید. تنها راز سیستم همین است.
- `acme.domain`: گواهی Let's Encrypt خودکار گرفته و تمدید می‌شود. پورت 443 باید از
  اینترنت باز باشد و دامنه به همین سرور اشاره کند. نیازی به nginx یا certbot نیست.
- `fallback`: سایتی که به هر کسی که رمز ندارد (مثل probe فیلترینگ) نشان داده می‌شود.
  می‌تواند یک سایت HTTPS عمومی روی 443 باشد (خودکار با TLS وصل می‌شود) یا یک
  وب‌سرور محلی مثل `127.0.0.1:80`. اگر خودتان سایتی روی این دامنه دارید بهترین است.

اجرا:

```
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-server
sudo journalctl -u tunnel-server -f      # باید ببینید: server listening on :443
```

بررسی از بیرون: `curl -I https://your-domain.example/` باید صفحه‌ی fallback را با
گواهی معتبر برگرداند. این دقیقاً چیزی است که فیلترینگ می‌بیند.

OpenVPN همین سرور باید TCP باشد، مثلاً در `server.conf`:

```
proto tcp-server
port 2083
local 127.0.0.1     # اختیاری: فقط از داخل تانل قابل دسترس باشد
```

### ۳. سرور ایران (رله)

```
sudo mkdir -p /etc/tunnel
sudo cp bin/tunnel-client-linux-amd64 /usr/local/bin/tunnel-client
sudo cp deploy/tunnel-client.service /etc/systemd/system/
```

`/etc/tunnel/client.json`:

```json
{
  "server": "your-domain.example:443",
  "password": "همان-رمز-سرور",
  "sni": "your-domain.example",
  "fingerprint": "chrome",
  "socks_listen": "",
  "http_listen": "",
  "forwards": [
    { "listen": "0.0.0.0:2083", "target": "127.0.0.1:2083" }
  ],
  "mux": { "enabled": true, "concurrency": 8, "pool": 4 },
  "allow_insecure": false,
  "log": "info"
}
```

- `forwards`: هر چه به پورت 2083 سرور ایران بیاید، از داخل تانل به `target` می‌رسد.
  `target` روی **سرور خارج** معنا می‌شود، پس `127.0.0.1:2083` یعنی OpenVPN خودِ
  سرور خارج. می‌توانید چند forward داشته باشید (SSH، سرویس دیگر، ...).
- `socks_listen`/`http_listen` خالی یعنی هیچ پراکسی محلی باز نمی‌شود؛ فقط forward.
- `allow_insecure` را `false` نگه دارید؛ فقط برای تست با گواهی self-signed `true` کنید.

```
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-client
sudo journalctl -u tunnel-client -f      # باید ببینید: port forward 0.0.0.0:2083 -> ...
```

فایروال سرور ایران باید 2083/tcp را برای کاربران باز کند.

### ۴. سمت کاربر

در پروفایل OpenVPN کاربر فقط آدرس و پروتکل عوض می‌شود:

```
remote <IP-سرور-ایران> 2083
proto tcp
```

بقیه‌ی پروفایل (گواهی‌ها، tls-crypt و ...) همان پروفایل OpenVPN سرور خارج است.

### ۵. حالت پراکسی (به‌جای OpenVPN)

اگر بخواهید مستقیم از روی سیستم خودتان استفاده کنید، `tunnel-client` را روی همان
سیستم اجرا کنید و به‌جای `forwards` این را بگذارید:

```json
"socks_listen": "127.0.0.1:1080",
"http_listen": "127.0.0.1:1081"
```

بعد مرورگر یا سیستم را روی SOCKS5 `127.0.0.1:1080` یا HTTP `127.0.0.1:1081` بگذارید.
هر دو پورت هر دو پروتکل را می‌فهمند.

### ۶. عیب‌یابی

| نشانه | علت احتمالی |
| --- | --- |
| `tls handshake: certificate` در لاگ کلاینت | SNI با دامنه‌ی گواهی نمی‌خواند، یا سرور هنوز گواهی ACME نگرفته (لاگ سرور را ببینید) |
| کلاینت وصل می‌شود ولی داده رد نمی‌شود | رمز کلاینت و سرور فرق دارد؛ سرور چنین کلاینتی را مثل probe به fallback می‌فرستد |
| `acme` گواهی نمی‌گیرد | پورت 443 از اینترنت باز نیست یا دامنه به این IP اشاره نمی‌کند |
| OpenVPN کاربر وصل نمی‌شود | OpenVPN سرور در حالت UDP است؛ باید `proto tcp-server` باشد |
| سرعت پایین | `tune-bbr.sh` را روی سرور خارج اجرا کنید؛ `mux.concurrency` را کم/زیاد کنید |

برای دیدن جزئیات، `"log": "debug"` بگذارید و سرویس را ری‌استارت کنید.

## REALITY mode (recommended)

Instead of your own domain and certificate, the server borrows the identity
of a real, popular site. Generate keys once:

```
tunnel-server -keygen
```

Server:

```json
"reality": { "dest": "www.microsoft.com:443", "server_names": ["www.microsoft.com"],
             "private_key": "<private>", "short_ids": ["a1b2c3d4"], "max_time_diff": 120 }
```

Client (`server` can be a bare IP; `sni` must be one of `server_names`):

```json
"server": "1.2.3.4:443", "sni": "www.microsoft.com", "fingerprint": "firefox",
"reality": { "public_key": "<public>", "short_id": "a1b2c3d4" }
```

Anyone connecting without the key is transparently spliced to the real site
and receives its real certificate. Keep both clocks NTP-synced.
`deploy/reality-openvpn/` has a complete pair of configs with a Persian guide.

## Through a CDN (when the exit IP is blocked)

When a datacenter cannot reach the exit at all, or its IP has been burned,
the tunnel can travel through a CDN. The censored link then carries HTTPS to
Cloudflare's addresses with Cloudflare's certificate, and the exit's own
address never appears on it. Two carriers are available, both served by the
same server setting:

- `http` (preferred): plain HTTP/2 requests, one long download (`GET`) and
  numbered uploads (`POST`) that the server puts back in order. The browser's
  TLS hello goes out unchanged, h2 included, and the traffic is ordinary
  requests and responses.
- `ws`: one WebSocket. To open it the client must offer only http/1.1 in its
  hello, which a browser talking to a CDN never does; a censor that keys on
  that, or on long-lived bidirectional flows, stops it after the handshake.

Server — a second door, since a REALITY port cannot also serve a CDN:

```json
"ws": { "path": "/live/stream/5f3c1a9e", "listen": ":8443" }
```

Client — usually as a backup, so the direct route is preferred while it works:

```json
"backups": [{ "server": "cdn.example.com:8443", "sni": "cdn.example.com",
              "http": { "path": "/live/stream/5f3c1a9e" } }]
```

(`"ws": { ... }` in place of `"http"` uses the WebSocket carrier.)

In Cloudflare: an A record for that name at the exit IP, proxied (orange
cloud), SSL mode Full (and WebSockets on, for `ws`). The client's port must
be the same as `ws.listen` (8443 here): Cloudflare connects to the origin on
the port the client used, and 443 would land on the REALITY port. `path` is
a second secret; every other path on the port is served by the fallback
site, so scanning finds nothing. The `http` carrier needs HTTP/2 between the
client and the CDN (Cloudflare always offers it); it is meant for a CDN, not
for connecting to the server directly.

### Hiding the domain itself (ECH)

Some networks let through only server names they already know: a new
domain completes its TLS handshake and then stalls, on any IP and with any
protocol inside, while a well-known site on the same CDN IP works. ECH
(Encrypted Client Hello) takes the name out of sight: the censor sees only
the CDN's shared public name (`cloudflare-ech.com`), and the CDN, which
holds the key, decrypts the real one and routes as usual. Cloudflare offers
it on every zone. Add the domain's key list to the route:

```json
"backups": [{ "server": "cdn.example.com:8443", "sni": "cdn.example.com",
              "http": { "path": "/live/stream/5f3c1a9e" },
              "ech": "AEX+DQBB...AAA=" }]
```

Get the value with `dig +short HTTPS cdn.example.com` and copy what follows
`ech=` (the whole line is accepted too). Cloudflare rotates these keys; a
stale one costs one extra handshake, in which Cloudflare sends its current
keys (checked against the public name's certificate) and the client uses
them from then on. ECH needs the `firefox` fingerprint. Nothing changes on
the server.

## Routes and failover

`server`, `servers` and `backups` together describe every way to reach the
exit. Each connection picks a random healthy route, preferring the primary
tier; a route that fails is set aside with exponential backoff and re-tested
in the background, so neither a blocked IP nor its recovery costs users more
than a single slow attempt. Established streams are moved onto whatever route
works. `tunnel-client -diag` reports every route stage by stage.

A REALITY handshake is also rejected outright when the client's clock is
wrong, which looks exactly like being blocked. The client measures the true
time against the imitated site, compensates, and says so in the log.

## Rotating carriers

With `mux` on, each TLS connection lives at most `rotate_seconds` (default
300) or `rotate_mb` (default 256), each connection drawing a random 50-100%
of both. Streams are resumable: when a connection is retired the client
continues every stream on a fresh connection from the exact byte the server
last received, so an OpenVPN session survives hundreds of rotations. Set a
value to 0 to disable that dimension.

The same machinery covers failure, not just rotation. A connection that is
reset, or that stops delivering data while appearing alive, is detected
(within `stallTimeout`, 15 s, rather than the kernel's ~90 s) and its streams
are moved. A move is prove-then-swap: the new connection is adopted only once
the server has confirmed the stream over it, so a failed attempt costs
nothing and the user keeps running on the old one. A stream whose header
never reached the server is simply opened again. Nothing the application has
written or read is ever lost or duplicated.

## Diagnostics

`tunnel-client -c client.json -diag` tests every configured route in turn:
TCP connect, the handshake with each browser fingerprint (printing each
ClientHello's size, since hellos over one packet are dropped by some
censors), the clock against the imitated site in REALITY mode, and finally a
real tunnel stream. A failing datacenter is classified in seconds — blocked
IP, blocked port, wrong SNI or fingerprint, wrong clock, or wrong password.

## Putting OpenVPN (or any TCP service) behind the tunnel

Use the client's `forwards` for a relay setup: users connect to a server inside
the country, which carries their traffic through the tunnel to the exit server.

```
user's OpenVPN client --> iran-relay:2083 --> [tunnel] --> exit-server:2083 (OpenVPN)
```

- On the **exit server**: run `tunnel-server` on :443 and OpenVPN in **TCP**
  mode (`proto tcp-server`), e.g. on port 2083, bound to localhost is fine.
- On the **relay server** (inside the country): run `tunnel-client` with

  ```json
  "forwards": [{ "listen": "0.0.0.0:2083", "target": "127.0.0.1:2083" }]
  ```

  `target` is resolved on the exit server, so `127.0.0.1` there means the exit
  server's own OpenVPN. You may leave `socks_listen`/`http_listen` empty.
- Users point their OpenVPN profile at `iran-relay:2083`, `proto tcp`.

OpenVPN must use TCP: the tunnel carries TCP only, and UDP-associate is not
implemented. The DPI only ever sees browser-looking HTTPS between the relay
and the exit server; the OpenVPN protocol never appears on that link.

## Configuration

See `server.example.json` and `client.example.json`; every field is commented.
Key client options: `fingerprint` (firefox/safari/ios/edge/chrome/random;
firefox is the default, chrome's ML-KEM hello is two packets and gets
dropped), `mux` (multiplexing, rotation), `sni` (server cert name, or the
imitated site in REALITY mode), `reality`, `servers`, `forwards`,
`allow_insecure` (only for a self-signed server).

## Notes and limits

- Current build tunnels TCP (CONNECT). UDP-associate is not yet implemented, so
  QUIC/HTTP3 and some game/VoIP UDP will fall back to TCP in the browser.
- Flow control is end-to-end: a user who stops reading blocks their own
  writer instead of making the relay buffer without bound, so one slow client
  cannot add latency for everyone or exhaust the relay's memory.
- `fingerprint: firefox` (the default) is the safest choice: Chrome's
  post-quantum ClientHello spans two packets and Iran's DPI drops it.
  `random` builds a ClientHello no real browser sends and should only be used
  for experiments.
- smux is vendored under `third_party/` with one bug fix (see its `PATCH.md`):
  upstream discards unread received data when a multiplexed stream is
  half-closed, which truncated transfers. Keep the `replace` directive.
- For the strongest cover, use a real domain + valid certificate and a real
  fallback website, not the self-signed/testing defaults.
- Use a long random password. It is the only secret protecting the server.
# cdn
