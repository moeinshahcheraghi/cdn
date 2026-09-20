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
