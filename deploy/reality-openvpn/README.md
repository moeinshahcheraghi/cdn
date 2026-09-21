# OpenVPN پشت تونل — REALITY + مسیر پشتیبان CDN (پیشنهادی)

این پوشه کانفیگ آماده‌ی سناریوی شماست:

```
کاربر OpenVPN ──▶ رله ایران 193.176.243.31:2083 ══(HTTPS به SNI مایکروسافت)══▶ exit 91.107.159.20 ──▶ 127.0.0.1:2083 OpenVPN
                                                   └─(اگر بسته شد: از راه کلودفلر)─┘
```

## سه مشکلی که در میدان دیدید و چه چیزی عوضش کرد

| چیزی که دیدید | علت | چه کاری برایش شده |
| --- | --- | --- |
| اول ۵۰-۶۰ مگ، بعد از ۱ ساعت ۱-۲ مگ، با ری‌استارت درست می‌شد | جریان طولانی و پرحجم را یا فیلترینگ throttle می‌کند یا اتصال بی‌صدا می‌میرد و تا ۹۰ ثانیه کسی نمی‌فهمد | هر اتصال بعد از چند دقیقه/چند صد مگ بازنشسته می‌شود و کاربرها بدون قطعی روی اتصال تازه می‌روند؛ اتصالی که دیتا را بلعیده باشد ظرف ۱۵ ثانیه شناسایی و عوض می‌شود؛ کاربرها روی چند اتصال پخش می‌شوند نه روی یکی |
| روی یک دیتاسنتر اصلاً وصل نمی‌شد | یا IP/پورت از آن‌جا بسته است، یا ساعت سرور غلط بود و REALITY هر بار رد می‌کرد | چند پورت روی سرور، چند exit، و **مسیر پشتیبان از راه کلودفلر**؛ ساعتِ غلط حالا خودکار تصحیح و در لاگ اعلام می‌شود |
| روی یکی شناسایی و کامل بسته شد | آن IP سوخته | مسیر CDN (IP مال کلودفلر است، نه شما) + `servers` چندتایی + چرخش اتصال‌ها |

## ۱) ساخت کلید (یک بار، هر جا)

```
tunnel-server -keygen
# private_key (server): ...   ← در server.json
# public_key  (client): ...   ← در client.json
openssl rand -hex 24          ← در هر دو فایل به‌عنوان password
```

`ws.path` را هم در هر دو فایل به یک رشته‌ی تصادفی عوض کنید (`openssl rand -hex 8`).

## ۲) سرور exit (91.107.159.20)

```
sudo install -m0755 tunnel-server-linux-amd64 /usr/local/bin/tunnel-server
sudo mkdir -p /etc/tunnel && sudo cp server.json /etc/tunnel/server.json   # کلید و رمز را بگذارید
sudo cp ../tunnel-server.service /etc/systemd/system/
sudo cp ../300-users/sysctl-tuning.conf /etc/sysctl.d/99-tunnel.conf && sudo sysctl --system
sudo timedatectl set-ntp true
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-server
sudo journalctl -u tunnel-server -f
```

در لاگ باید ببینید:

```
server listening on :443 ...      ← و همین‌طور :8880 و :2053
websocket carrier on /live/...    ← درِ CDN
websocket/CDN listener on :8443
reality mode: imitating www.microsoft.com
```

پورت‌های 443، 8880، 2053 و 8443 را در فایروال باز کنید. OpenVPN همین سرور روی
`127.0.0.1:2083` با `proto tcp-server` باشد.

بررسی از هر جای دنیا (باید گواهی واقعی مایکروسافت را ببینید):

```
curl -v --resolve www.microsoft.com:443:91.107.159.20 https://www.microsoft.com/ -o /dev/null 2>&1 | grep -E "subject|issuer"
```

## ۳) مسیر پشتیبان از راه کلودفلر (اختیاری ولی توصیه‌ی جدی)

بدون این هم کار می‌کند؛ با این، «بسته شدن IP» دیگر شما را زمین نمی‌زند.

1. یک دامنه در کلودفلر اضافه کنید (پلن رایگان کافی است).
2. یک رکورد A بسازید: `cdn` → `91.107.159.20`، ابر **نارنجی** (Proxied).
3. در SSL/TLS → Overview، حالت را روی **Full** بگذارید.
   (اگر Origin Certificate گرفتید و در `tls_cert`/`tls_key` گذاشتید، **Full (strict)**.)
4. در Network، **WebSockets** روشن باشد (پیش‌فرض روشن است).
5. در `client.json`، `backups[0].server` و `sni` را `cdn.example.com` خودتان کنید.

کلودفلر روی پورت‌های 443/2053/2083/2087/2096/8443 به origin وصل می‌شود؛ ما 8443
گذاشته‌ایم و در کانفیگ سرور همان است.

## ۴) رله ایران (193.176.243.31)

```
sudo install -m0755 tunnel-client-linux-amd64 /usr/local/bin/tunnel-client
sudo mkdir -p /etc/tunnel && sudo cp client.json /etc/tunnel/client.json   # کلید عمومی و رمز
sudo cp ../tunnel-client.service /etc/systemd/system/
sudo cp ../300-users/sysctl-tuning.conf /etc/sysctl.d/99-tunnel.conf && sudo sysctl --system
sudo timedatectl set-ntp true
sudo tunnel-client -c /etc/tunnel/client.json -diag     # قبل از راه‌اندازی، مسیر را بسنجید
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-client
```

`-diag` هر مسیر را جدا جدا می‌سنجد و می‌گوید مشکل کجاست: TCP وصل نمی‌شود (IP/پورت
بسته است)، handshake جواب نمی‌دهد (SNI/اثرانگشت)، ساعت خراب است (خودش اختلاف را
می‌گوید)، یا تونل استریم را رد می‌کند (رمز/کلید اشتباه یا OpenVPN روی exit پایین).

## ۵) کاربران

در `.ovpn` فقط:

```
proto tcp
remote 193.176.243.31 2083
```

## ۶) وقتی باز هم مشکلی پیش آمد

اول `-diag` روی رله. بعد لاگ رله (`journalctl -u tunnel-client -f`) — این پیام‌ها
معنی دارند:

| پیام | یعنی |
| --- | --- |
| `connection via ... stalled after ...; replacing it` | یک اتصال را شبکه بلعیده بود؛ خودش عوض شد. اگر زیاد تکرار شود، آن مسیر تحت فشار است |
| `endpoint ... failing: ...` | آن مسیر (IP/پورت) از کار افتاد؛ روی بقیه ادامه می‌دهد و خودش دوباره امتحان می‌کند |
| `endpoint ... is back` | برگشت |
| `this machine's clock is off by ...` | ساعت رله غلط بود؛ خودش جبران کرد، ولی NTP را درست کنید |
| `move stream: ...` | یک جابه‌جایی کاربر ناموفق بود؛ کاربر روی اتصال قبلی‌اش ادامه می‌دهد و دوباره امتحان می‌شود |

اگر یک کاربر خاص (مثلاً iOS) وصل نمی‌شود ولی بقیه خوب‌اند، قبل از مقصر دانستن
تونل، همان پروفایل را **بدون تونل** و مستقیم تست کنید: گواهی باطل‌شده (CRL) یا
CN تکراری دقیقاً همان‌جا گیر می‌کند و از بیرون شبیه مشکل تونل است.
