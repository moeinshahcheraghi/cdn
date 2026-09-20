> **Recommended now: `deploy/reality-openvpn/`** (REALITY mode, no domain/cert, harder to detect). This directory is the older own-domain setup and still works.

# راه‌اندازی تونل برای OpenVPN روی پورت 2083

این پوشه یک جفت کانفیگ آماده دارد برای عبور OpenVPN (حالت TCP) از داخل تونلِ مقاومِ DPI.
هر دو سرِ OpenVPN روی پورت **2083** تنظیم شده‌اند:

- کلاینتِ رله (داخل ایران) روی `0.0.0.0:2083` گوش می‌دهد.
- سرورِ exit، ترافیک را به OpenVPN محلی روی `127.0.0.1:2083` تحویل می‌دهد.

```
OpenVPN client  ──▶  relay :2083  ══(TLS/تونل :443)══▶  exit  ──▶  127.0.0.1:2083  OpenVPN server
        (ایران)         (client.json)                        (server.json)
```

## قبل از شروع، این‌ها را در فایل‌ها عوض کن

- `domain`/`sni` را با دامنه‌ی خودت که به IP سرور exit اشاره می‌کند بگذار (الان `game.xirix.li`).
  - **مهم:** `sni` در client باید دقیقاً برابر `acme.domain` در server باشد، وگرنه TLS خطای internal error می‌دهد.
- `email` در server را با ایمیل خودت بگذار (برای Let's Encrypt).
- `password` (client) و `passwords` (server) از قبل با یک رمز تصادفی قوی پر شده و یکی هستند؛
  اگر خواستی عوضش کن ولی هر دو طرف باید **بایت‌به‌بایت** یکی بمانند.
- fingerprint را روی `firefox` بگذار، **نه chrome** (ClientHello کروم دو پکت می‌شود و DPI ایران drop می‌کند).

## سرور exit (خارج)

پیش‌نیاز: دامنه به IP این سرور A record داشته باشد، پورت 443 آزاد باشد، و OpenVPN
روی `127.0.0.1:2083` (TCP) بالا باشد.

```bash
# باینری
sudo install -m0755 bin/tunnel-server-linux-amd64 /usr/local/bin/tunnel-server
# کانفیگ
sudo mkdir -p /etc/tunnel && sudo cp deploy/openvpn-2083/server.json /etc/tunnel/server.json
# سرویس
sudo cp deploy/tunnel-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-server
sudo journalctl -u tunnel-server -f      # اولین بار صدور گواهی ACME را ببین
```

## کلاینت رله (ایران)

```bash
sudo install -m0755 bin/tunnel-client-linux-amd64 /usr/local/bin/tunnel-client
sudo mkdir -p /etc/tunnel && sudo cp deploy/openvpn-2083/client.json /etc/tunnel/client.json
sudo cp deploy/tunnel-client.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-client
sudo journalctl -u tunnel-client -f      # دنبال خطوط  relay ->  بگرد
```

## کلاینت‌های OpenVPN

در فایل `.ovpn` کاربرها فقط IP رله‌ی ایران و پورت 2083 را بگذار (TCP):

```
proto tcp
remote <IP-رله-ایران> 2083
```

## تست سریع

از روی باکس رله، بعد از بالا آمدن هر دو سرویس:

```bash
# باید به OpenVPN روی exit وصل شود (از داخل تونل)
nc -vz 127.0.0.1 2083
```

اگر `relay ->` در لاگ کلاینت دیدی یعنی تونل کار می‌کند. برای سرعت بهتر روی خط پرافت،
BBR را روشن کن (به `deploy/300-users/sysctl-tuning.conf` نگاه کن).
