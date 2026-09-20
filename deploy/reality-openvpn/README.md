# OpenVPN پشت تونل، حالت REALITY (پیشنهادی)

این پوشه کانفیگ آماده‌ی سناریوی شماست:

```
کاربر OpenVPN ──▶ رله ایران 193.176.243.31:2083 ══(HTTPS به SNI مایکروسافت)══▶ exit 91.107.159.20:443 ──▶ 127.0.0.1:2083 OpenVPN
```

چرا REALITY؟ در حالت قبلی (دامنه‌ی خودتان + گواهی Let's Encrypt) فیلترینگ یک
دامنه‌ی ناشناس روی یک IP دیتاسنتر می‌بیند که ساعت‌ها ترافیک سنگین می‌گیرد؛ همین
کافی است تا مسدود شود. در REALITY:

- SNI و گواهی متعلق به یک سایت بزرگ مجاز است (مثلاً `www.microsoft.com`).
- پروب فیلترینگ عیناً به سایت واقعی وصل می‌شود و گواهی اصلی را می‌گیرد؛ هیچ
  چیزی برای «کشف» وجود ندارد.
- نیازی به دامنه، گواهی یا وب‌سرور ندارید.

به‌علاوه هر اتصال TLS بعد از چند دقیقه/چندصد مگابایت عوض می‌شود (`rotate_*`) و
جریان کاربر بدون قطعی روی اتصال جدید ادامه می‌یابد؛ این همان چیزی است که جلوی
«بعد از یک ساعت ۱-۲ مگابیت می‌شود» را می‌گیرد.

## ۱) ساخت کلید (یک بار، هر جا)

```
tunnel-server -keygen
# private_key (server): ...   ← در server.json
# public_key  (client): ...   ← در client.json
openssl rand -hex 24          ← در هر دو فایل به‌عنوان password
```

## ۲) سرور exit (91.107.159.20)

```
sudo install -m0755 tunnel-server-linux-amd64 /usr/local/bin/tunnel-server
sudo mkdir -p /etc/tunnel && sudo cp server.json /etc/tunnel/server.json   # کلید و رمز را بگذارید
sudo cp ../tunnel-server.service /etc/systemd/system/
sudo cp ../300-users/sysctl-tuning.conf /etc/sysctl.d/99-tunnel.conf && sudo sysctl --system
sudo timedatectl set-ntp true            # ساعت درست لازم است (max_time_diff)
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-server
sudo journalctl -u tunnel-server -f      # reality mode: imitating www.microsoft.com
```

OpenVPN همین سرور روی `127.0.0.1:2083` با `proto tcp-server` باشد.

بررسی از هر جای دنیا (باید گواهی واقعی مایکروسافت را ببینید):

```
curl -v --resolve www.microsoft.com:443:91.107.159.20 https://www.microsoft.com/ -o /dev/null 2>&1 | grep -E "subject|issuer"
```

## ۳) رله ایران (193.176.243.31)

```
sudo install -m0755 tunnel-client-linux-amd64 /usr/local/bin/tunnel-client
sudo mkdir -p /etc/tunnel && sudo cp client.json /etc/tunnel/client.json   # کلید عمومی و رمز
sudo cp ../tunnel-client.service /etc/systemd/system/
sudo cp ../300-users/sysctl-tuning.conf /etc/sysctl.d/99-tunnel.conf && sudo sysctl --system
sudo timedatectl set-ntp true
sudo tunnel-client -c /etc/tunnel/client.json -diag     # قبل از راه‌اندازی، مسیر را بسنجید
sudo systemctl daemon-reload && sudo systemctl enable --now tunnel-client
```

`-diag` مرحله‌به‌مرحله می‌گوید مشکل کجاست: TCP وصل نمی‌شود (IP بسته است)،
handshake جواب نمی‌دهد (SNI/اثرانگشت مشکل دارد؛ اثرانگشت‌های دیگر را هم امتحان
می‌کند)، یا تونل استریم را رد می‌کند (رمز/کلید اشتباه، یا OpenVPN روی exit پایین است).

## ۴) کاربران

در `.ovpn` فقط:

```
proto tcp
remote 193.176.243.31 2083
```

## اگر دیتاسنتری اصلاً وصل نمی‌شود

`-diag` را همان‌جا بزنید. اگر TCP به `91.107.159.20:443` وصل نمی‌شود، آن IP از
آن دیتاسنتر بسته است؛ یک exit دیگر بگیرید و در `servers` اضافه کنید (ترافیک
بین چند exit پخش می‌شود). اگر TCP وصل می‌شود ولی handshake با همه‌ی
اثرانگشت‌ها می‌خوابد، `dest`/`sni` را عوض کنید (مثلاً `dl.google.com`).
