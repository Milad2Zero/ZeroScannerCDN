# ZeroScannerCDN

اسکنر پیشرفته TLS/CDN با قابلیت تحلیل HTTP، پشتیبانی از IPv4/IPv6 و خروجی CSV.

---

# قابلیت‌ها

- اسکن سریع چند‌نخی (Multi-threaded)
- تحلیل TLS Handshake
- شناسایی CDN
- تحلیل پاسخ HTTP
- پشتیبانی از IPv4 و IPv6
- پشتیبانی از ALPN
- پشتیبانی از HTTP/1.1 و HTTP/2
- خروجی CSV
- رابط کاربری ترمینالی حرفه‌ای
- سیستم Confidence Score
- پشتیبانی از SNI
- معماری بهینه برای کاهش False Negative

---

# CDN های قابل شناسایی

- Cloudflare
- Akamai
- AWS CloudFront
- Fastly
- ArvanCloud
- سایر Edge/CDN ها

---

# پیش‌نیازها

- Python 3.10+
- Linux / Termux / macOS
- بدون نیاز به کتابخانه خارجی

---

# نصب

کلون کردن پروژه:

```bash
git clone https://github.com/YOUR_USERNAME/ZeroScannerCDN.git
cd ZeroScannerCDN
```

---

# اجرا

اجرای اسکنر:

```bash
python ZeroScannerCDN.py
```

---

# فایل تارگت‌ها

اسکنر تارگت‌ها را از فایل زیر می‌خواند:

```text
targets.txt
```

نمونه:

```text
1.1.1.1
8.8.8.8
104.16.132.229
```

---

# حالت‌های اسکن

## HTTP Mode
اسکن استاندارد HTTP/1.1

## HTTP/2 Mode
استفاده از ALPN برای HTTP/2

## Auto Mode
انتخاب خودکار بهترین پروتکل

---

# فایل‌های خروجی

## تارگت‌های سالم

```text
OkTargets.txt
```

شامل IP هایی که پاسخ معتبر داده‌اند.

---

## گزارش کامل CSV

```text
ScanResults.csv
```

شامل:

- IP
- Port
- وضعیت TLS
- نسخه TLS
- وضعیت HTTP
- CDN شناسایی‌شده
- Confidence Score
- Latency
- Error

---

# سیستم Confidence Score

اسکنر بر اساس موارد زیر امتیاز محاسبه می‌کند:

- موفقیت TLS
- اعتبار پاسخ HTTP
- تطبیق CDN Fingerprint
- اطلاعات ASN

---

# نمونه خروجی

```text
IP                RTT   TLS      HTTP   CDN               CONF
104.16.132.229    38ms  TLS1.3   403    Cloudflare        95%
```

---

# توضیحات فنی

- استفاده از SSL داخلی پایتون
- پشتیبانی از ALPN Negotiation
- Parsing بهینه پاسخ HTTP
- مدیریت بهبود یافته Socket
- معماری کاهش False Negative

---

# عملکرد و Thread پیشنهادی

| دستگاه | تعداد Thread |
|--------|---------------|
| گوشی ضعیف | 50-100 |
| گوشی متوسط | 100-250 |
| VPS / PC | 300-500 |

---

# نصب در Termux

نصب Python:

```bash
pkg update
pkg install python git
```

اجرای اسکنر:

```bash
python ZeroScannerCDN.py
```

---

# محدودیت‌ها

- شناسایی CDN مبتنی بر Heuristic است
- برخی CDN ها Fingerprint خود را مخفی می‌کنند
- HTTP/2 به‌صورت کامل پیاده‌سازی نشده
- TLS Fingerprint Randomization پیشرفته وجود ندارد
- سیستم‌های DPI پیشرفته همچنان ممکن است رفتار اسکن را تشخیص دهند

---

# License

MIT License