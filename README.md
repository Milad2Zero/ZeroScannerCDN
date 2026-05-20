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
git clone https://github.com/Milad2Zero/ZeroScannerCDN
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
git clone https://github.com/Milad2Zero/ZeroScannerCDN.git
cd ZeroScannerCDN
```

اجرای اسکنر:

```bash
python ZeroScannerCDN.py
```

# ذخیره و دسترسی به فایل نتایج در Termux

بعد از پایان اسکن، فایل‌های زیر ساخته می‌شوند:

```text
OkTargets.txt
ScanResults.csv
```

این فایل‌ها داخل پوشه پروژه ذخیره می‌شوند.

---

# مشاهده فایل‌ها

نمایش فایل نتایج:

```bash
cat OkTargets.txt
```

یا:

```bash
cat ScanResults.csv
```

---

# ذخیره در حافظه گوشی

برای دسترسی به حافظه داخلی Android:

```bash
termux-setup-storage
```

سپس اجازه دسترسی را تایید کنید.

---

# انتقال فایل به حافظه داخلی گوشی

کپی فایل نتایج به Downloads:

```bash
cp OkTargets.txt /sdcard/Download/
```

کپی فایل CSV:

```bash
cp ScanResults.csv /sdcard/Download/
```

---

# ساخت فایل targets.txt

در Termux:

```bash
nano targets.txt
```

---

# نمونه محتوا

```text
1.1.1.1
8.8.8.8
104.16.132.229
```

# پشتیبانی از CIDR

```text
104.16.0.0/24
```

# پشتیبانی از Range

```text
104.16.0.1-104.16.0.50
```

# پشتیبانی از URL

```text
https://example.com
```

---

# ذخیره فایل در nano

بعد از وارد کردن IP ها:

```text
CTRL + X
Y
ENTER
```

---

# اجرای اسکن

```bash
python ZeroScannerCDN.py
```

---

# استفاده از فایل دلخواه

اگر کاربر فایل دیگری داشته باشد:

```text
mytargets.txt
```

هنگام اجرای اسکنر، نام فایل را وارد کند:

```text
IP list file [targets.txt]: mytargets.txt
```

---

# انتقال فایل Target از حافظه گوشی

مثلاً اگر فایل داخل Download باشد:

```bash
cp /sdcard/Download/mytargets.txt .
```

---

# License

MIT License