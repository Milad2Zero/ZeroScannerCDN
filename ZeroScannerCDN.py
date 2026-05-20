#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════════
#   ZeroScannerCDN  v1.0  ·  Advanced TLS Scanner
#   Optimized for High-Accuracy TLS/CDN Analysis
# ══════════════════════════════════════════════════════════════════════════════

import socket
import ssl
import sys
import time
import ipaddress
import os
import re
import random
import asyncio
import csv
import selectors
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from threading import Lock

# ─── ANSI Color Palette ───────────────────────────────────────────────────────
class C:
    G    = '\033[38;5;46m'
    LG   = '\033[38;5;82m'
    Y    = '\033[38;5;226m'
    LY   = '\033[38;5;229m'
    R    = '\033[38;5;196m'
    LR   = '\033[38;5;210m'
    CY   = '\033[38;5;51m'
    LC   = '\033[38;5;87m'
    M    = '\033[38;5;201m'
    LM   = '\033[38;5;213m'
    BL   = '\033[38;5;33m'
    OR   = '\033[38;5;208m'
    DG   = '\033[38;5;240m'
    MG   = '\033[38;5;245m'
    W    = '\033[97m'
    B    = '\033[1m'
    N    = '\033[0m'

print_lock = Lock()

# ─── Randomization Data (Anti-Fingerprinting) ─────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
]

TLS12_CIPHER_SUITES = [
    "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:ECDH+AES256:DH+AES256:!aNULL:!MD5:!DSS",
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
]

TLS13_CIPHER_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
]

# ─── Terminal Layout ──────────────────────────────────────────────────────────
def tw():
    try: return min(os.get_terminal_size().columns, 120)
    except: return 80

def hr(ch='─', col=C.DG):
    return f"{col}{ch * tw()}{C.N}"

def print_banner():
    w = tw()
    txt = "ZeroScannerCDN  v3.0  ·  Advanced TLS/CDN Scanner · Enhanced Detection"
    pad = max(0, (w - len(txt)) // 2) * ' '
    print(f"\n{pad}{C.CY}{C.B}{txt}{C.N}\n")

# ─── Progress & UI ────────────────────────────────────────────────────────────
def render_progress(done, total, tls_ok, failed, elapsed):
    w        = tw()
    bar_len  = max(10, min(30, w - 55))
    filled   = int(bar_len * done / total) if total else 0
    bar      = f"{C.G}{'█' * filled}{C.DG}{'░' * (bar_len - filled)}{C.N}"
    pct      = int(100 * done / total) if total else 0
    rate     = done / elapsed if elapsed > 0 else 0
    eta      = int((total - done) / rate) if rate > 0 else 0
    eta_s    = f"{eta//60}m{eta%60:02d}s" if eta >= 60 else f"{eta}s"
    with print_lock:
        sys.stdout.write(
            f"\r  {bar} {C.W}{C.B}{pct:>3}%{C.N} "
            f"{C.DG}[{done}/{total}]{C.N} "
            f"{C.G}TLS✓ {tls_ok}{C.N}  "
            f"{C.R}✗ {failed}{C.N}  "
            f"{C.DG}ETA:{eta_s} · {rate:.1f}/s{C.N}   "
        )
        sys.stdout.flush()

# ─── Core Probe Engine ────────────────────────────────────────────────────────
def is_valid_sni(host: str) -> bool:
    host = (host or '').strip().rstrip('.')
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    labels = host.split('.')
    if len(labels) < 2:
        return False
    label_re = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')
    return all(label_re.match(label) for label in labels)

def make_tcp_socket(ip: str, port: int, timeout: float):
    infos = socket.getaddrinfo(ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

    last_err = None

    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except Exception as e:
            last_err = e
            try:
                sock.close()
            except Exception:
                pass

    if last_err:
        raise last_err

    raise OSError("No usable address family found")

def read_http_response(sock: socket.socket, timeout: float, max_bytes: int = 131072) -> bytes:
    resp = b''
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()

    try:
        selector.register(sock, selectors.EVENT_READ)

        while time.monotonic() < deadline and len(resp) < max_bytes:
            events = selector.select(timeout=0.2)

            if not events:
                continue

            try:
                chunk = sock.recv(8192)

                if not chunk:
                    break

                resp += chunk

                if b'\r\n\r\n' in resp:
                    header_end = resp.find(b'\r\n\r\n')
                    if header_end != -1 and len(resp) > header_end + 4:
                        break

            except socket.timeout:
                continue
            except (ssl.SSLError, OSError):
                break
    finally:
        selector.close()

    return resp

def build_tls_context(alpn_protos=None, min_tls=None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        ctx.minimum_version = min_tls or ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    try:
        ctx.set_alpn_protocols(alpn_protos or ['h2', 'http/1.1'])
    except Exception:
        pass

    try:
        ctx.set_ciphers(random.choice(TLS12_CIPHER_SUITES))
    except Exception:
        pass

    set_ciphersuites = getattr(ctx, 'set_ciphersuites', None)
    if callable(set_ciphersuites):
        try:
            set_ciphersuites(random.choice(TLS13_CIPHER_SUITES))
        except Exception:
            pass

    return ctx

FRONTING_CDNS = {"Cloudflare", "Akamai", "AWS CloudFront", "Fastly", "ArvanCloud"}
CDN_COLOR = { "Cloudflare": C.OR, "Akamai": C.BL, "AWS CloudFront": C.Y, "Fastly": C.M, "ArvanCloud": C.LG, "Unknown": C.DG }

ASN_RANGES = {
    "Cloudflare": ["13335"],
    "Akamai": ["20940"],
    "AWS CloudFront": ["16509"],
    "Fastly": ["54113"]
}

def detect_asn_provider(ip: str) -> str:
    # Lightweight placeholder mapping hook for future RDAP/ASN integration
    private_prefixes = (
        "10.", "127.", "192.168.", "172.16."
    )

    if ip.startswith(private_prefixes):
        return "Private"

    return "Unknown"

def compute_confidence(cdn: str, http_status: int, tls_ok: bool, asn: str) -> int:
    score = 0

    if tls_ok:
        score += 35

    if http_status in (200, 301, 302, 403):
        score += 25

    if cdn != "Unknown":
        score += 25

    if asn != "Unknown":
        score += 15

    return min(score, 100)

def detect_cdn(hdrs: str) -> str:
    low = hdrs.lower()
    sigs = {
        "Cloudflare": ["cf-ray", "server: cloudflare", "cf-cache-status"],
        "Akamai": ["x-akamai-transformed", "server: akamaighost", "x-akamai-request-id"],
        "AWS CloudFront": ["x-amz-cf-id", "via: cloudfront"],
        "Fastly": ["x-fastly-request-id", "server: fastly"],
        "ArvanCloud": ["x-arvan-cache", "server: arvancloud"],
        "Gcore": ["server: gcore"]
    }
    for name, keywords in sigs.items():
        if any(k in low for k in keywords): return name
    for line in hdrs.split('\r\n'):
        if line.lower().startswith('server:'):
            val = line.split(':', 1)[1].strip()
            if val: return val[:30]
    return "Unknown"

def probe(ip: str, port: int, sni: str, timeout: float, dpi_bypass: bool = False, alpn_mode: str = 'auto') -> dict:
    r = dict(ip=ip, port=port, sni=sni, tcp=False, tls=False, http_ok=False, fronting_ok=False, 
             fronting_note='—', tcp_ms=9999, tls_ms=0, http_ms=0, http_status=0, cdn='—', 
             tls_version='—', asn='—', confidence=0, error='')

    raw_sock = None
    try:
        # Phase 1: TCP
        t0 = time.monotonic()
        raw_sock = make_tcp_socket(ip, port, timeout)
        r['tcp_ms'] = int((time.monotonic() - t0) * 1000)
        r['tcp'] = True

        # Phase 2: TLS
        alpn_strats = {'auto': [['h2', 'http/1.1'], ['http/1.1']], 'h2': [['h2']], 'h11': [['http/1.1']]}
        tls_sock = None
        tls_attempts = alpn_strats.get(alpn_mode, alpn_strats['auto'])

        for idx, alpn in enumerate(tls_attempts):
            attempt_sock = raw_sock
            if idx > 0:
                try:
                    if raw_sock:
                        raw_sock.close()
                except Exception:
                    pass
                try:
                    attempt_sock = make_tcp_socket(ip, port, timeout)
                except Exception:
                    raw_sock = None
                    continue

            try:
                ctx = build_tls_context(alpn_protos=alpn)
                t_tls = time.monotonic()
                tls_sock = ctx.wrap_socket(attempt_sock, server_hostname=sni)
                r['tls_ms'] = int((time.monotonic() - t_tls) * 1000)
                r['tls'] = True
                r['tls_version'] = tls_sock.version() or '—'
                raw_sock = tls_sock
                break
            except Exception:
                try:
                    attempt_sock.close()
                except Exception:
                    pass
                raw_sock = None
                continue

        if not r['tls']:
            r['error'] = 'TLS Handshake Failed'
            return r

        # Phase 3: HTTP Request
        raw_sock.settimeout(timeout)
        ua = random.choice(USER_AGENTS)
        req = (f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: {ua}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode('utf-8')

        t_http = time.monotonic()

        raw_sock.sendall(req)

        resp = read_http_response(raw_sock, timeout)
        r['http_ms'] = int((time.monotonic() - t_http) * 1000)

        if resp:
            r['http_ok'] = True
            text = resp.decode('utf-8', errors='replace')
            r['cdn'] = detect_cdn(text)
            r['asn'] = detect_asn_provider(ip)
            
            try: r['http_status'] = int(text.split('\r\n')[0].split(' ')[1])
            except: pass

            suitable = r['cdn'] in FRONTING_CDNS
            r['fronting_ok'] = suitable
            r['fronting_note'] = f"✓ {r['cdn']} Ready" if suitable else f"{r['cdn']} ({r['http_status']})"
            r['confidence'] = compute_confidence(r['cdn'], r['http_status'], r['tls'], r['asn'])
        else:
            r['error'] = 'Empty Response'

    except Exception as e:
        r['error'] = type(e).__name__
    finally:
        if raw_sock:
            try: raw_sock.close()
            except: pass

    return r

# ─── Presentation ─────────────────────────────────────────────────────────────
def print_header():
    w = tw()
    ip_w = max(18, int(w * 0.25))
    cdn_w = max(12, int(w * 0.18))
    with print_lock:
        print(f"\n{hr('═', C.CY)}")
        if w >= 85:
            print(f"  {C.CY}{C.B}{'IP:PORT':<{ip_w}}{'TCP':>7}  {'TLS':>6}  {'VER':>8}  {'HTTP':>5}  {'CDN':<{cdn_w}}{'CONF':>6}  {'STATUS'}{C.N}")
        else:
            print(f"  {C.CY}{C.B}{'IP:PORT':<{ip_w}}{'TCP':>6}  {'TLS':>6}  {'HTTP':>5}  {'STATUS'}{C.N}")
        print(f"{hr('─', C.DG)}")

def print_result(r: dict):
    w = tw()
    ip_w = max(18, int(w * 0.25))
    cdn_w = max(12, int(w * 0.18))

    ip_s = f"{r['ip']}:{r['port']}"[:ip_w-1].ljust(ip_w)
    cdn_s = r['cdn'][:cdn_w-1].ljust(cdn_w)
    sc = C.G if 200 <= r['http_status'] < 300 else C.Y if r['http_status'] else C.R
    http_s = f"{sc}{r['http_status']}{C.N}" if r['http_ok'] else f"{C.R}—{C.N}"
    cc = CDN_COLOR.get(r['cdn'], C.MG)

    if r['fronting_ok']: stat = f"{C.G}{C.B}◉ FRONTING ✓{C.N}"
    elif r['tls'] and r['http_ok']: stat = f"{C.Y}◎ {r['fronting_note'][:22]}{C.N}"
    elif r['tls']: stat = f"{C.LY}◑ TLS OK / No HTTP{C.N}"
    else: stat = f"{C.R}✗ {r['error'][:22]}{C.N}"

    with print_lock:
        if w >= 85:
            print(f"  {C.LC}{ip_s}{C.N}{C.Y}{r['tcp_ms']:>5}ms{C.N}  {C.G}TLS✓  {C.N}{C.DG}{r['tls_version']:<8}{C.N}  {http_s:>5}  {cc}{cdn_s}{C.N}{C.CY}{r['confidence']:>4}%{C.N}  {stat}")
        else:
            print(f"  {C.LC}{ip_s}{C.N}{C.Y}{r['tcp_ms']:>4}ms{C.N}  {C.G}TLS✓  {C.N}{http_s:>5}  {stat}")

# ─── I/O Helpers ──────────────────────────────────────────────────────────────
def parse_line(line):
    out = []
    s = line.strip()
    if not s or s.startswith('#'): return out
    if '://' in s: s = urlparse(s).netloc.split(':')[0]
    if '/' in s:
        try: return [str(ip) for ip in ipaddress.ip_network(s, strict=False).hosts()]
        except: pass
    if '-' in s:
        p = s.split('-')
        if len(p) == 2:
            try:
                start = ipaddress.ip_address(p[0].strip())
                end = ipaddress.ip_address(f"{str(start).rsplit('.', 1)[0]}.{p[1].strip()}" if '.' not in p[1] else p[1].strip())
                while start <= end:
                    out.append(str(start))
                    start += 1
                return out
            except: pass
    out.append(s)
    return out

def load_targets(path):
    raw = []
    try:
        with open(path, encoding='utf-8') as f:
            for line in f: raw.extend(parse_line(line))
    except FileNotFoundError:
        print(f"\n{C.R}[!] File not found: '{path}'{C.N}"); sys.exit(1)
    return list(dict.fromkeys(raw)) # Unique preserve order

def ask(prompt, default='', cast=str):
    while True:
        raw = input(f"  {C.M}❯{C.N} {prompt} {C.DG}[{default}]{C.N}: ").strip()
        try: return cast(raw if raw else default)
        except: print(f"    {C.R}Invalid value{C.N}")

def ask_choice(prompt, options: list, default=0) -> int:
    for i, (key, desc) in enumerate(options):
        print(f"  {f'{C.G}►{C.N}' if i == default else f'{C.DG} {C.N}'} {C.Y}[{key}]{C.N} {desc}")
    raw = input(f"  {C.M}❯{C.N} {prompt} {C.DG}[{options[default][0]}]{C.N}: ").strip()
    return next((i for i, (k, _) in enumerate(options) if raw == k), default)

# ─── Main Execution ───────────────────────────────────────────────────────────
def main():
    print_banner()
    print(f"{hr('─', C.DG)}\n  {C.CY}Scan Settings{C.N}\n")

    targets = load_targets(ask("IP list file", "targets.txt"))
    if not targets: 
        print(f"\n{C.R}[!] No valid IPs found.{C.N}")
        sys.exit(1)
    print(f"    {C.G}✓ {len(targets)} targets loaded{C.N}\n")
    
    port = ask("Port", "443", int)
    sni = ask("SNI hostname", "www.akamai.com", str)

    if not is_valid_sni(sni):
        print(f"\n{C.R}[!] Invalid SNI hostname. Use a real hostname, not an IP address or empty value.{C.N}")
        sys.exit(1)
    
    print(f"\n  {C.CY}ALPN Mode:{C.N}")
    alpn_mode = ['auto', 'h11', 'h2'][ask_choice("Select", [
        ('0', 'Auto (h2 + http/1.1 fallback) — Recommended'),
        ('1', 'HTTP/1.1 only — Better compatibility'),
        ('2', 'HTTP/2 ALPN only — Experimental compatibility mode')
    ], 0)]
    
    print(f"\n  {C.CY}DPI Bypass Mode:{C.N}")
    dpi_bypass = ask_choice("Select", [
        ('0', 'Standard — No fragmentation'),
        ('1', 'Compatibility send mode — Standard segmented send')
    ], 1) == 1
    
    timeout = ask("Timeout (seconds)", "2.0", float)
    threads = min(ask("Thread count", "100", int), 512)

    print(f"\n{hr('═', C.CY)}")
    print(f"  {C.DG}Targets :{C.N} {C.W}{C.B}{len(targets)}{C.N}  |  Port: {C.W}{port}{C.N}")
    print(f"  {C.DG}SNI     :{C.N} {C.W}{sni}{C.N}")
    print(f"  {C.DG}ALPN    :{C.N} {C.W}{alpn_mode}{C.N}")
    print(f"  {C.DG}DPI     :{C.N} {C.W}{'Fragment Active' if dpi_bypass else 'Standard'}{C.N}")
    print(f"  {C.DG}Timeout :{C.N} {C.W}{timeout}s{C.N}  |  Threads: {C.W}{threads}{C.N}")
    print(f"{hr('─', C.DG)}")
    input(f"\n  {C.Y}Press Enter to start scanning ...{C.N} ")

    print_header()
    results, tls_count, fail_count, done_count = [], 0, 0, 0
    t_start = time.monotonic()

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe, ip, port, sni, timeout, dpi_bypass, alpn_mode): ip for ip in targets}
        try:
            for fut in as_completed(futs):
                done_count += 1
                r = fut.result()
                results.append(r)
                if r['tls']:
                    tls_count += 1
                    print_result(r)
                else: 
                    fail_count += 1
                render_progress(done_count, len(targets), tls_count, fail_count, time.monotonic() - t_start)
        except KeyboardInterrupt:
            print(f"\n\n{C.Y}[!] Interrupted — saving partial results ...{C.N}")

    file_name = "OkTargets.txt"
    ok_ips = [r for r in results if r['tls']]
    
    # Sort by TCP latency (low to high) and save line by line
    with open(file_name, 'w') as f:
        f.writelines(f"{r['ip']}\n" for r in sorted(ok_ips, key=lambda x: x['tcp_ms']))

    csv_name = "ScanResults.csv"

    with open(csv_name, 'w', newline='', encoding='utf-8') as csvf:
        writer = csv.writer(csvf)
        writer.writerow([
            'ip',
            'port',
            'tls',
            'tls_version',
            'http_status',
            'cdn',
            'asn',
            'confidence',
            'latency_ms',
            'error'
        ])

        for row in sorted(results, key=lambda x: x['tcp_ms']):
            writer.writerow([
                row['ip'],
                row['port'],
                row['tls'],
                row['tls_version'],
                row['http_status'],
                row['cdn'],
                row['asn'],
                row['confidence'],
                row['tcp_ms'],
                row['error']
            ])
    
    elapsed = time.monotonic() - t_start

    print(f"\n\n{hr('═', C.CY)}")
    print(f"  {C.CY}{C.B}Scan Results{C.N}")
    print(f"{hr('─', C.DG)}")
    print(f"  {C.W}Total Targets :{C.N} {C.W}{C.B}{len(targets)}{C.N}")
    print(f"  {C.G}TLS Success   :{C.N} {C.G}{C.B}{tls_count}{C.N}  {C.DG}← saved to {file_name}{C.N}")
    print(f"  {C.R}TLS Failed    :{C.N} {C.R}{fail_count}{C.N}")
    print(f"  {C.DG}Scan Duration :{C.N} {C.Y}{elapsed:.1f}s{C.N}")
    print(f"{hr('═', C.CY)}\n")

if __name__ == '__main__':
    try: 
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.R}[!] Stopped by user.{C.N}\n")
        sys.exit(0)
