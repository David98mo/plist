import re, html, base64, time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs
import urllib.request

POST_RE = re.compile(r'data-post="([^"/]+)/(\d+)"')
TIME_RE = re.compile(r'datetime="([^"]+)"')
HREF_RE = re.compile(r'href="([^"]+)"')
RAW_RE  = re.compile(r'(tg://(?:proxy|socks)\?[^\s"\'<>]+)')

def _valid_secret(s: str) -> bool:
    s = s.strip()
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
        n = len(s) // 2
    elif re.fullmatch(r'[A-Za-z0-9_\-]+', s):
        try:
            n = len(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))
        except Exception:
            return False
    else:
        return False
    return 16 <= n <= 255

def parse_proxy_url(u: str):
    u = html.unescape(u)
    p = urlparse(u)
    kind = None
    if p.scheme == 'tg':
        kind = (p.netloc or p.path.lstrip('/')).lower()
    elif p.netloc.lower() in ('t.me', 'telegram.me', 'telegram.dog'):
        kind = p.path.strip('/').lower()
    if kind not in ('proxy', 'socks'):
        return None

    q = parse_qs(p.query)
    host = (q.get('server') or [''])[0].strip()
    port = (q.get('port') or [''])[0].strip()
    if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        return None

    if kind == 'proxy':
        sec = (q.get('secret') or [''])[0].strip()
        if not _valid_secret(sec):
            return None
        return {"type": "mtproto", "host": host, "port": int(port), "secret": sec}
    return {"type": "socks5", "host": host, "port": int(port)}

def parse_page(html_text: str, max_age_days: int = 7):
    out, marks = [], list(POST_RE.finditer(html_text))
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(html_text)
        block, html_text[m.start():end], int(m.group(2))

        t = TIME_RE.search(block)
        if t:
            try:
                if datetime.fromisoformat(t.group(1)) < cutoff:
                    continue
            except ValueError:
                pass

        for u in HREF_RE.findall(block) + RAW_RE.findall(block):
            pr = parse_proxy_url(u)
            if pr:
                out.append(pr)
    return out, (min(int(m.group(2)) for m in marks) if marks else None)

def fetch_channel(name: str, pages: int = 4, max_age_days: int = 7):
    found, before = [], None
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    for _ in range(pages):
        url = f"https://t.me/s/{name}"
        if before:
            url += f"?before={before}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                if r.status != 200:
                    break
                text = r.read(2_000_000).decode("utf-8", errors="replace")
        except Exception as e:
            print(f"  [{name}] network error: {e}")
            break
        if 'tgme_widget_message' not in text:
            break
        items, oldest = parse_page(text, max_age_days)
        found += items
        if not oldest or oldest <= 1:
            break
        before = oldest
        time.sleep(1.5)
    print(f"  [{name}] {len(found)} proxies")
    return found

def collect_from_channels(channels=None):
    if channels is None:
        channels = ["MTProtoProxies", "ProxyMTProto", "mtp4tg", "socks5_mtproto"]
    all_p = []
    for ch in channels:
        try:
            all_p += fetch_channel(ch)
        except Exception as e:
            print(f"  [{ch}] FAILED: {e}")
    return all_p