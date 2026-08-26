import re, html

TG = re.compile(
    r'(?:tg://proxy|https?://t\.me/proxy)\?server=([^&\s"\'<]+)'
    r'&(?:amp;)?port=(\d{1,5})'
    r'&(?:amp;)?secret=([A-Za-z0-9+/=_-]+)'
)
HOSTPORT = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b')

def parse_tg_links(text):
    text = html.unescape(text)
    return [{"type": "mtproto", "host": h, "port": int(p), "secret": s}
            for h, p, s in TG.findall(text)]

def parse_socks_text(text):
    return [{"type": "socks5", "host": h, "port": int(p)}
            for h, p in HOSTPORT.findall(text)]
proxies  = collect_from_repos()        #  raw
proxies += collect_from_channels()     # 

seen, uniq = set(), []
for p in proxies:
    k = f"{p['type']}:{p['host']}:{p['port']}:{p.get('secret','')}"
    if k not in seen:
        seen.add(k)
        uniq.append(p)
        new = json.dumps(payload, sort_keys=True, separators=(',', ':'))
old = Path("list.json").read_text() if Path("list.json").exists() else ""
if new != old:
    Path("list.json").write_text(new)
Path("heartbeat.txt").write_text(datetime.now(timezone.utc).isoformat())