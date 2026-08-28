#!/usr/bin/env python3
"""
Aggregator for docs/list.json.

Pipeline:
    sources.json -> parallel fetch -> parse -> validate -> dedup -> sanity gate
                 -> deterministic serialize -> write ONLY if proxies changed

Standard library only, on purpose: this must keep running unattended for years,
so it has no dependency that can break, get yanked, or need a version bump.

Signing is NOT done here (stdlib has no ECDSA). build.py sets a `changed`
output; the workflow signs with openssl and commits only when that is true.
"""

import concurrent.futures
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ─────────────────────────── paths ───────────────────────────

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SOURCES_PATH = os.path.join(HERE, "sources.json")
OUT_PATH = os.path.join(REPO, "docs", "list.json")

SCHEMA_VERSION = 1
USER_AGENT = "plist-aggregator/1.0 (+https://github.com/david98mo/plist)"

# ─────────────────────────── logging ───────────────────────────


def log(msg):
    print(msg, flush=True)


# ─────────────────────────── fetch ───────────────────────────


def fetch(url, timeout, max_bytes):
    """Returns decoded body, or None on any failure. Never raises."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain, text/*, */*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                log("  ! %s -> HTTP %s" % (url, resp.status))
                return None
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                log("  ! %s -> body over %d bytes, rejected" % (url, max_bytes))
                return None
            return raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        log("  ! %s -> HTTP %s" % (url, e.code))
    except Exception as e:
        log("  ! %s -> %s: %s" % (url, type(e).__name__, e))
    return None


# ─────────────────────────── validation ───────────────────────────

IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I
)
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+=*$")

# Deliberate deviation from the spec's 16..64: a faketls secret is
# 0xEE + 16 key bytes + domain, so a long domain trivially exceeds 64 bytes
# and a 64-byte cap would silently discard perfectly healthy proxies.
# The Android client uses the same 16..255 bound.
SECRET_MIN_BYTES = 16
SECRET_MAX_BYTES = 255


def norm_host(host):
    h = (host or "").strip().rstrip(".").lower()
    if not h or len(h) > 253:
        return None
    if IPV4_RE.match(h) or HOSTNAME_RE.match(h):
        return h
    return None


def norm_port(port):
    try:
        p = int(str(port).strip())
    except Exception:
        return None
    return p if 1 <= p <= 65535 else None


def secret_bytes_len(secret):
    """Decoded length in bytes, or None if it is neither hex nor base64url."""
    s = (secret or "").strip()
    if not s:
        return None
    if HEX_RE.match(s):
        return None if len(s) % 2 else len(s) // 2
    if B64URL_RE.match(s):
        return len(s.rstrip("=")) * 6 // 8
    return None


def make_mtproto(host, port, secret):
    h = norm_host(host)
    p = norm_port(port)
    if not h or not p:
        return None
    s = (secret or "").strip()
    n = secret_bytes_len(s)
    if n is None or not (SECRET_MIN_BYTES <= n <= SECRET_MAX_BYTES):
        return None
    return {"type": "mtproto", "host": h, "port": p, "secret": s}


def make_socks5(host, port):
    h = norm_host(host)
    p = norm_port(port)
    if not h or not p:
        return None
    return {"type": "socks5", "host": h, "port": p}


# ─────────────────────────── parsers ───────────────────────────

MT_RE = re.compile(
    r"server=([A-Za-z0-9\.\-_]+)"
    r"[&;]?.*?port=(\d{1,5})"
    r"[&;]?.*?secret=([A-Za-z0-9_\-=]+)",
    re.I,
)

SOCKS_RE = re.compile(
    r"(?:socks5?://)?"
    r"((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9\.\-]+\.[A-Za-z]{2,})"
    r":(\d{1,5})"
)


def parse_mtproto(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for m in MT_RE.finditer(line):
            p = make_mtproto(m.group(1), m.group(2), m.group(3))
            if p:
                out.append(p)
    return out


def parse_socks5(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # a t.me/tg proxy link is MTProto, never a bare socks5 host:port
        if "secret=" in line.lower():
            continue
        m = SOCKS_RE.search(line)
        if not m:
            continue
        p = make_socks5(m.group(1), m.group(2))
        if p:
            out.append(p)
    return out


PARSERS = {"mtproto": parse_mtproto, "socks5": parse_socks5}


# ─────────────────────────── telegram channels ───────────────────────────


def collect_channels(channels):
    """
    Optional extra input. Isolated on purpose: t.me HTML changes without notice,
    so a broken scraper must degrade to "no channel proxies", never fail the run.
    """
    if not channels:
        return []
    try:
        sys.path.insert(0, HERE)
        import tg_channel  # noqa: E402
    except Exception as e:
        log("  ! tg_channel import failed (%s: %s) — skipping channels"
            % (type(e).__name__, e))
        return []

    fn = getattr(tg_channel, "collect_from_channels", None)
    if not callable(fn):
        log("  ! tg_channel.collect_from_channels not found — skipping channels")
        return []

    try:
        try:
            raw = fn(channels)
        except TypeError:
            raw = fn()          # module keeps its own channel list
    except Exception as e:
        log("  ! channel scrape failed (%s: %s) — continuing without it"
            % (type(e).__name__, e))
        return []

    return normalize_channel_output(raw)


def normalize_channel_output(raw):
    """Accept either proxy dicts or raw t.me/tg:// link strings."""
    if not raw:
        return []
    out = []
    for item in raw:
        try:
            if isinstance(item, str):
                out.extend(parse_mtproto(item))
            elif isinstance(item, dict):
                kind = str(item.get("type", "mtproto")).lower()
                host = item.get("host") or item.get("server") or item.get("ip")
                port = item.get("port")
                if kind == "socks5":
                    p = make_socks5(host, port)
                else:
                    p = make_mtproto(host, port, item.get("secret"))
                if p:
                    out.append(p)
        except Exception:
            continue
    return out


# ─────────────────────────── dedup + serialize ───────────────────────────


def spec_key(p):
    return "%s:%s:%s:%s" % (p["type"], p["host"], p["port"], p.get("secret", ""))


def dedup(proxies):
    """
    Two passes. The spec key first, then host:port — because the Android client's
    DiffUtil identity is still ip:port, so two rows sharing it would break
    rendering there no matter how distinct they look here.
    """
    by_spec = {}
    for p in proxies:
        by_spec.setdefault(spec_key(p), p)

    by_hostport = {}
    for p in by_spec.values():
        by_hostport.setdefault("%s:%s" % (p["host"], p["port"]), p)
    return list(by_hostport.values())


def sort_proxies(proxies):
    return sorted(
        proxies,
        key=lambda p: (p["type"], p["host"], p["port"], p.get("secret", "")),
    )


def ordered(p):
    """Fixed key order so the serialized bytes are stable across runs."""
    d = {"type": p["type"], "host": p["host"], "port": p["port"]}
    if p["type"] == "mtproto":
        d["secret"] = p["secret"]
    return d


def serialize(payload):
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def load_previous():
    try:
        with open(OUT_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ─────────────────────────── main ───────────────────────────


def main():
    with open(SOURCES_PATH, encoding="utf-8") as f:
        cfg = json.load(f)

    limits = cfg.get("limits", {})
    timeout = int(limits.get("per_source_timeout_seconds", 30))
    max_bytes = int(limits.get("max_body_bytes", 2 * 1024 * 1024))
    max_proxies = int(limits.get("max_proxies", 5000))
    min_hosts = int(limits.get("min_distinct_hosts", 50))
    max_drop = float(limits.get("max_drop_ratio", 0.7))

    enabled = [s for s in cfg.get("sources", []) if s.get("enabled", True)]
    log("fetching %d sources" % len(enabled))

    collected = []
    ok_sources = 0

    def one(src):
        body = fetch(src["url"], timeout, max_bytes)
        if body is None:
            return src, []
        parser = PARSERS.get(src.get("kind", "mtproto"))
        if parser is None:
            log("  ! %s -> unknown kind %r" % (src["id"], src.get("kind")))
            return src, []
        return src, parser(body)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for src, items in pool.map(one, enabled):
            if items:
                ok_sources += 1
            log("  %-22s %4d proxies" % (src["id"], len(items)))
            collected.extend(items)

    channel_items = collect_channels(cfg.get("channels"))
    if channel_items:
        ok_sources += 1
    log("  %-22s %4d proxies" % ("telegram_channels", len(channel_items)))
    collected.extend(channel_items)

    if ok_sources == 0:
        log("FAIL: every source failed — refusing to touch list.json")
        return 1

    proxies = sort_proxies(dedup(collected))
    if len(proxies) > max_proxies:
        log("capping %d -> %d" % (len(proxies), max_proxies))
        proxies = proxies[:max_proxies]

    distinct_hosts = len(set(p["host"] for p in proxies))
    log("result: %d proxies, %d distinct hosts, %d/%d sources answered"
        % (len(proxies), distinct_hosts, ok_sources, len(enabled) + 1))

    # ── sanity gates: a broken upstream must not be allowed to publish a
    #    gutted list over a healthy one. Counted on distinct hosts, because
    #    dozens of rows can share one operator's secret.
    if distinct_hosts < min_hosts:
        log("FAIL: only %d distinct hosts (min %d) — keeping previous list"
            % (distinct_hosts, min_hosts))
        return 1

    previous = load_previous()
    prev_proxies = (previous or {}).get("proxies", [])
    if prev_proxies:
        prev_hosts = len(set(p.get("host") for p in prev_proxies))
        if prev_hosts and distinct_hosts < prev_hosts * (1.0 - max_drop):
            log("FAIL: distinct hosts dropped %d -> %d (>%.0f%%) — keeping previous list"
                % (prev_hosts, distinct_hosts, max_drop * 100))
            return 1

    body_proxies = [ordered(p) for p in proxies]

    # ── generated_at is refreshed ONLY when proxies actually change.
    #    Rewriting list.json on every run would mint a new ETag every time and
    #    kill the client's If-None-Match / 304 path entirely. The heartbeat file
    #    exists to keep the cron alive instead.
    unchanged = (
        previous is not None
        and previous.get("proxies") == body_proxies
        and previous.get("mirrors") == cfg.get("mirrors", [])
        and previous.get("schema_version") == SCHEMA_VERSION
        and previous.get("ttl_seconds") == cfg.get("ttl_seconds", 21600)
    )
    if unchanged:
        log("no content change — list.json left untouched")
        emit_changed(False)
        return 0

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ttl_seconds": int(cfg.get("ttl_seconds", 21600)),
        "mirrors": list(cfg.get("mirrors", [])),
        "proxies": body_proxies,
    }

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(serialize(payload))
    log("wrote %s (%d proxies)" % (OUT_PATH, len(body_proxies)))
    emit_changed(True)
    return 0


def emit_changed(changed):
    value = "true" if changed else "false"
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("changed=%s\n" % value)
    log("changed=%s" % value)


if __name__ == "__main__":
    sys.exit(main())
