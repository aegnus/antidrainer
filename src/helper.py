#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sniff Test contributors
"""
Sniff Test - local helper.

Run:   python3 drainer-bench.py
Then open http://127.0.0.1:8787/ in a browser profile with NO wallet extensions.

What it does:
  * Serves the Sniff Test page at http://127.0.0.1:8787/
  * Runs the site under test at its own separate address, http://127.0.0.1:8788/,
    and fetches every file and API call that site makes on its behalf. Browsers
    otherwise refuse to load a site's code into a test page.

Safety rules built in:
  * Listens on 127.0.0.1 only, so nothing else on your network can use it.
  * The bench (port 8787) and the site under test (port 8788) are different
    browser origins, so the tested site cannot read or control the bench.
  * The bench's own fetch route needs a random key that only the bench page knows.
  * Nothing is fetched from your local network (router, NAS, this helper itself),
    unless you start it with --allow-private (to test your own local dApp).
  * No cookies are sent to or kept from the tested site. Cookies its answers would set are only listed for
    the bench page's privacy report.

Needs only Python 3.8+, no extra packages.
"""
import argparse
import collections
import hashlib
import io
import math
import os
import struct
import time
import http.server
import ipaddress
import json
import secrets
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

BENCH_HTML = r'''@@BENCH_HTML@@'''

# Visitor profiles for the bench's phone check: some attack kits serve code only to phones.
PROFILES = {
    "ios16": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "ios18": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    "android": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
}
MAX_BYTES = 25 * 1024 * 1024
MAX_LOG = 1500
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
TOKEN = secrets.token_urlsafe(24)
ALLOW_PRIVATE = False
OWN_PORTS = set()
STATE = {"html": "<!doctype html><p>No site loaded yet.</p>", "url": "about:blank", "scripts": [],
         "requests": [], "cookies": []}
STATE_LOCK = threading.Lock()

BOOT_HTML = """<!doctype html><meta charset="utf-8">
<body style="font:14px system-ui,sans-serif;color:#667;padding:20px">Preparing the sandbox...
<script>
(async () => {
  const q = new URLSearchParams(location.search);
  try {
    await navigator.serviceWorker.register('/__bench/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise(r => navigator.serviceWorker.addEventListener('controllerchange', r, { once: true }));
    }
    location.replace(q.get('path') || '/');
  } catch (e) {
    document.body.textContent = 'The sandbox could not start: ' + e.message;
    parent.postMessage({ __dtb: q.get('r'), type: 'bootfail', data: { msg: String(e.message) } }, '*');
  }
})();
</script>"""

SW_JS = r"""
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const req = e.request;
  const url = new URL(req.url);
  if (url.origin === self.location.origin) {
    if (url.pathname.startsWith('/__bench/') || req.mode === 'navigate') return;
    e.respondWith(relay(e, req, '/__bench/p?rel=' + encodeURIComponent(url.pathname + url.search)));
    return;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  e.respondWith(relay(e, req, '/__bench/p?u=' + encodeURIComponent(req.url)));
});
async function relay(e, req, target) {
  // Pass every header the page set (API keys, app IDs, protocol versions) to the helper in one field.
  const all = {};
  for (const [k, v] of req.headers) all[k] = v;
  const headers = { 'x-bench-h': encodeURIComponent(JSON.stringify(all)) };
  const init = { method: req.method, headers, credentials: 'omit', redirect: 'follow' };
  if (req.method !== 'GET' && req.method !== 'HEAD') init.body = await req.arrayBuffer();
  try {
    const r = await fetch(target, init);
    // Re-wrap so the response keeps the original URL: modules resolve their relative imports from it.
    const nullBody = [101, 204, 205, 304].includes(r.status);
    return new Response(nullBody ? null : r.body, { status: r.status, statusText: r.statusText, headers: r.headers });
  } catch (err) { return new Response('', { status: 502 }); }
}
"""

# Request headers from the page that the helper replaces or must not forward.
DROP_REQ = {"host", "origin", "referer", "cookie", "content-length", "connection", "keep-alive", "accept-encoding",
            "user-agent", "transfer-encoding", "upgrade", "te", "trailer", "proxy-authorization"}
# Response headers that must not be passed back (framing, cookies, and the real site's browser policies).
DROP_RESP = {"content-length", "content-encoding", "transfer-encoding", "connection", "keep-alive", "set-cookie",
             "content-type", "content-security-policy", "content-security-policy-report-only",
             "strict-transport-security", "alt-svc", "x-frame-options", "cross-origin-opener-policy",
             "cross-origin-embedder-policy", "cross-origin-resource-policy", "cache-control", "expires", "etag",
             "last-modified", "age", "date", "server", "vary", "report-to", "nel", "permissions-policy"}


def ssl_context():
    ctx = ssl.create_default_context()
    try:
        import certifi  # optional; fixes python.org builds on macOS without certificates
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


SSL_CTX = ssl_context()


def check_target(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https", "ws", "wss") or not u.hostname:
        raise ValueError("Only http and https addresses can be fetched.")
    port = u.port or (443 if u.scheme in ("https", "wss") else 80)
    try:
        infos = socket.getaddrinfo(u.hostname, port)
    except socket.gaierror:
        raise ValueError("Could not find " + u.hostname + " (DNS lookup failed).")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_unspecified:
            raise ValueError("Blocked by your DNS: " + u.hostname + " resolves to 0.0.0.0, which usually means an "
                             "ad or tracker blocker is filtering it.")
        if ip.is_loopback and port in OWN_PORTS:
            raise ValueError("Refused: requests to the helper itself are not allowed.")
        if not ALLOW_PRIVATE and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                                  or ip.is_multicast or ip.is_unspecified):
            raise ValueError("Refused: " + u.hostname + " is on your local network. Start the helper with "
                             "--allow-private to test local sites.")


class CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_target(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(CheckedRedirects(), urllib.request.HTTPSHandler(context=SSL_CTX))


def origin_of(url):
    u = urllib.parse.urlsplit(url)
    return u.scheme + "://" + u.netloc if u.scheme in ("http", "https") and u.netloc else None


def upstream(url, method="GET", body=None, page_headers=None, page_url=None, accept=None, ua=None):
    """Fetch url; returns (status, headers, bytes, final_url).

    page_headers: headers the tested page set on the request; page_url: the tested site's real address,
    used as Origin and Referer so its servers see the request as coming from the site itself."""
    check_target(url)
    headers = {"User-Agent": ua or UA, "Accept": accept or "*/*", "Accept-Language": "en-US,en;q=0.9"}
    for k, v in (page_headers or {}).items():
        if k.lower() not in DROP_REQ and not k.lower().startswith(("x-bench", "sec-")):
            headers[k] = v
    headers["Sec-GPC"] = "1"  # Global Privacy Control: the test visitor opts out of tracking and data sale
    site_origin = origin_of(page_url or "")
    if site_origin:
        headers["Referer"] = page_url
        if method not in ("GET", "HEAD") or origin_of(url) != site_origin:
            headers["Origin"] = site_origin
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = OPENER.open(req, timeout=25)
    except urllib.error.HTTPError as e:
        resp = e
    with resp:
        data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise OverflowError("larger than 25 MB")
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, data, resp.geturl()


def record(url, status, headers, size):
    """Log a request the site made and any cookies its answer would set. The cookies are only reported to the
    bench page; they are never stored or sent back, so the tested site still sees a visitor with no cookies."""
    ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    with STATE_LOCK:
        if len(STATE["requests"]) < MAX_LOG:
            STATE["requests"].append({"url": url, "status": status, "type": ctype, "size": size})
        for raw in headers.get_all("Set-Cookie") or []:
            if len(STATE["cookies"]) < MAX_LOG:
                STATE["cookies"].append({"url": url, "raw": raw[:600]})


DL_MAX = 250 * 1024 * 1024   # largest file the bench will inspect
DL_HEAD = 2 * 1024 * 1024    # bytes kept from the start for header parsing
DL_TAIL = 256 * 1024         # bytes kept from the end (zip directory, disk-image trailer)
DL_SECONDS = 150
PACKER_SECTIONS = ("upx0", "upx1", "upx2", ".themida", ".vmp0", ".vmp1", ".enigma1", ".aspack", ".adata", ".petite", ".mpress1", ".nsp0")
RISKY_INSIDE = (".exe", ".scr", ".lnk", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".bat", ".cmd", ".ps1", ".msi", ".jar", ".com", ".hta", ".app", ".pkg", ".dmg", ".command", ".sh")


def entropy(counts, total):
    if not total:
        return 0.0
    return -sum(c / total * math.log2(c / total) for c in counts.values() if c)


def parse_pe(head, size):
    """Read a Windows executable's headers. Returns facts, never runs or loads anything."""
    out = {"kind": "Windows executable"}
    if len(head) < 0x40:
        return out, []
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    if pe + 24 > len(head) or head[pe:pe + 4] != b"PE\0\0":
        out["note"] = "MZ header without a valid PE header"
        return out, []
    machine, nsec, stamp, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", head, pe + 4)
    out.update(machine={0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine)), dll=bool(chars & 0x2000), timestamp=stamp)
    opt = pe + 24
    magic = struct.unpack_from("<H", head, opt)[0] if opt + 2 <= len(head) else 0
    dd = opt + (96 if magic == 0x10b else 112)
    def entry(i):
        o = dd + 8 * i
        return struct.unpack_from("<II", head, o) if o + 8 <= len(head) else (0, 0)
    cert_off, cert_size = entry(4)
    out["signed"] = cert_size > 0
    out["dotnet"] = entry(14)[1] > 0
    sec_start = opt + optsize
    sections = []
    for i in range(min(nsec, 96)):
        o = sec_start + 40 * i
        if o + 40 > len(head):
            break
        name = head[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rsize, rptr, _, _, _, _, flags = struct.unpack_from("<IIIIIIHHI", head, o + 8)
        sections.append({"name": name, "start": rptr, "end": rptr + rsize, "flags": flags})
    return out, sections


def parse_macho(head):
    out = {"kind": "macOS executable"}
    magic = head[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        is64 = magic[0] == 0xcf
        cpu, _, ftype, ncmds, _, flags = struct.unpack_from("<iiIIII", head, 4)[:6] if len(head) >= 28 else (0,) * 6
        out.update(cpu={7: "x86", 0x01000007: "x64", 12: "arm", 0x0100000c: "arm64"}.get(cpu, str(cpu)),
                   type={1: "object", 2: "executable", 6: "library", 8: "bundle"}.get(ftype, str(ftype)))
        off = 32 if is64 else 28
        signed = False
        for _ in range(min(ncmds, 400)):
            if off + 8 > len(head):
                break
            cmd, size = struct.unpack_from("<II", head, off)
            if cmd == 0x1d:
                signed = True
            if size < 8:
                break
            off += size
        out["signed"] = signed
    else:
        out["kind"] = "macOS universal binary"
        out["note"] = "Contains several architectures. Check its signature with codesign."
    return out


def parse_zip(tail, size):
    out = {"kind": "ZIP archive", "names": [], "encrypted": False}
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or i + 22 > len(tail):
        return out
    count, cd_size, cd_off = struct.unpack_from("<HII", tail, i + 10)
    base = size - len(tail)
    pos = cd_off - base
    if pos < 0 or pos + cd_size > len(tail) + 0:
        out["note"] = "File list not read (archive directory is far from the end)"
        return out
    for _ in range(min(count, 400)):
        if pos + 46 > len(tail) or tail[pos:pos + 4] != b"PK\x01\x02":
            break
        flag = struct.unpack_from("<H", tail, pos + 8)[0]
        nlen, elen, clen = struct.unpack_from("<HHH", tail, pos + 28)
        out["names"].append(tail[pos + 46:pos + 46 + nlen].decode("utf-8", "replace"))
        if flag & 1:
            out["encrypted"] = True
        pos += 46 + nlen + elen + clen
    out["entries"] = count
    return out


class MemoryResponse:
    """A file the page built in the browser, handed over as bytes, shaped like an HTTP response."""
    status = 200

    def __init__(self, data, name, ctype):
        self.data, self.name, self.headers = io.BytesIO(data), name, {"Content-Type": ctype or "", "Content-Length": str(len(data))}

    def read(self, n):
        return self.data.read(n)

    def geturl(self):
        return "generated in the page: " + self.name

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def inspect_download(url, data=None, ctype=""):
    """Read a file into memory only (never to disk), hash it and read its headers. Nothing is run or opened.
    The file comes from url, or from data when the page built it in the browser."""
    if data is None:
        check_target(url)
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        opened = OPENER.open(req, timeout=25)
    else:
        opened = MemoryResponse(data, url, ctype)
    started = time.time()
    with opened as resp:
        if resp.status >= 400:
            raise ValueError("The site answered with HTTP %d." % resp.status)
        length = int(resp.headers.get("Content-Length") or 0)
        if length > DL_MAX:
            raise OverflowError("larger than %d MB" % (DL_MAX // 1048576))
        sha, md5, sha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
        head, tail, size = bytearray(), b"", 0
        total_counts = collections.Counter()
        sections, parsed, extra = [], False, {}
        sec_counts = {}
        while True:
            if time.time() - started > DL_SECONDS:
                raise TimeoutError("took longer than %d seconds" % DL_SECONDS)
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            if size + len(chunk) > DL_MAX:
                raise OverflowError("larger than %d MB" % (DL_MAX // 1048576))
            sha.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            if len(head) < DL_HEAD:
                head += chunk[:DL_HEAD - len(head)]
            tail = (tail + chunk)[-DL_TAIL:]
            total_counts.update(chunk)
            if not parsed and len(head) >= min(DL_HEAD, 4096) and head[:2] == b"MZ":
                extra, sections = parse_pe(bytes(head), 0)
                sec_counts = {s["name"] + str(i): collections.Counter() for i, s in enumerate(sections)}
                parsed = True
            for i, s in enumerate(sections):
                lo, hi = max(s["start"], size), min(s["end"], size + len(chunk))
                if hi > lo and s["end"] > s["start"]:
                    sec_counts[s["name"] + str(i)].update(chunk[lo - size:hi - size])
            size += len(chunk)
    head = bytes(head)
    info = {"url": url, "finalUrl": resp.geturl(), "size": size, "sha256": sha.hexdigest(), "sha1": sha1.hexdigest(), "md5": md5.hexdigest(),
            "contentType": resp.headers.get("Content-Type", ""), "disposition": resp.headers.get("Content-Disposition", ""),
            "entropy": round(entropy(total_counts, size), 2)}
    if head[:2] == b"MZ":
        if not parsed:
            extra, sections = parse_pe(head, size)
        info.update(extra)
        info["sections"] = []
        for i, s in enumerate(sections):
            c = sec_counts.get(s["name"] + str(i), collections.Counter())
            n = sum(c.values())
            info["sections"].append({"name": s["name"], "entropy": round(entropy(c, n), 2) if n > 4096 else None,
                                     "exec": bool(s["flags"] & 0x20000000), "write": bool(s["flags"] & 0x80000000),
                                     "packer": s["name"].lower() in PACKER_SECTIONS})
    elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        info.update(parse_macho(head))
    elif head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        info.update(parse_zip(tail, size))
    elif head[:8] in (b"encrcdsa", b"cdsaencr"):
        info.update(kind="Encrypted disk image", encrypted=True)
    elif len(tail) >= 512 and tail[-512:-508] == b"koly":
        info["kind"] = "macOS disk image (DMG)"
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        info["kind"] = "Microsoft installer or Office file"
    elif head[:4] == b"\x7fELF":
        info["kind"] = "Linux executable"
    elif head[:2] == b"#!":
        info["kind"] = "Script"
    else:
        info["kind"] = "Unknown format"
    if not os.environ.get("SNIFF_NO_LOOKUP"):
        info["circl"] = circl_lookup(info["sha256"])
        info["cymru"] = cymru_lookup(info["sha1"])
    vt = os.environ.get("VT_API_KEY")
    if vt:
        info["virustotal"] = vt_lookup(info["sha256"], vt)
    return info


def circl_lookup(sha256):
    """CIRCL hashlookup: free, no key. Knows files from NSRL and Linux/Android/Windows software sets and some malware
    lists. Only the hash is sent."""
    req = urllib.request.Request("https://hashlookup.circl.lu/lookup/sha256/" + sha256, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with OPENER.open(req, timeout=15) as r:
            d = json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e:
        return {"known": False} if e.code == 404 else {"error": "HTTP %d" % e.code}
    except Exception as e:
        return {"error": str(e)[:120]}
    return {"known": True, "malicious": str(d.get("KnownMalicious", ""))[:80], "name": str(d.get("FileName", ""))[:120],
            "source": str(d.get("source", ""))[:80], "trust": d.get("hashlookup:trust")}


def cymru_lookup(sha1):
    """Team Cymru Malware Hash Registry: free, no key. A DNS TXT record "<time> <percent of AV engines flagging it>".
    Python cannot query TXT records, so this goes through Cloudflare's DNS-over-HTTPS. Only the hash is sent."""
    url = "https://cloudflare-dns.com/dns-query?type=TXT&name=" + sha1 + ".malware.hash.cymru.com"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/dns-json"})
    try:
        with OPENER.open(req, timeout=15) as r:
            d = json.loads(r.read(200_000))
    except Exception as e:
        return {"error": str(e)[:120]}
    if d.get("Status") == 3 or not d.get("Answer"):
        return {"known": False}
    try:
        parts = str(d["Answer"][0]["data"]).strip('"').split()
        return {"known": True, "detection": int(parts[1])}
    except Exception:
        return {"error": "unreadable answer"}


def vt_lookup(sha256, key):
    """Ask VirusTotal about a hash. Only the hash leaves this machine, never the file."""
    req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha256, headers={"x-apikey": key, "User-Agent": UA})
    try:
        with OPENER.open(req, timeout=20) as r:
            a = json.loads(r.read(2_000_000)).get("data", {}).get("attributes", {})
    except urllib.error.HTTPError as e:
        return {"known": False} if e.code == 404 else {"error": "HTTP %d" % e.code}
    except Exception as e:
        return {"error": str(e)[:120]}
    stats = a.get("last_analysis_stats", {})
    pop = (a.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
    return {"known": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()), "label": pop}


def friendly_error(e):
    if isinstance(e, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(e):
        return ("Secure connection failed (" + str(e) + "). On macOS with Python from python.org, run "
                "'Install Certificates.command' in your Python folder, or 'pip3 install certifi'.")
    if isinstance(e, urllib.error.URLError):
        return "Could not reach the site: " + str(e.reason)
    if isinstance(e, OverflowError):
        return "The file is " + str(e) + " and was not fetched."
    return str(e)


class Base(http.server.BaseHTTPRequestHandler):
    server_version = "DrainerBenchHelper"

    def log_message(self, fmt, *args):
        pass

    def send_body(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra.items() if hasattr(extra, "items") else (extra or [])):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def read_body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise OverflowError("too large")
        return self.rfile.read(n) if n else b""


class BenchHandler(Base):
    """Port 8787: the bench page, its key-protected fetch route, and staging of the page under test."""

    def same_origin_ok(self):
        origin = self.headers.get("Origin")
        return origin is None or origin == "http://" + self.headers.get("Host", "")

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path in ("/", "/index.html"):
            cfg = json.dumps({"token": TOKEN, "specimen": "http://127.0.0.1:%d" % self.server.specimen_port})
            page = ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
                    "<script>window.BENCH_HELPER = " + cfg + ";</script>\n" + BENCH_HTML)
            return self.send_body(200, page, "text/html; charset=utf-8", {"Cache-Control": "no-store"})
        if parsed.path == "/fetch":
            if not self.same_origin_ok():
                return self.send_body(403, "Refused: request did not come from the bench page.")
            if self.headers.get("X-Bench-Token") != TOKEN:
                return self.send_body(403, "Refused: missing or wrong key. Reload the bench page.")
            q = urllib.parse.parse_qs(parsed.query)
            target = q.get("url", [""])[0]
            try:
                status, headers, data, final = upstream(target, accept="text/html,application/javascript,*/*;q=0.8", ua=PROFILES.get(q.get("ua", [""])[0]))
            except Exception as e:
                return self.send_body(403 if isinstance(e, ValueError) else 502, friendly_error(e))
            if "top" in q:  # the page being tested: start a fresh log
                with STATE_LOCK:
                    STATE["requests"] = []
                    STATE["cookies"] = []
                record(final, status, headers, len(data))
            if status >= 400:
                server = (headers.get("Server") or "").lower()
                if status in (403, 429, 503) and ("cloudflare" in server or headers.get("cf-mitigated") or "akamai" in server or "sucuri" in server):
                    return self.send_body(502, "The site answered with HTTP %d and a bot check (%s). It only lets real browsers in, "
                                          "and this tool does not try to get past that, so this site cannot be tested here. "
                                          "Sites behind a bot check are usually run by a company that blocks scripts on purpose." % (status, server.split("/")[0] or "protection service"))
                return self.send_body(502, "The site answered with HTTP %d." % status)
            charset = headers.get_content_charset() or "utf-8"
            return self.send_body(200, data.decode(charset, errors="replace"),
                                  extra={"X-Final-URL": final, "Cache-Control": "no-store"})
        if parsed.path == "/scan-file":
            if not self.same_origin_ok() or self.headers.get("X-Bench-Token") != TOKEN:
                return self.send_body(403, "Refused.")
            target = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
            try:
                return self.send_body(200, json.dumps(inspect_download(target)), "application/json", {"Cache-Control": "no-store"})
            except Exception as e:
                return self.send_body(403 if isinstance(e, ValueError) else 502, friendly_error(e))
        if parsed.path == "/log":
            if not self.same_origin_ok() or self.headers.get("X-Bench-Token") != TOKEN:
                return self.send_body(403, "Refused.")
            with STATE_LOCK:
                body = json.dumps({k: STATE[k] for k in ("scripts", "requests", "cookies")})
            return self.send_body(200, body, "application/json", {"Cache-Control": "no-store"})
        if parsed.path == "/favicon.ico":
            return self.send_body(204, b"")
        return self.send_body(404, "Not found")

    def do_POST(self):
        route = urllib.parse.urlsplit(self.path)
        if route.path not in ("/stage", "/scan-file"):
            return self.send_body(404, "Not found")
        if not self.same_origin_ok() or self.headers.get("X-Bench-Token") != TOKEN:
            return self.send_body(403, "Refused.")
        if route.path == "/scan-file":
            # A file the page built in the browser (for example a Blob behind a Download button), sent as raw bytes.
            q = urllib.parse.parse_qs(route.query)
            try:
                data = self.read_body(DL_MAX)
                return self.send_body(200, json.dumps(inspect_download(q.get("name", ["file"])[0][:120], data, q.get("type", [""])[0][:100])),
                                      "application/json", {"Cache-Control": "no-store"})
            except Exception as e:
                return self.send_body(413 if isinstance(e, OverflowError) else 502, friendly_error(e))
        try:
            payload = json.loads(self.read_body(30 * 1024 * 1024).decode("utf-8"))
            with STATE_LOCK:
                STATE["html"] = str(payload["html"])
                STATE["url"] = str(payload["url"])
                STATE["scripts"] = []
        except Exception as e:
            return self.send_body(400, "Bad staging request: " + str(e))
        return self.send_body(200, "ok")


class SpecimenHandler(Base):
    """Port 8788: the site under test. Pages get the staged HTML; everything else is relayed upstream."""

    def handle_any(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/__bench/boot":
            return self.send_body(200, BOOT_HTML, "text/html; charset=utf-8", {"Cache-Control": "no-store"})
        if parsed.path == "/__bench/sw.js":
            return self.send_body(200, SW_JS, "text/javascript; charset=utf-8",
                                  {"Service-Worker-Allowed": "/", "Cache-Control": "no-store"})
        if parsed.path == "/__bench/p":
            return self.relay(parsed)
        if parsed.path == "/__bench/ws":
            return self.ws_tunnel(parsed)
        if self.command in ("GET", "HEAD"):
            with STATE_LOCK:
                html = STATE["html"]
            return self.send_body(200, html, "text/html; charset=utf-8", {"Cache-Control": "no-store"})
        return self.send_body(405, "")

    def relay(self, parsed):
        q = urllib.parse.parse_qs(parsed.query)
        with STATE_LOCK:
            page_url = STATE["url"]
        if "u" in q:
            target = q["u"][0]
        elif "rel" in q:
            target = urllib.parse.urljoin(page_url, q["rel"][0])
        else:
            return self.send_body(400, "")
        try:
            page_headers = json.loads(urllib.parse.unquote(self.headers.get("x-bench-h") or "%7B%7D"))
        except Exception:
            page_headers = {}
        try:
            body = self.read_body(MAX_BYTES) if self.command not in ("GET", "HEAD") else None
            status, headers, data, final = upstream(target, self.command, body, page_headers, page_url)
        except Exception as e:
            return self.send_body(403 if isinstance(e, ValueError) else 502, friendly_error(e))
        extra = {}
        for k, v in headers.items():
            if k.lower() not in DROP_RESP and not k.lower().startswith("access-control-"):
                extra[k] = v
        extra["Cache-Control"] = "no-store"  # every test run sees every file fresh
        record(final, status, headers, len(data))
        ctype = (headers.get("Content-Type") or "").lower()
        if status < 400 and ("javascript" in ctype or "ecmascript" in ctype):
            with STATE_LOCK:
                if target not in STATE["scripts"] and len(STATE["scripts"]) < 500:
                    STATE["scripts"].append(target)
        return self.send_body(status, data, headers.get("Content-Type") or "application/octet-stream", extra)

    def ws_tunnel(self, parsed):
        """Tunnel a WebSocket: repeat the browser's upgrade request upstream with the tested site's Origin,
        hand the server's answer back, then pass bytes both ways untouched."""
        target = urllib.parse.parse_qs(parsed.query).get("u", [""])[0]
        u = urllib.parse.urlsplit(target)
        if u.scheme not in ("ws", "wss") or self.headers.get("Upgrade", "").lower() != "websocket":
            return self.send_body(400, "Not a WebSocket request.")
        try:
            check_target(target)
            port = u.port or (443 if u.scheme == "wss" else 80)
            raw = socket.create_connection((u.hostname, port), timeout=15)
            up = SSL_CTX.wrap_socket(raw, server_hostname=u.hostname) if u.scheme == "wss" else raw
        except Exception as e:
            return self.send_body(502, friendly_error(e))
        with STATE_LOCK:
            site_origin = origin_of(STATE["url"]) or "null"
        host = u.hostname + ("" if u.port is None else ":%d" % u.port)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        lines = ["GET %s HTTP/1.1" % path, "Host: " + host, "Origin: " + site_origin, "User-Agent: " + UA,
                 "Upgrade: websocket", "Connection: Upgrade", "Pragma: no-cache", "Cache-Control: no-cache"]
        for h in ("Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"):
            if self.headers.get(h):
                lines.append(h + ": " + self.headers.get(h))
        try:
            up.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = up.recv(4096)
                if not chunk or len(buf) > 65536:
                    raise ConnectionError("the server closed the connection during the handshake")
                buf += chunk
        except Exception as e:
            up.close()
            return self.send_body(502, friendly_error(e))
        head, rest = buf.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n", 1)[0]
        self.close_connection = True
        client = self.connection
        try:
            client.sendall(head + b"\r\n\r\n" + rest)
        except Exception:
            up.close()
            return
        if b" 101 " not in status_line + b" ":
            up.close()
            return
        up.settimeout(None)
        client.settimeout(None)

        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        t = threading.Thread(target=pipe, args=(up, client), daemon=True)
        t.start()
        pipe(client, up)
        t.join(timeout=5)
        up.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = handle_any

    def do_OPTIONS(self):
        return self.send_body(204, b"")


def start(handler, port, tries=20):
    for p in range(port, port + tries):
        try:
            return http.server.ThreadingHTTPServer(("127.0.0.1", p), handler)
        except OSError:
            continue
    sys.exit("No free port between %d and %d." % (port, port + tries - 1))


def main():
    global ALLOW_PRIVATE
    ap = argparse.ArgumentParser(description="Local helper for Sniff Test.")
    ap.add_argument("--port", type=int, default=8787, help="port for the bench (the site under test uses the next free one)")
    ap.add_argument("--allow-private", action="store_true", help="allow fetching local network addresses (to test your own dApp)")
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = ap.parse_args()
    ALLOW_PRIVATE = args.allow_private

    bench = start(BenchHandler, args.port)
    specimen = start(SpecimenHandler, bench.server_address[1] + 1)
    bench.specimen_port = specimen.server_address[1]
    OWN_PORTS.update({bench.server_address[1], specimen.server_address[1]})
    threading.Thread(target=specimen.serve_forever, daemon=True).start()

    url = "http://127.0.0.1:%d/" % bench.server_address[1]
    print("Sniff Test is running at " + url, flush=True)
    print("Sites under test run at http://127.0.0.1:%d/" % specimen.server_address[1], flush=True)
    print("Open it in a browser profile with NO wallet extensions. Press Ctrl+C to stop.", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        bench.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
