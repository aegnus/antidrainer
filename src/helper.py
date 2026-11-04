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
                return self.send_body(502, "The site answered with HTTP %d." % status)
            charset = headers.get_content_charset() or "utf-8"
            return self.send_body(200, data.decode(charset, errors="replace"),
                                  extra={"X-Final-URL": final, "Cache-Control": "no-store"})
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
        if urllib.parse.urlsplit(self.path).path != "/stage":
            return self.send_body(404, "Not found")
        if not self.same_origin_ok() or self.headers.get("X-Bench-Token") != TOKEN:
            return self.send_body(403, "Refused.")
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
