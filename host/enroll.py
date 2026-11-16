#!/usr/bin/env python3
"""One-time SSH key enrollment endpoint.

The client cannot SSH before its key is authorized, and the host disables
password auth. This endpoint closes that gap: it listens on the tailnet,
accepts one POST with a one-time code plus a public key, appends the key to
~/.ssh/authorized_keys, then exits.

Protocol:
    POST /enroll
    {"code": "<token>", "key": "ssh-ed25519 AAAA... comment"}

Responses:
    200 {"ok": true}                     key accepted (or already present)
    400 {"ok": false, "error": "..."}    malformed key or body
    401 {"ok": false, "error": "bad code"}
    404 {"ok": false, "error": "not found"}
    429 {"ok": false, "error": "..."}    too many attempts from one source

Environment:
    HERDR_ENROLL_TOKEN   required, one-time code
    HERDR_ENROLL_BIND    default 127.0.0.1, the address to listen on
    HERDR_ENROLL_PORT    default 8787
    HERDR_ENROLL_TTL     default 600 seconds
    HERDR_ENROLL_LOG     optional log path
    HERDR_ENROLL_KEYS    optional authorized_keys path

Security:
    - bind to one address only; the default is the loopback address
    - constant-time compare of the code, as bytes
    - 5 wrong attempts per source address in 5 minutes
    - no code or key in the log
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import hostlib

TOKEN = os.environ.get("HERDR_ENROLL_TOKEN", "")
BIND = os.environ.get("HERDR_ENROLL_BIND") or "127.0.0.1"
PORT = int(os.environ.get("HERDR_ENROLL_PORT", "8787"))
TTL = int(os.environ.get("HERDR_ENROLL_TTL", "600"))
LOG = os.environ.get("HERDR_ENROLL_LOG", "")
PORTFILE = os.environ.get("HERDR_ENROLL_PORTFILE", "")
KEYS = os.environ.get("HERDR_ENROLL_KEYS", os.path.expanduser("~/.ssh/authorized_keys"))

MAX_FAILS = 5
FAIL_WINDOW = 300
FAILS = {}
LOCK = threading.Lock()


def log(msg: str) -> None:
    line = "%s %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg)
    print(line, flush=True)
    if LOG:
        try:
            with open(LOG, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass


def check_attempt(source: str, supplied: str) -> str:
    """Check the code and count a wrong attempt in one locked step."""
    now = time.time()
    with LOCK:
        times = [t for t in FAILS.get(source, []) if now - t < FAIL_WINDOW]
        if len(times) >= MAX_FAILS:
            FAILS[source] = times
            return "limited"
        if not hostlib.secret_equals(supplied, TOKEN):
            times.append(now)
            FAILS[source] = times
            return "bad"
        FAILS[source] = times
        return "ok"


def record_fail(source: str) -> None:
    with LOCK:
        FAILS.setdefault(source, []).append(time.time())


class EnrollServer(ThreadingHTTPServer):
    """Concurrent server with a backlog that survives a parallel burst.

    The default backlog of 5 refused connections when twenty clients asked at
    once, which looked like a rate-limit reply of 0 to the caller.
    """

    daemon_threads = False
    # server_close() waits for the handler, so a shutdown after one
    # success cannot cut the last response in half.
    block_on_close = True
    request_queue_size = 128


class Handler(BaseHTTPRequestHandler):
    server_version = "herdr-enroll/1.0"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - required name
        try:
            self._request()
        except Exception as exc:  # noqa: BLE001 - the handler must not die
            source = self.client_address[0]
            record_fail(source)
            log("error source=%s reason=%s" % (source, exc))
            try:
                self._send(500, {"ok": False, "error": "internal error"})
            except Exception:
                pass

    def _request(self) -> None:
        if self.path != "/enroll":
            return self._send(404, {"ok": False, "error": "not found"})

        source = self.client_address[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 8192:
                return self._send(400, {"ok": False, "error": "bad body"})
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError) as exc:
            return self._send(400, {"ok": False, "error": "bad json: %s" % exc})

        code = str(data.get("code", ""))
        key = str(data.get("key", "")).strip()

        attempt = check_attempt(source, code)
        if attempt == "limited":
            log("deny source=%s reason=rate-limit" % source)
            return self._send(429, {"ok": False, "error": "too many attempts"})
        if attempt == "bad":
            log("deny source=%s reason=bad-code" % source)
            return self._send(401, {"ok": False, "error": "bad code"})

        if hostlib.parse_key(key) is None:
            log("deny source=%s reason=bad-key" % source)
            return self._send(400, {"ok": False, "error": "bad key"})

        try:
            already = hostlib.append_key(KEYS, key)
        except OSError as exc:
            log("error source=%s reason=%s" % (source, exc))
            return self._send(500, {"ok": False, "error": "cannot write keys"})

        log("ok source=%s result=%s" % (source, "already-present" if already else "added"))
        self._send(200, {"ok": True, "alreadyPresent": already})

        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, fmt: str, *args) -> None:  # silence default logging
        return


def main() -> int:
    if not TOKEN:
        print("HERDR_ENROLL_TOKEN is required", file=sys.stderr)
        return 2

    server = EnrollServer((BIND, PORT), Handler)
    actual_port = server.server_address[1]
    if PORTFILE:
        try:
            with open(PORTFILE, "w", encoding="utf-8") as handle:
                handle.write(str(actual_port))
        except OSError:
            pass
    deadline = time.time() + TTL

    def expire() -> None:
        while time.time() < deadline:
            time.sleep(1)
        log("ttl-expired")
        server.shutdown()

    threading.Thread(target=expire, daemon=True).start()
    log("listening bind=%s port=%d ttl=%d keys=%s" % (BIND, actual_port, TTL, KEYS))
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
