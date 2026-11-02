#!/usr/bin/env python3
"""JWT authentication reverse proxy (stdlib only, no dependencies).

Listens on LISTEN_PORT (the "port 80" of the exercise: the internet-facing
entrypoint) and forwards only requests carrying a valid HS256 JWT in the
`Authorization: Bearer <token>` header to UPSTREAM (the legacy service on the
internal network, e.g. http://127.0.0.1:8081).

Config via environment:
    LISTEN_PORT  public port (default 8080)
    UPSTREAM     internal backend base URL (default http://127.0.0.1:8081)
    JWT_SECRET   HMAC secret for HS256 (default "changeme-in-prod")
    JWT_LEEWAY   clock-skew tolerance in seconds (default 30)

Run:
    UPSTREAM=http://127.0.0.1:8081 JWT_SECRET=mysecret python3 jwt_proxy.py
"""

import base64
import hashlib
import hmac
import json
import os
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
UPSTREAM = os.environ.get("UPSTREAM", "http://127.0.0.1:8081").rstrip("/")
JWT_SECRET = os.environ.get("JWT_SECRET", "changeme-in-prod")
JWT_LEEWAY = int(os.environ.get("JWT_LEEWAY", "30"))

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}

_up = urlsplit(UPSTREAM)
UP_HOST, UP_PORT = _up.hostname, _up.port or 80


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(token: str):
    """Return (ok, payload-or-error-message)."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return False, "malformed token"
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except Exception:
        return False, "bad base64/json"
    if header.get("alg") != "HS256":
        return False, "only HS256 accepted"
    expected = hmac.new(
        JWT_SECRET.encode(), f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        return False, "bad signature"
    exp = payload.get("exp")
    if exp is not None and time.time() > float(exp) + JWT_LEEWAY:
        return False, "token expired"
    return True, payload


class Handler(BaseHTTPRequestHandler):
    server_version = "JWTAuthProxy/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        print("%s %s" % (self.command, self.path), flush=True)

    def _reject(self, msg):
        body = json.dumps({"error": msg}).encode()
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        if self.path == "/__proxy_health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._reject("missing bearer token")
            return
        ok, info = verify_jwt(auth[len("Bearer "):].strip())
        if not ok:
            self._reject(info)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        fwd = {k: v for k, v in self.headers.items()
               if k.lower() not in HOP_BY_HOP and k.lower() != "authorization"}
        fwd["Host"] = f"{UP_HOST}:{UP_PORT}"
        fwd["X-Forwarded-For"] = self.client_address[0]
        conn = HTTPConnection(UP_HOST, UP_PORT, timeout=30)
        conn.request(self.command, self.path, body=body, headers=fwd)
        resp = conn.getresponse()
        data = resp.read()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP_BY_HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print("proxy on :%d -> %s" % (LISTEN_PORT, UPSTREAM), flush=True)
    srv.serve_forever()
