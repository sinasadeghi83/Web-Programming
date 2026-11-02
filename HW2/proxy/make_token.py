#!/usr/bin/env python3
"""Issue an HS256 JWT for the proxy (demo helper, stdlib only).

Usage: JWT_SECRET=mysecret python3 make_token.py [subject] [minutes-valid]
Prints a bearer token.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time

secret = os.environ.get("JWT_SECRET", "changeme-in-prod")
sub = sys.argv[1] if len(sys.argv) > 1 else "sina"
ttl = int(sys.argv[2]) if len(sys.argv) > 2 else 60


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64(json.dumps(
    {"sub": sub, "iat": int(time.time()),
     "exp": int(time.time()) + ttl * 60}).encode())
sig = b64(hmac.new(secret.encode(), f"{header}.{payload}".encode(),
                   hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
