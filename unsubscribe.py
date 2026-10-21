#!/usr/bin/env python3
"""RFC 8058 one-click unsubscribe endpoint for the SES platform (Gate 3).

Every live send carries:
  List-Unsubscribe: <https://{SES_UNSUB_HOST}/u/{token}>, <mailto:unsubscribe@{from_domain}?subject=unsubscribe>
  List-Unsubscribe-Post: List-Unsubscribe=One-Click

The token is self-contained: base64url(email) + '.' + HMAC-SHA256(secret,
email)[:24] — no per-recipient state to look up, and a forged token cannot
opt out a third party. The secret lives in data/unsub_secret.key (0600,
generated on first use, never printed).

Both hit types record the opt-out into the SHARED suppression registry
(reason='unsubscribe', source='ses-unsubscribe-endpoint'), after which the
sender refuses the address pre-send in every program:
  * POST /u/{token} with body 'List-Unsubscribe=One-Click'  (RFC 8058)
  * GET  /u/{token}                                        (link click)

Serve it:  python3 unsubscribe.py --serve --port 8080
Deployment note: before any live staircase step, this must run at a public
HTTPS URL and SES_UNSUB_HOST must be set to that host — sender.py refuses
--live without SES_UNSUB_HOST, so a placeholder endpoint can never ship.
"""
import base64, hashlib, hmac, json, os, sys
import suppression as S

BASE = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(BASE, "data", "unsub_secret.key")


def _secret():
    # Deployed instances (Render) have an ephemeral disk and no access to the
    # platform's secret file, so the secret is injected as SES_UNSUB_SECRET —
    # its value is the same hex string the platform keeps in
    # data/unsub_secret.key, so tokens minted by sender.py verify here.
    env = os.environ.get("SES_UNSUB_SECRET")
    if env:
        return env.strip().encode()
    if not os.path.exists(SECRET_FILE):
        os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
        with open(SECRET_FILE, "wb") as f:
            f.write(os.urandom(32).hex().encode())
        os.chmod(SECRET_FILE, 0o600)
    with open(SECRET_FILE, "rb") as f:
        return f.read().strip()


def export_key():
    """Key for the sync pull (GET /optouts?k=...). Derived from the shared
    secret under a distinct message, so an unsubscribe token (a different
    HMAC message) can never be replayed as the export key."""
    return hmac.new(_secret(), b"optouts-export", hashlib.sha256).hexdigest()


def list_optouts():
    """All opt-outs recorded by THIS instance's registry (source =
    ses-unsubscribe-endpoint). unsub_sync.py pulls these into the platform
    registry on the VM, which is the sender's durable source of truth."""
    db = S.connect()
    rows = db.execute(
        "SELECT email,reason,source,detail,first_seen,updated FROM suppressions"
        " WHERE source=?", ("ses-unsubscribe-endpoint",)).fetchall()
    db.close()
    return [{"email": r[0], "reason": r[1], "source": r[2], "detail": r[3],
             "first_seen": r[4], "updated": r[5]} for r in rows]


def mint_token(email):
    email = email.strip().lower()
    sig = hmac.new(_secret(), email.encode(), hashlib.sha256).hexdigest()[:24]
    return base64.urlsafe_b64encode(email.encode()).decode().rstrip("=") + "." + sig


def verify_token(token):
    """Return the email for a valid token, else None."""
    try:
        payload, sig = token.rsplit(".", 1)
        email = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    except Exception:
        return None
    expect = hmac.new(_secret(), email.encode(), hashlib.sha256).hexdigest()[:24]
    return email if hmac.compare_digest(sig, expect) else None


def record_optout(email, via):
    db = S.connect()
    S.add_suppression(db, email, "unsubscribe", "ses-unsubscribe-endpoint",
                      detail=f"RFC 8058 opt-out via {via}")
    db.close()
    return email


def make_handler():
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def _handle(self, via):
            parts = self.path.strip("/").split("/")
            if len(parts) == 2 and parts[0] == "u":
                email = verify_token(parts[1])
                if email:
                    record_optout(email, via)
                    body = b"Unsubscribed. You will not be emailed again."
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
            body = b"Invalid unsubscribe link."
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _export(self):
            from urllib.parse import urlparse, parse_qs
            key = parse_qs(urlparse(self.path).query).get("k", [""])[0]
            if hmac.compare_digest(key, export_key()):
                body = json.dumps(list_optouts()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b"Forbidden."
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)  # body is 'List-Unsubscribe=One-Click'
            self._handle("one-click POST")

        def do_GET(self):
            from urllib.parse import urlparse
            if urlparse(self.path).path == "/optouts":
                self._export()
                return
            if urlparse(self.path).path in ("/", "/healthz"):
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._handle("link GET")

        def log_message(self, *a):
            pass

    return Handler


def serve(port=8080, host="0.0.0.0"):
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer((host, port), make_handler()).serve_forever()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    if args.serve:
        serve(args.port)
    else:
        print("usage: unsubscribe.py --serve [--port N]")
