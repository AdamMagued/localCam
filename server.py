#!/usr/bin/env python3
"""Password-protected camera streaming for a private local network."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import os
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
STATE = ROOT / ".localcam"
MAX_FRAME_BYTES = 2_000_000
SESSION_SECONDS = 12 * 60 * 60


def default_host() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()


def ensure_private_host(host: str) -> None:
    address = ipaddress.ip_address(host)
    if not (address.is_private or address.is_loopback):
        raise SystemExit("Refusing to bind to a public IP address.")


def ensure_certificate(host: str) -> tuple[Path, Path]:
    STATE.mkdir(exist_ok=True)
    cert, key = STATE / f"cert-{host}.pem", STATE / f"key-{host}.pem"
    if cert.exists() and key.exists():
        return cert, key
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "365", "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=localCam",
            "-addext", f"subjectAltName=IP:{host},DNS:localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    return cert, key


class CameraServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], password: str):
        super().__init__(address, Handler)
        self.password_hash = hashlib.sha256(password.encode()).digest()
        self.session_key = secrets.token_bytes(32)
        self.frame: bytes | None = None
        self.frame_lock = threading.Lock()
        self.host_ip = address[0]

    def make_session(self) -> str:
        expires = str(int(time.time()) + SESSION_SECONDS)
        signature = hmac.new(self.session_key, expires.encode(), hashlib.sha256).hexdigest()
        return f"{expires}.{signature}"

    def valid_session(self, value: str) -> bool:
        try:
            expires, signature = value.split(".", 1)
            expected = hmac.new(self.session_key, expires.encode(), hashlib.sha256).hexdigest()
            return int(expires) > time.time() and hmac.compare_digest(signature, expected)
        except (ValueError, TypeError):
            return False


class Handler(http.server.BaseHTTPRequestHandler):
    server: CameraServer
    server_version = "localCam"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.client_address[0]} - {fmt % args}")

    def allowed_client(self) -> bool:
        address = ipaddress.ip_address(self.client_address[0])
        return address.is_private or address.is_loopback

    def authenticated(self) -> bool:
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        session = cookie.get("localcam_session")
        return bool(session and self.server.valid_session(session.value))

    def local_broadcaster(self) -> bool:
        return self.client_address[0] in {self.server.host_ip, "127.0.0.1", "::1"}

    def response_headers(self, status: int, content_type: str, length: int = 0) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )

    def send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.response_headers(status, content_type, len(body))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header(
                "Set-Cookie",
                f"localcam_session={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}",
            )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if not self.allowed_client():
            return self.send_error(403)
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            return self.send_file("login.html")
        if path == "/style.css":
            return self.send_file("style.css", "text/css; charset=utf-8")
        if path == "/app.js":
            return self.send_file("app.js", "text/javascript; charset=utf-8")
        if not self.authenticated():
            return self.redirect("/login")
        if path == "/":
            return self.send_file("viewer.html")
        if path == "/broadcast":
            if not self.local_broadcaster():
                return self.send_error(403, "Broadcast controls are available only on the camera laptop")
            return self.send_file("broadcast.html")
        if path == "/frame":
            with self.server.frame_lock:
                frame = self.server.frame
            if frame is None:
                return self.send_bytes(204, "image/jpeg", b"")
            return self.send_bytes(200, "image/jpeg", frame)
        self.send_error(404)

    def send_file(self, name: str, content_type: str = "text/html; charset=utf-8") -> None:
        try:
            body = (PUBLIC / name).read_bytes()
        except FileNotFoundError:
            return self.send_error(404)
        self.send_bytes(200, content_type, body)

    def do_POST(self) -> None:
        if not self.allowed_client():
            return self.send_error(403)
        path = urllib.parse.urlsplit(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_error(400)

        if path == "/login":
            if not 0 <= length <= 4096:
                return self.send_error(413)
            values = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            supplied = hashlib.sha256(values.get("password", [""])[0].encode()).digest()
            if hmac.compare_digest(supplied, self.server.password_hash):
                return self.redirect("/", self.server.make_session())
            return self.redirect("/login?wrong=1")

        if path == "/publish":
            if not self.authenticated() or not self.local_broadcaster():
                return self.send_error(403)
            if self.headers.get_content_type() != "image/jpeg" or not 0 < length <= MAX_FRAME_BYTES:
                return self.send_error(400)
            frame = self.rfile.read(length)
            with self.server.frame_lock:
                self.server.frame = frame
            return self.send_bytes(204, "text/plain", b"")
        self.send_error(404)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", help="private LAN IP to bind to")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    host = args.host or default_host()
    ensure_private_host(host)
    password = os.environ.get("LOCALCAM_PASSWORD") or getpass.getpass("Viewer password: ")
    if len(password) < 8:
        raise SystemExit("Use a password with at least 8 characters.")
    cert, key = ensure_certificate(host)
    server = CameraServer((host, args.port), password)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"\nBroadcast on this laptop: https://{host}:{args.port}/broadcast")
    print(f"Viewer link:              https://{host}:{args.port}/")
    print("Keep this terminal open. Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
