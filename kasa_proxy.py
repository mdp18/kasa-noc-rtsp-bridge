"""Local HTTPS proxy for EC71 2.4.x media TLS-PSK streams.

The camera requires a provisioned PSK and TLS 1.2 with
ECDHE-PSK-AES128-CBC-SHA256. Python's ssl module does not expose TLS-PSK, so this
prototype uses the installed OpenSSL s_client process as the camera transport.

Environment:
  KASA_USERNAME / KASA_PASSWORD   TP-Link account (used for Basic auth)
  KASA_CAMERA_HOST                camera IP address (required)
  KASA_PROXY_HOST                 default 127.0.0.1
  KASA_PROXY_PORT                 default 19444

PSK input:
  secrets/active-psk.json, created by probe_noc.py
"""
from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
SECRETS = ROOT / "secrets"
OPENSSL = Path(os.environ.get("OPENSSL_PATH", "openssl"))
CAMERA_HOST = os.environ.get("KASA_CAMERA_HOST")
if not CAMERA_HOST:
    raise RuntimeError("Set KASA_CAMERA_HOST to the camera IP address")
LISTEN_HOST = os.environ.get("KASA_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("KASA_PROXY_PORT", "19444"))
CERT_PATH = SECRETS / "proxy-cert.pem"
KEY_PATH = SECRETS / "proxy-key.pem"
PSK_PATH = Path(os.environ.get("KASA_PSK_FILE", "active-psk.json"))
if not PSK_PATH.is_absolute():
    PSK_PATH = SECRETS / PSK_PATH
TLS_CIPHER = "ECDHE-PSK-AES128-CBC-SHA256"


def refresh_psk() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "probe_noc.py")],
        cwd=ROOT,
        capture_output=True,
        timeout=90,
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        # Do not print captured output: protocol debug logs can contain session data.
        raise RuntimeError("Unable to refresh media PSK")


def load_psk() -> dict:
    if not PSK_PATH.exists():
        refresh_psk()
    record = json.loads(PSK_PATH.read_text(encoding="utf-8"))
    if not record.get("psk_id") or not record.get("psk_key"):
        raise RuntimeError("PSK file is missing psk_id/psk_key")
    obtained = int(record.get("obtained_at", 0))
    expires = int(record.get("expired", 0) or 0)
    if expires and obtained and time.time() >= obtained + expires - 60:
        refresh_psk()
        record = json.loads(PSK_PATH.read_text(encoding="utf-8"))
    return record


def ensure_proxy_certificate() -> None:
    if CERT_PATH.exists() and KEY_PATH.exists():
        return
    SECRETS.mkdir(exist_ok=True)
    subprocess.run(
        [
            str(OPENSSL),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-days",
            "365",
            "-keyout",
            str(KEY_PATH),
            "-out",
            str(CERT_PATH),
        ],
        check=True,
        capture_output=True,
    )


def camera_authorization() -> str:
    username = os.environ.get("KASA_USERNAME", "")
    password = os.environ.get("KASA_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("KASA_USERNAME and KASA_PASSWORD are required")
    # EC71's media endpoint expects base64(plaintext password) inside Basic auth.
    password_b64 = base64.b64encode(password.encode()).decode()
    return "Basic " + base64.b64encode(f"{username}:{password_b64}".encode()).decode()


class CameraConnection:
    def __init__(self) -> None:
        psk = load_psk()
        self.process = subprocess.Popen(
            [
                str(OPENSSL),
                "s_client",
                "-connect",
                f"{CAMERA_HOST}:19443",
                "-tls1_2",
                "-cipher",
                f"{TLS_CIPHER}:@SECLEVEL=0",
                "-psk_identity",
                psk["psk_id"],
                "-psk",
                psk["psk_key"].encode().hex(),
                "-quiet",
                "-ign_eof",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        if not self.process.stdin or not self.process.stdout:
            raise RuntimeError("Unable to start OpenSSL camera transport")

    def request(self, path: str, authorization: str) -> None:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {CAMERA_HOST}:19443\r\n"
            f"Authorization: {authorization}\r\n"
            "User-Agent: Kasa/3.4.750\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode()
        self.process.stdin.write(request)
        self.process.stdin.flush()

    def read_headers(self) -> tuple[int, dict[str, str]]:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.process.stdout.read(1)
            if not chunk:
                raise RuntimeError("Camera closed before sending HTTP headers")
            data.extend(chunk)
            if len(data) > 32768:
                raise RuntimeError("Camera HTTP headers are too large")
        header_bytes = bytes(data).split(b"\r\n\r\n", 1)[0]
        lines = header_bytes.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        return status, headers

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        print(f"proxy: connection from {self.client_address}", flush=True)
        super().handle()

    def log_message(self, format: str, *args) -> None:
        # Do not log query strings or credentials.
        print(f"proxy: {self.client_address[0]} {format % args}")

    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        camera = None
        try:
            print("proxy: creating camera connection", flush=True)
            authorization = self.headers.get("Authorization") or camera_authorization()
            camera = CameraConnection()
            print("proxy: sending camera request", flush=True)
            camera.request(self.path, authorization)
            status, headers = camera.read_headers()
            print(f"proxy: camera HTTP {status}", flush=True)
            self.send_response(status)
            for name in ("Content-Type", "Transfer-Encoding"):
                if name.lower() in headers:
                    self.send_header(name, headers[name.lower()])
            if status != 200 and "content-length" in headers:
                self.send_header("Content-Length", headers["content-length"])
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

            while True:
                chunk = camera.process.stdout.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        except Exception as exc:
            print(f"proxy: camera request failed: {type(exc).__name__}: {exc}")
            if not self.wfile.closed:
                try:
                    self.send_error(502, "Camera proxy failure")
                except (BrokenPipeError, ConnectionResetError):
                    pass
        finally:
            if camera is not None:
                camera.close()


def main() -> None:
    ensure_proxy_certificate()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), ProxyHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_PATH, KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"EC71 proxy listening on https://{LISTEN_HOST}:{LISTEN_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
