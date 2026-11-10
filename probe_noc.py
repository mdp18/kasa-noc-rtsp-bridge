"""Request EC71 media PSK using the official NOC-first authentication order."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import sys
import time
import struct
import base64

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / ".vendor" / "python-kasa"))

from kasa.credentials import Credentials
from kasa.deviceconfig import (
    DeviceConfig,
    DeviceConnectionParameters,
    DeviceEncryptionType,
    DeviceFamily,
)
from kasa.transports.tpaptransport import BaseAuthContext, TpapNOCData, TpapTransport
from probe_media_psk import test_psk
import requests
import urllib3
import ssl
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


async def main() -> None:
    host = os.environ.get("KASA_CAMERA_HOST")
    if not host:
        raise RuntimeError("Set KASA_CAMERA_HOST to the camera IP address")
    config = DeviceConfig(
        host=host,
        timeout=15,
        port_override=10443,
        credentials=Credentials(
            os.environ["KASA_USERNAME"], os.environ["KASA_PASSWORD"]
        ),
        connection_type=DeviceConnectionParameters(
            device_family=DeviceFamily.SmartIpCamera,
            encryption_type=DeviceEncryptionType.Tpap,
            https=True,
            http_port=10443,
        ),
    )
    transport = TpapTransport(config=config)
    auth = transport._authenticator
    persistent_http = requests.Session()
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_context.check_hostname = False
    tls_context.verify_mode = ssl.CERT_NONE
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.maximum_version = ssl.TLSVersion.TLSv1_2
    tls_context.set_ciphers("AES256-GCM-SHA384")

    class CameraAdapter(HTTPAdapter):
        def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
            kwargs["ssl_context"] = tls_context
            return super().init_poolmanager(connections, maxsize, block=block, **kwargs)

    persistent_http.mount("https://", CameraAdapter())

    async def persistent_login_tslp(self, params, *, step_name):
        body = {"method": "login", "params": params}
        response = persistent_http.post(
            str(self._transport._app_url.with_path("/")),
            json=body,
            headers={
                "Content-Type": "application/json",
                "Connection": "keep-alive",
                "Accept": "*/*",
                "User-Agent": "Kasa/3.4.750 (iPhone; iOS 27.2; Scale/3.00)",
            },
            verify=False,
            timeout=15,
        )
        data = response.json()
        print(step_name, "HTTP", response.status_code, "err_code", data.get("err_code"), "result_keys", list(data.get("result", {}).keys()))
        if response.status_code != 200:
            raise RuntimeError(f"{step_name} returned HTTP {response.status_code}: {data}")
        self._authenticator._handle_response_error_code(data, step_name)
        return data.get("result") or {}

    BaseAuthContext._login_tslp = persistent_login_tslp

    # EC71 advertises these values through cloud get_sysinfo. This older TPAP
    # implementation otherwise issues an in-band discover that cameras reject.
    auth._tpap_noc = True
    auth._tpap_tls = 1
    auth._tpap_dac = False
    auth._tpap_pake = [2]

    async def skip_camera_discovery() -> None:
        return None

    auth._discover = skip_camera_discovery
    secret_dir = ROOT / "secrets"
    secret_dir.mkdir(exist_ok=True)
    noc_path = secret_dir / "noc-materials.json"
    if noc_path.exists():
        auth._noc_data = TpapNOCData(**json.loads(noc_path.read_text()))
    try:
        auth._ensure_noc()
        noc = auth._noc_data
        if noc is not None:
            noc_path.write_text(json.dumps(noc.__dict__, indent=2), encoding="utf-8")
        await transport._authenticator.ensure_authenticator()
        print("Local NOC/TPAP session established")
        seq = auth.seq
        cipher = auth.cipher
        ds_url = auth.ds_url
        if seq is None or cipher is None or ds_url is None:
            raise RuntimeError("NOC session fields missing")
        request = json.dumps(
            {
                "smartlife.cam.ipcamera.system": {"get_media_psk": {}},
                "context": {"source": "46a4d58b-6279-432c-ae23-e115c2db8354"},
            },
            separators=(",", ":"),
        )
        payload = struct.pack(">I", seq) + cipher.encrypt(request.encode(), seq)
        ds_response = persistent_http.post(
            str(ds_url),
            data=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Accept": "application/octet-stream",
                "Connection": "keep-alive",
            },
            verify=False,
            timeout=15,
        )
        print("DS HTTP", ds_response.status_code, "headers", dict(ds_response.headers))
        raw = ds_response.content
        plaintext = None
        if raw and all(32 <= byte <= 126 for byte in raw):
            raw = base64.b64decode(raw)
            key = 0xAB
            decoded = bytearray()
            for byte in raw:
                decoded.append(key ^ byte)
                key = byte
            if decoded.startswith(b"{"):
                plaintext = bytes(decoded)
        if plaintext is None:
            rseq = struct.unpack(">I", raw[:4])[0]
            plaintext = cipher.decrypt(raw[4:], rseq)
        if plaintext and all(32 <= byte <= 126 for byte in plaintext):
            try:
                wrapped = base64.b64decode(plaintext, validate=True)
                key = 0xAB
                decoded = bytearray()
                for byte in wrapped:
                    decoded.append(key ^ byte)
                    key = byte
                if decoded.startswith(b"{"):
                    plaintext = bytes(decoded)
            except ValueError:
                pass
        response = json.loads(plaintext)
        method = response.get("smartlife.cam.ipcamera.system", {}).get("get_media_psk", {})
        psk_id = method.get("psk_id")
        psk_key = method.get("psk_key")
        expired = method.get("expired")
        if not psk_id or not psk_key:
            raise RuntimeError(f"No PSK returned: {method}")
        record = {
            "host": host,
            "psk_id": psk_id,
            "psk_key": psk_key,
            "expired": expired,
            "obtained_at": int(time.time()),
        }
        secret_dir = ROOT / "secrets"
        psk_path = Path(os.environ.get("KASA_PSK_FILE", "active-psk.json"))
        if not psk_path.is_absolute():
            psk_path = secret_dir / psk_path
        psk_path.write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )
        ok, details = test_psk(host, psk_id, psk_key)
        print(
            f"PSK received (expires in {expired}s); "
            f"media TLS handshake {'SUCCESS' if ok else 'failed'}"
        )
        if not ok:
            print(details)
            raise RuntimeError("Media PSK handshake failed")
        print("OpenSSL negotiated ECDHE-PSK-AES128-CBC-SHA256")
    finally:
        await transport.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(main())
