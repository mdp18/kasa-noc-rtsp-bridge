"""OpenSSL helper for testing a provisioned EC71 media PSK.

The official client passes psk_key.encode() to BouncyCastle. OpenSSL expects the
same bytes encoded as hexadecimal.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

OPENSSL = Path(os.environ.get("OPENSSL_PATH", "openssl"))


def test_psk(host: str, psk_id: str, psk_key: str) -> tuple[bool, str]:
    """Return whether the camera accepts the PSK, without logging its value."""
    command = [
        str(OPENSSL),
        "s_client",
        "-connect",
        f"{host}:19443",
        "-tls1_2",
        "-cipher",
        "ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0",
        "-psk_identity",
        psk_id,
        "-psk",
        psk_key.encode().hex(),
        "-brief",
    ]
    try:
        completed = subprocess.run(
            command,
            input="Q\n",
            text=True,
            capture_output=True,
            timeout=12,
        )
        output = completed.stdout + completed.stderr
        return "CONNECTION ESTABLISHED" in output, output[-2000:]
    except subprocess.TimeoutExpired:
        return False, "OpenSSL timed out"
