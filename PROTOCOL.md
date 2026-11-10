# EC71 2.4.3 protocol notes

## Problem

The legacy go2rtc Kasa source connects to `19443/https/stream/mixed` using ordinary certificate-based TLS and Basic authentication. EC71 2.4.3 rejects that handshake with TLS alert 40. Cipher, SNI, certificate-validation, reboot, and Third-Party Compatibility tests do not fix it.

## Recovered flow

### 1. TPAP/NOC capability

The camera advertises TPAP on TCP 10443 with TLS mode 1, NOC enabled, and SPAKE2+ available. The working path here uses NOC.

### 2. NOC enrollment

- Log in to TP-Link cloud and resolve the CVM service using `nbu.cvm-server-v2`.
- Generate an EC P-256 private key and a SHA256withECDSA CSR with OU `UNOC`.
- POST the account token and CSR to `/v1/certificate/noc/app/apply`.
- Cache the returned client certificate, chain, and locally generated private key.

### 3. NOC KEX and proof

Send JSON `login` requests to `https://CAMERA:10443/`:

- `noc_kex` includes hashed `admin`, an `encryption` list, and a Base64-encoded compressed EC public point.
- `noc_proof` includes Base64-encoded AES-CCM ciphertext and tag.
- The client proof signs the original certificate DER, intermediate DER if present, and the ephemeral public keys.
- Keep a persistent HTTPS session for KEX, proof, and subsequent `/ds` traffic. Switching HTTP clients between these steps caused failures during testing.
- The returned `stok`, `start_seq`, and expiry establish the encrypted session.

### 4. Media PSK request

Over `/stok=.../ds`, send:

```json
{
  "smartlife.cam.ipcamera.system": {"get_media_psk": {}},
  "context": {"source": "Kasa application client UUID"}
}
```

The response contains `psk_id`, `psk_key`, and `expired`. Some legacy errors use Base64 plus XOR-autokey encoding even inside the decrypted response, so both layers must be handled.

### 5. Media TLS-PSK connection

Connect to TCP 19443 using:

- TLS 1.2
- `ECDHE-PSK-AES128-CBC-SHA256`
- The returned PSK identity and key

The official client treats the PSK key as UTF-8 bytes. OpenSSL's `-psk` argument therefore receives the hexadecimal representation of those bytes.

### 6. Media HTTP request

Request `/https/stream/mixed` with Basic authentication. The Basic password field is itself base64-encoded plaintext. The response is `multipart/x-mixed-replace` with H.264 video and G.711 audio parts, which go2rtc can package as RTSP.

## Verification

The implementation was validated with:

- Successful cloud NOC enrollment
- Successful local NOC KEX/proof
- Successful PSK retrieval
- Successful OpenSSL media handshake
- HTTP 200 multipart media response
- go2rtc SDP containing H.264 and PCMU
- Actual RTP traffic after RTSP PLAY
- Two cameras with independent PSKs and proxy instances
