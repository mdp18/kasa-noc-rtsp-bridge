# Kasa EC71 2.4.x local streaming via NOC + media PSK

A working local-stream bridge for TP-Link Kasa EC71 cameras running firmware 2.4.3. It provisions the camera's media PSK, connects with TLS-PSK, and forwards the proprietary multipart stream to go2rtc for RTSP/Home Assistant use.

This is an independent, unofficial project and is not affiliated with TP-Link.

## What works

- NOC certificate enrollment through TP-Link cloud
- TPAP NOC KEX/proof against camera TCP 10443
- Media PSK provisioning through the encrypted TPAP channel
- TLS 1.2 `ECDHE-PSK-AES128-CBC-SHA256` media connection on TCP 19443
- H.264 video and G.711/PCMU audio through go2rtc
- Multiple cameras with separate PSK files and proxy ports
- Automatic PSK refresh when missing or near expiry

## Requirements

- Windows with PowerShell (the setup/start helpers are PowerShell)
- Python 3.11+
- Git
- OpenSSL 3 with `s_client` PSK support
- go2rtc
- An EC71 bound to your TP-Link account

## Setup

1. Run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\setup.ps1
   ```

   This creates a virtual environment, installs dependencies, checks out the required TPAP implementation, and applies the EC71 compatibility fixes in `vendor/tpaptransport.py`.

2. Copy and edit the configuration:

   ```powershell
   Copy-Item config.example.json config.json
   ```

   Set each camera's IP, proxy port, PSK filename, and the go2rtc paths. `config.json` is gitignored.

3. Add the streams from `go2rtc.example.yaml` to your go2rtc configuration. URL-encode the account email and base64-encode the password as required by go2rtc's Kasa source.

4. Start:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start.ps1
   ```

   The script prompts for the TP-Link account if the corresponding environment variables are not set.

On the first connection, the proxy provisions and caches the PSK. The NOC private key, PSKs, and proxy key are stored under `secrets/`, which is gitignored. Do not share that directory. Avoid repeatedly deleting the NOC cache because cloud certificate enrollment may be rate-limited.

## Home Assistant

Add **Settings → Devices & services → Add integration → Generic Camera** for each stream:

- Stream URL: `rtsp://GO2RTC_HOST:8554/camera1` (replace with the configured stream name)
- RTSP transport: TCP
- Username/password: blank
- Frame rate: 2 (this controls still-image polling, not camera FPS)
- Verify SSL certificate: unchecked for the proxy's local self-signed certificate
- Still image URL: optional

The go2rtc host must be reachable from Home Assistant. Check routing and local firewall rules if the initial probe times out.

## Protocol findings

See [PROTOCOL.md](PROTOCOL.md) for the recovered flow and compatibility details.

## Limitations

- RTSP carries media only; no pan/tilt controls are exposed.
- Python's standard `ssl` module does not support TLS-PSK, so the proxy uses an OpenSSL `s_client` subprocess per media connection.
- The upstream camera connection currently disables certificate verification, matching the legacy official-client behavior. The proxy binds to localhost by default.
- This has been tested with EC71 firmware 2.4.3; other models/firmware may differ.

## Upstream attribution

The TPAP implementation is derived from `ZeliardM/python-kasa` at commit `43b779d`, with EC71 compatibility changes. See `UPSTREAM-LICENSE`. The go2rtc Kasa multipart implementation informed the media-forwarding design.
