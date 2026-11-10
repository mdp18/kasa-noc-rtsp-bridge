$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
$vendor = Join-Path $root '.vendor\python-kasa'

& $python -m venv "$root\.venv"
& "$root\.venv\Scripts\python.exe" -m pip install -r "$root\requirements.txt"

if (-not (Test-Path $vendor)) {
    git clone https://github.com/ZeliardM/python-kasa.git $vendor
}
git -C $vendor checkout 43b779d
Copy-Item "$root\vendor\tpaptransport.py" "$vendor\kasa\transports\tpaptransport.py" -Force

Write-Host 'Setup complete. Copy config.example.json to config.json and edit your camera IPs.'
Write-Host 'Set OPENSSL_PATH if openssl is not on PATH.'
