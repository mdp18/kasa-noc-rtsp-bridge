$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $root 'config.json'
if (-not (Test-Path $configPath)) {
    throw 'Copy config.example.json to config.json and edit it first.'
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    throw 'Run setup.ps1 first.'
}

if (-not $env:KASA_USERNAME) {
    $env:KASA_USERNAME = Read-Host 'TP-Link email'
}
if (-not $env:KASA_PASSWORD) {
    $secure = Read-Host 'TP-Link password' -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $env:KASA_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

foreach ($camera in $config.cameras) {
    if (-not (Get-NetTCPConnection -LocalPort $camera.proxy_port -State Listen -ErrorAction SilentlyContinue)) {
        $env:KASA_CAMERA_HOST = $camera.host
        $env:KASA_PROXY_HOST = '127.0.0.1'
        $env:KASA_PROXY_PORT = [string]$camera.proxy_port
        $env:KASA_PSK_FILE = $camera.psk_file
        Start-Process -FilePath $python -ArgumentList @("$root\kasa_proxy.py") `
            -WorkingDirectory $root -WindowStyle Hidden `
            -RedirectStandardOutput "$root\$($camera.name).log" `
            -RedirectStandardError "$root\$($camera.name)-error.log"
    }
    Write-Host "$($camera.name): rtsp://$($config.public_host):8554/$($camera.name)"
}

if ($config.go2rtc_path -and (Test-Path $config.go2rtc_path) -and -not (Get-Process go2rtc -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $config.go2rtc_path -ArgumentList @('-c', $config.go2rtc_config) `
        -WorkingDirectory (Split-Path -Parent $config.go2rtc_path) -WindowStyle Hidden
}
