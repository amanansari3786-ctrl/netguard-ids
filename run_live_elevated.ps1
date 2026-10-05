$ErrorActionPreference = "Continue"
$root = "C:\Users\amana\netguard-ids"
$py = Join-Path $root ".venv\Scripts\python.exe"
$log = Join-Path $root "data\live_capture.log"
New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null
"[$(Get-Date -Format o)] elevated start, user=$env:USERNAME" | Out-File $log -Encoding utf8

# Loopback needs admin; Wi-Fi needs admin for full promiscuous capture.
& $py (Join-Path $root "netguard.py") watch `
    --iface "Loopback Pseudo-Interface 1" `
    --duration 90 --db (Join-Path $root "data\live.db") `
    --jsonl (Join-Path $root "data\live.jsonl") `
    --progress-every 0 *>&1 |
    Tee-Object -FilePath $log -Append

"[$(Get-Date -Format o)] elevated done" | Out-File $log -Append -Encoding utf8
