# NetGuard - Live capture demo (single elevated process, no window juggling)
$ErrorActionPreference = "Continue"
$root = "C:\Users\amana\netguard-ids"
$py  = "$root\.venv\Scripts\python.exe"
$data = "$root\data"
New-Item -ItemType Directory -Force -Path $data | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Admin: $isAdmin   User: $env:USERNAME"

$iface = "Loopback Pseudo-Interface 1"
$db = "$data\live.db"
$jsonl = "$data\live.jsonl"
Remove-Item $db,$jsonl -ErrorAction SilentlyContinue

Write-Host "Starting traffic generator + capture for 40s on '$iface'..." -ForegroundColor Cyan

# Run generator in background job
$job = Start-Job -ScriptBlock {
    param($root)
    Set-Location $root
    & "$root\.venv\Scripts\python.exe" -m netguard.live_traffic 38
} -ArgumentList $root

Start-Sleep -Seconds 2
& $py "$root\netguard.py" watch --iface $iface --duration 38 --db $db --jsonl $jsonl --progress-every 0
Stop-Job $job -ErrorAction SilentlyContinue

Write-Host "`n===== SUMMARY =====" -ForegroundColor Cyan
& $py "$root\netguard.py" summary --db $db
Write-Host "jsonl bytes: $((Get-Item $jsonl -ErrorAction SilentlyContinue).Length)"
Write-Host "Done. Closing in 3s."
Start-Sleep -Seconds 3
