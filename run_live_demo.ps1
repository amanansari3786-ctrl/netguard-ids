# NetGuard - Live capture demo (Administrator required)
#
# Live capture needs admin: Npcap opens a kernel-mode driver handle.
# This script verifies admin, then runs a loopback traffic generator and
# NetGuard live capture together, then prints a SOC summary.
#
# Loopback (127.0.0.1) only. Nothing leaves your machine.

param([int]$Duration = 40, [string]$Iface = "Loopback Pseudo-Interface 1")

$root = "C:\Users\amana\netguard-ids"
$py  = "$root\.venv\Scripts\python.exe"
$data = "$root\data"
New-Item -ItemType Directory -Force -Path $data | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " NetGuard IDS - LIVE CAPTURE   Admin=$isAdmin" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not $isAdmin) {
    Write-Host "`nERROR: Not running as Administrator." -ForegroundColor Red
    Write-Host "Npcap cannot open the driver without elevation." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as administrator, then run:" -ForegroundColor Yellow
    Write-Host "  .\run_live_demo.ps1`n" -ForegroundColor Yellow
    Start-Sleep -Seconds 8
    exit 1
}

$db = "$data\live.db"
$jsonl = "$data\live.jsonl"
Remove-Item $db, $jsonl -ErrorAction SilentlyContinue

Write-Host "Interface : $Iface" -ForegroundColor Cyan
Write-Host "Duration  : ${Duration}s" -ForegroundColor Cyan
Write-Host "Database  : $db`n" -ForegroundColor Cyan

# Traffic generator as a background job so it runs concurrently.
$job = Start-Job -ScriptBlock {
    param($r, $d)
    Set-Location $r
    & "$r\.venv\Scripts\python.exe" -m netguard.live_traffic $d
} -ArgumentList $root, ($Duration - 3)

Start-Sleep -Seconds 2

Write-Host "--- live capture starting, alerts appear below ---`n" -ForegroundColor DarkGray
& $py "$root\netguard.py" watch `
    --iface $Iface `
    --duration $Duration `
    --db $db `
    --jsonl $jsonl `
    --progress-every 0

Stop-Job $job -ErrorAction SilentlyContinue
Remove-Job $job -Force -ErrorAction SilentlyContinue

Write-Host "`n===== SOC SUMMARY =====" -ForegroundColor Cyan
& $py "$root\netguard.py" summary --db $db

$size = 0
if (Test-Path $jsonl) { $size = (Get-Item $jsonl).Length }
Write-Host "jsonl bytes written: $size" -ForegroundColor DarkGray

& $py "$root\netguard.py" report --db $db --out "$data\live_report.html" | Out-Null
Write-Host "Report written: $data\live_report.html" -ForegroundColor Green

Start-Sleep -Seconds 5
