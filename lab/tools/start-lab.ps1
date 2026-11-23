# Start the PaySecure lab WITHOUT wiping it (audits and account are kept), then open SegCheck in the browser.
# Double-click "lab\Start lab (keep audits).cmd", or run:  powershell -ExecutionPolicy Bypass -File lab\tools\start-lab.ps1
param([switch]$NoBrowser)                  # -NoBrowser: notification only (used for testing)
$Lab = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot "lab-common.ps1")
Set-Location (Join-Path $Lab "docker")

if (-not (Start-DockerIfNeeded)) { exit 1 }   # starts Docker Desktop by itself if it is closed

Write-Host "Starting the 7 lab containers (firewall first, then the auditor and the company systems)..."
docker compose up -d                       # starts stopped containers; creates them only if missing
if ($LASTEXITCODE -ne 0) { Write-Host "The lab did not start; see the messages above." -ForegroundColor Red; exit 1 }

if (-not (Wait-SegCheck)) { Write-Host "SegCheck did not answer. Check: docker compose -f lab\docker\docker-compose.yml logs auditor" -ForegroundColor Red; exit 1 }

$url = Open-LabDashboard "Started with your audits kept." -NoBrowser:$NoBrowser
Write-Host ""
Write-Host "Ready. PaySecure Ltd lab is running; SegCheck opened at $url" -ForegroundColor Green
Write-Host "  The firewall starts WITH the loophole (a start always loads 'as found')."
Write-Host "  Loophole: double-click 'Firewall - fix loophole' / 'Firewall - add loophole' any time"
