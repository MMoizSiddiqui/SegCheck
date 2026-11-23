# Start the PaySecure office lab from scratch: empty SegCheck, firewall "as found" (with the loophole).
# Double-click "lab\Reset lab (fresh, with loophole).cmd", or run:
#   powershell -ExecutionPolicy Bypass -File lab\tools\reset-demo.ps1
param([switch]$NoBrowser)                  # -NoBrowser: notification only (used for testing)
$ErrorActionPreference = "Stop"
$Lab = Split-Path $PSScriptRoot -Parent           # the lab folder
. (Join-Path $PSScriptRoot "lab-common.ps1")     # wait for SegCheck, open the browser, notify
Set-Location (Join-Path $Lab "docker")           # docker compose reads docker-compose.yml here

if (-not (Start-DockerIfNeeded)) { exit 1 }   # starts Docker Desktop by itself if it is closed

Write-Host "Removing the previous lab (its SegCheck data lives only inside the lab)..."
docker compose down --remove-orphans
Remove-Item (Join-Path $Lab ".office-admin") -ErrorAction SilentlyContinue

Write-Host "Building and starting the lab (the first build takes a few minutes)..."
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Write-Host "The lab did not start; see the messages above." -ForegroundColor Red; exit 1 }

if (-not (Wait-SegCheck)) { Write-Host "SegCheck did not answer. Check: docker compose -f lab\docker\docker-compose.yml logs auditor" -ForegroundColor Red; exit 1 }

# A read-only copy of the firewall's rules, for SegCheck's Step 3 "Firewall rules" box.
$ErrorActionPreference = "Continue"
docker compose exec -T firewall iptables-save | Set-Content -Encoding ascii (Join-Path $Lab "firewall-rules.txt")

$url = Open-LabDashboard "Fresh lab, with the loophole." -NoBrowser:$NoBrowser
Write-Host ""
Write-Host "Ready. PaySecure Ltd lab is running, fresh, WITH the loophole (staff PCs -> card database 5432)." -ForegroundColor Green
Write-Host "  Opened:       $url (create your account there)"
Write-Host "  Setup token:  office-setup-token-change-me-0123456789abcdef   (lab only)"
Write-Host "  Step 3 file:  lab\firewall-rules.txt (Firewall rules > Choose File)"
Write-Host "  Loophole:     double-click 'Firewall - fix loophole' / 'Firewall - add loophole' any time"
