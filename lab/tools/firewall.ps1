# Switch or check the lab firewall (the "Firewall - ..." double-click files in lab\ call this script):
#   fixed  = the client removed the legacy rule (for the retest)
#   office = as found, with the hidden hole (what every start or reset begins with)
#   status = only show which of the two is loaded right now
# powershell -ExecutionPolicy Bypass -File lab\tools\firewall.ps1 fixed
param([ValidateSet("office", "fixed", "status")][string]$Mode = "status")
Set-Location (Join-Path (Split-Path $PSScriptRoot -Parent) "docker")   # where docker-compose.yml is

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker is not running. Start Docker Desktop, wait for 'Engine running', then try again." -ForegroundColor Red
    exit 1
}

if ($Mode -ne "status") {
    docker compose exec -T firewall /lab/rules.sh $Mode | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Could not reach the lab firewall. Is the lab running? Double-click 'Reset lab (fresh, with loophole)'." -ForegroundColor Red
        exit 1
    }
}

$rules = docker compose exec -T firewall iptables-save 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Could not reach the lab firewall. Is the lab running? Double-click 'Reset lab (fresh, with loophole)'." -ForegroundColor Red
    exit 1
}
if ($Mode -ne "status") {
    # Keep the Step 3c file in step with the firewall (as a client would send a fresh export after a change).
    $rules | Set-Content -Encoding ascii (Join-Path (Split-Path $PSScriptRoot -Parent) "firewall-rules.txt")
}
Write-Host ""
if ($rules -match "legacy-reporting") {
    Write-Host "Firewall now HAS the loophole (as found)." -ForegroundColor Yellow
    Write-Host "  Corporate staff PCs can reach the card database on port 5432 (rule 'legacy-reporting')."
    Write-Host "  An audit from Corporate will FAIL and name this rule."
} else {
    Write-Host "Firewall is now FIXED: the loophole is gone." -ForegroundColor Green
    Write-Host "  The legacy Corporate -> card database rule was removed."
    Write-Host "  A retest from Corporate will PASS; History > Compare shows it as FIXED."
}
Write-Host ""
if ($Mode -ne "status") {
    Write-Host "lab\firewall-rules.txt now holds this firewall's rules. Optional: load it again in Step 3c" -ForegroundColor DarkGray
    Write-Host "(Replace the rule export) so the report also quotes the current rule book." -ForegroundColor DarkGray
}
Write-Host "Note: a reset always starts with the loophole." -ForegroundColor DarkGray
