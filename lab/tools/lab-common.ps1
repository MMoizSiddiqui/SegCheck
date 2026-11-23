# Shared helpers for the lab's double-click files (dot-sourced by reset-demo.ps1 and start-lab.ps1).
# A container cannot open anything on the Windows desktop, so these run on the PC: they wait until SegCheck in
# the auditor container answers on http://127.0.0.1:5091, then open the browser and show a Windows notification.

$LabUrl = "http://127.0.0.1:5091"

function Start-DockerIfNeeded([int]$Seconds = 180) {
    # Docker's engine must run for the containers. If it does not, start Docker Desktop and wait for it.
    $ErrorActionPreference = "Continue"   # Docker's "not running" message must not abort the caller
    docker info *> $null
    if ($LASTEXITCODE -eq 0) { return $true }
    $exe = @("$env:ProgramFiles\Docker\Docker\Docker Desktop.exe", "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $exe) {
        Write-Host "Docker Desktop is not installed (or not in the usual place). Install it from docker.com, then try again." -ForegroundColor Red
        return $false
    }
    Write-Host "Docker is not running: starting Docker Desktop and waiting for its engine (up to $([int]($Seconds / 60)) minutes)..."
    Start-Process $exe
    for ($i = 0; $i -lt $Seconds / 3; $i++) {
        Start-Sleep -Seconds 3
        docker info *> $null
        if ($LASTEXITCODE -eq 0) { Write-Host "Docker is running." -ForegroundColor Green; return $true }
    }
    Write-Host "Docker Desktop did not finish starting. Open it, wait for 'Engine running', then try again." -ForegroundColor Red
    return $false
}

function Wait-SegCheck([int]$Seconds = 120) {
    for ($i = 0; $i -lt $Seconds / 2; $i++) {
        try { if ((Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "$LabUrl/api/health").StatusCode -eq 200) { return $true } } catch { }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Get-DashboardUrl {
    # A fresh lab has no account yet: the setup page is open. Otherwise go to sign-in.
    try { if ((Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "$LabUrl/setup").StatusCode -eq 200) { return "$LabUrl/setup" } } catch { }
    return "$LabUrl/login"
}

function Show-LabNotification([string]$Title, [string]$Text) {
    # Windows 10/11 notification (toast); falls back to a tray balloon if toasts are unavailable.
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        $esc = { param($s) [System.Security.SecurityElement]::Escape($s) }
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml("<toast><visual><binding template=`"ToastGeneric`"><text>$(& $esc $Title)</text><text>$(& $esc $Text)</text></binding></visual></toast>")
        $appId = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
    } catch {
        try {
            Add-Type -AssemblyName System.Windows.Forms, System.Drawing
            $icon = New-Object System.Windows.Forms.NotifyIcon
            $icon.Icon = [System.Drawing.SystemIcons]::Information
            $icon.Visible = $true
            $icon.ShowBalloonTip(8000, $Title, $Text, [System.Windows.Forms.ToolTipIcon]::Info)
            Start-Sleep -Seconds 8
            $icon.Dispose()
        } catch { }
    }
}

function Open-LabDashboard([string]$Why, [switch]$NoBrowser) {
    $url = Get-DashboardUrl
    Show-LabNotification "SegCheck lab is running" ("$Why All 7 containers are up; the auditor container serves SegCheck at $url")
    if (-not $NoBrowser) { Start-Process $url }
    return $url
}
