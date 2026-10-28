<#
.SYNOPSIS
    Detects brute-force logon attempts in a Windows Security event log.

.DESCRIPTION
    Implements the correlation logic that standalone Sigma scanners cannot:
    groups failed logon events (Event ID 4625) by target account inside a
    sliding time window and raises an alert when the count meets or exceeds
    a threshold. Optionally correlates each alert with the matching account
    lockout event (Event ID 4740).

    Read-only. Reads an exported .evtx file; it does not change any logs.

    MITRE ATT&CK: T1110 (Brute Force) / T1110.001 (Password Guessing)

.PARAMETER EvtxPath
    Path to an exported Security .evtx file.

.PARAMETER Threshold
    Number of failed logons against one account that triggers an alert. Default 5.

.PARAMETER WindowMinutes
    Sliding time window in minutes. Default 5.

.EXAMPLE
    .\Detect-BruteForce.ps1 -EvtxPath C:\SOC-Lab\evidence\Security-20261027-153859.evtx
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvtxPath,

    [int]$Threshold = 5,

    [int]$WindowMinutes = 5
)

if (-not (Test-Path $EvtxPath)) {
    Write-Error "Evtx file not found: $EvtxPath"
    exit 1
}

Write-Host "Scanning $EvtxPath for brute-force activity..." -ForegroundColor Cyan
Write-Host "Threshold: $Threshold failed logons within $WindowMinutes minute(s) per account.`n"

# 1. Pull all failed logons (4625) and extract the target account name
$failed = Get-WinEvent -Path $EvtxPath -FilterXPath "*[System[EventID=4625]]" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [pscustomobject]@{
            Time        = $_.TimeCreated
            TargetUser  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            SourceIP    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            LogonType   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        }
    }

if (-not $failed) {
    Write-Host "No failed logon (4625) events found." -ForegroundColor Green
    exit 0
}

# 2. Lockout events (4740) for correlation
$lockouts = Get-WinEvent -Path $EvtxPath -FilterXPath "*[System[EventID=4740]]" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [pscustomobject]@{
            Time       = $_.TimeCreated
            TargetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        }
    }

# 3. Sliding-window correlation per account
$alerts = @()
foreach ($group in ($failed | Group-Object TargetUser)) {
    $events = $group.Group | Sort-Object Time
    for ($i = 0; $i -lt $events.Count; $i++) {
        $windowEnd = $events[$i].Time.AddMinutes($WindowMinutes)
        $inWindow  = $events | Where-Object { $_.Time -ge $events[$i].Time -and $_.Time -le $windowEnd }
        if ($inWindow.Count -ge $Threshold) {
            $locked = $lockouts | Where-Object { $_.TargetUser -eq $group.Name }
            $alerts += [pscustomobject]@{
                TargetUser   = $group.Name
                FailedCount  = $inWindow.Count
                FirstAttempt = ($inWindow | Select-Object -First 1).Time
                LastAttempt  = ($inWindow | Select-Object -Last 1).Time
                SourceIP     = ($inWindow | Select-Object -First 1).SourceIP
                LogonType    = ($inWindow | Select-Object -First 1).LogonType
                AccountLocked = [bool]$locked
                LockoutTime  = ($locked | Select-Object -First 1).Time
            }
            break   # one alert per account is enough
        }
    }
}

# 4. Report
if ($alerts) {
    Write-Host "[!] BRUTE-FORCE DETECTED" -ForegroundColor Red
    $alerts | Format-List
    Write-Host "MITRE ATT&CK: T1110 / T1110.001" -ForegroundColor Yellow
} else {
    Write-Host "No brute-force pattern met the threshold." -ForegroundColor Green
}
