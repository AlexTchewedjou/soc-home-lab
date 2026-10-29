# Setup Guide — Environment, Endpoint Logging & Cloud SIEM

> **Scope:** This guide documents how the Windows endpoint in this lab was assessed and instrumented for security monitoring, and how a Wazuh SIEM was deployed on a hardened cloud server. Every step below was executed and validated on the lab machine. Nothing here is simulated or assumed.
>
> **Status:** ✅ Endpoint logging complete · ✅ Cloud SIEM (Wazuh) deployed and connected

---

## 1. Environment Assessment (Phase 1)

### Host machine

| Item | Value |
|---|---|
| OS | Windows 11 Home (build 26300) |
| CPU | Intel Core i5-1135G7 (4 cores / 8 threads) |
| RAM | 8 GB (7.7 GB usable) |
| Free disk | ~239 GB |
| Hypervisor | VirtualBox 7.0.12 installed; Windows hypervisor active (Memory Integrity / VBS) |

### Resource findings

Before choosing an architecture, available memory was measured with `Get-Counter '\Memory\Available MBytes'` and Task Manager:

| Measurement | Result |
|---|---|
| Initial available RAM | ~790 MB |
| After removing redundant antivirus products, setting SQL Server to manual start, and disabling non-essential startup apps | ~1,990 MB |

**Conclusion:** ~2 GB of free RAM is not enough to run a Windows VM reliably alongside the host, especially with VirtualBox running through the Windows hypervisor API.

### Architecture decision

| Component | Location | Role |
|---|---|---|
| Sysmon + Windows audit policy + PowerShell logging | Host (this guide) | Monitored endpoint |
| Wazuh (manager, indexer, dashboard) | Hetzner cloud server (Ubuntu 24.04, 8 GB) | SIEM — see Section 9 |
| Wireshark | Host | Network analysis |

Security controls were **not** disabled to make room for the lab: Memory Integrity (VBS) and Microsoft Defender remain enabled.

---

## 2. Project Folder Structure

```powershell
New-Item -ItemType Directory -Force -Path "C:\SOC-Lab\soc-home-lab\configs","C:\SOC-Lab\soc-home-lab\docs","C:\SOC-Lab\soc-home-lab\detection-rules","C:\SOC-Lab\soc-home-lab\incident-reports","C:\SOC-Lab\soc-home-lab\screenshots","C:\SOC-Lab\soc-home-lab\scripts","C:\SOC-Lab\evidence"
```

| Folder | Purpose | Committed to GitHub? |
|---|---|---|
| `soc-home-lab\` | Project repository | ✅ Yes |
| `evidence\` | Raw logs, policy backups | ❌ Never |

---

## 3. Sysmon (Native Windows 11 Feature)

Windows 11 now includes Sysmon as a built-in optional feature (disabled by default). This lab uses the native version instead of the standalone Sysinternals download, so it is updated through Windows Update.

### 3.1 Confirm Sysmon is not already installed

```powershell
Get-Service Sysmon* -ErrorAction SilentlyContinue
Get-WindowsOptionalFeature -Online | Where-Object FeatureName -match 'Sysmon' | Select-Object FeatureName, State
```

Result: no existing Sysmon service; features `Sysmon` and `Sysmon-Service` present and **Disabled**.

### 3.2 Enable the feature

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All
```

Result: `RestartNeeded : False`. The `sysmon.exe` binary is available at `C:\Windows\System32\sysmon.exe`.

### 3.3 Configuration

The lab uses the community baseline **[SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)**, chosen because it captures security-relevant events while filtering common noise, which keeps disk and CPU usage low.

```powershell
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\SOC-Lab\soc-home-lab\configs\sysmonconfig.xml"
([xml](Get-Content "C:\SOC-Lab\soc-home-lab\configs\sysmonconfig.xml")).Sysmon.schemaversion
```

Result: schema version `4.50`.

### 3.4 Install and start

```powershell
sysmon -accepteula -i "C:\SOC-Lab\soc-home-lab\configs\sysmonconfig.xml"
```

Result:
```
Loading configuration file with schema version 4.50
Sysmon schema version: 4.91
Configuration file validated.
Sysmon installed.
SysmonDrv started.
Sysmon started.
```

### 3.5 Validation

| Test | Command | Result |
|---|---|---|
| Service running | `Get-Service Sysmon*` | `Sysmon` — Running, Automatic |
| Process creation logged | Launched `notepad.exe`, queried Sysmon Event ID 1 | ✅ Event ID 1 with `Image: ...\Notepad.exe` |
| DNS logging | Observed in Event Viewer | ✅ Event ID 22 (DNS query) present |

📸 Evidence: [`screenshots/01-sysmon-event-id-1.png`](../screenshots/01-sysmon-event-id-1.png)

---

## 4. Windows Advanced Audit Policy

By default, Windows does not log all events a SOC analyst needs. The following subcategories were enabled using **GUIDs**, so the commands work regardless of the system language.

### 4.1 Back up the existing policy

```powershell
auditpol /backup /file:C:\SOC-Lab\evidence\auditpol-backup.csv
```

### 4.2 Apply the lab policy

| Subcategory | GUID | Setting | Key Event IDs |
|---|---|---|---|
| Logon | `{0CCE9215-69AE-11D9-BED3-505054503030}` | Success + Failure | 4624, 4625 |
| Account Lockout | `{0CCE9217-69AE-11D9-BED3-505054503030}` | Success + Failure | 4625 (lockout) |
| Special Logon | `{0CCE921B-69AE-11D9-BED3-505054503030}` | Success | 4672 |
| Credential Validation | `{0CCE923F-69AE-11D9-BED3-505054503030}` | Success + Failure | 4776 |
| User Account Management | `{0CCE9235-69AE-11D9-BED3-505054503030}` | Success + Failure | 4720, 4740 |
| Security Group Management | `{0CCE9237-69AE-11D9-BED3-505054503030}` | Success | 4732 |
| Process Creation | `{0CCE922B-69AE-11D9-BED3-505054503030}` | Success | 4688 |

```powershell
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable
```

### 4.3 Include command lines in Event 4688

```powershell
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
```

### 4.4 Validation

| Test | Result |
|---|---|
| `auditpol /get` on all 7 subcategories | ✅ All match the table above |
| Ran `whoami /groups`, queried Security Event 4688 | ✅ `Process Command Line: "C:\WINDOWS\system32\whoami.exe" /groups` |

`whoami` is a common attacker discovery command (MITRE ATT&CK T1033), so this test also confirms the lab can see reconnaissance activity.

---

## 5. PowerShell Script Block Logging

Records the PowerShell code that actually executes (Event ID 4104), which is a key data source for detecting malicious scripts.

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
```

**Validation:** In a new PowerShell session, ran `Write-Output "SOC-LAB-TEST-4104"` and searched the PowerShell Operational log. ✅ Event ID 4104 recorded.

> The search string was split (`'SOC-LAB' + '-TEST-4104'`) so the search command would not match its own logged script block.

---

## 6. Log Retention

Default log sizes are small, so older events are overwritten quickly. Sizes were increased to preserve lab evidence:

```powershell
wevtutil sl Security /ms:268435456
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:134217728
```

| Log | Max size (verified) |
|---|---|
| Security | 256 MB |
| Microsoft-Windows-Sysmon/Operational | 256 MB |
| Microsoft-Windows-PowerShell/Operational | 128 MB |

---

## 7. Rollback

All changes are reversible:

```powershell
# Sysmon: uninstall, then disable the Windows feature
sysmon -u
Disable-WindowsOptionalFeature -Online -FeatureName Sysmon

# Audit policy: restore the original backup
auditpol /restore /file:C:\SOC-Lab\evidence\auditpol-backup.csv

# Command-line auditing and Script Block Logging
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging

# Log sizes: set back to a smaller value if needed
# wevtutil sl <LogName> /ms:<bytes>
```

---

## 8. Privacy and Data Handling

- This lab runs on a personal machine, so raw event logs may contain personal information.
- Raw logs and policy backups are stored in `C:\SOC-Lab\evidence\`, which is **never committed**.
- Screenshots and exported events are reviewed before publishing; hostnames and usernames are redacted.
- Only events tied to the dedicated lab test account and lab time windows are used as evidence.

---

## 9. Cloud SIEM — Wazuh on a Hardened Server

The full Wazuh SIEM runs on a small cloud server rather than the laptop, so the 8 GB host is never burdened with it. The endpoint connects as an agent and forwards its logs over TLS.

### 9.1 Provision the server
- **Provider:** Hetzner Cloud, server type CPX31 (4 vCPU / 8 GB / 160 GB), Ubuntu 24.04 LTS.
- Billed hourly (~$0.12/h), so the lab can run for a session and the server deleted or snapshotted afterward.
- SSH key authentication only (ed25519 key generated with `ssh-keygen`; public key added at creation, no password login).

### 9.2 Harden before installing anything
Restrict every inbound port to the analyst's single home IP. Nothing is exposed to the open internet.

```bash
apt update && apt upgrade -y
ufw default deny incoming
ufw default allow outgoing
ufw allow from <HOME_IP> to any port 22   proto tcp   # SSH
ufw allow from <HOME_IP> to any port 443  proto tcp   # Wazuh dashboard
ufw allow from <HOME_IP> to any port 1514 proto tcp   # agent events
ufw allow from <HOME_IP> to any port 1515 proto tcp   # agent enrollment
ufw --force enable
ufw status verbose
```

> Residential IPs can change; if the dashboard stops loading, update these rules with the new IP.

### 9.3 Install Wazuh (all-in-one)
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && bash ./wazuh-install.sh -a
```
Takes ~5–10 minutes. The final summary prints the dashboard URL and the generated `admin` password. Access the dashboard at `https://<SERVER_IP>` (self-signed certificate — expected in a lab; proceed past the browser warning).

### 9.4 Connect the Windows endpoint as an agent
From the dashboard, **Deploy new agent** generates an install command. Run it in an **elevated** PowerShell (the MSI requires true administrator rights — a non-elevated run fails with *Error 1925*):

```powershell
$msi = "$env:tmp\wazuh-agent.msi"
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi -OutFile $msi
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn WAZUH_MANAGER=<SERVER_IP> WAZUH_AGENT_NAME=windows-endpoint" -Wait
Start-Service WazuhSvc
```

Add the Sysmon channel so Wazuh receives it (the Security channel is forwarded by default):
```powershell
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
Copy-Item $conf "$conf.bak"
$block = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
(Get-Content $conf -Raw) -replace '</ossec_config>', "$block`r`n</ossec_config>" | Set-Content $conf -Encoding utf8
Restart-Service WazuhSvc
```

### 9.5 Validation
| Test | Result |
|---|---|
| Agent log shows connection | ✅ `Connected to the server ([<SERVER_IP>]:1514/tcp)` and `Agent is now online` |
| Dashboard agent status | ✅ `windows-endpoint` — **Active** |
| Brute force replayed → alerts | ✅ 8 authentication failures, 0 successes; rule 60204 "Multiple Windows Logon Failures" (level 10); mapped to MITRE ATT&CK T1110 (Brute Force) |

📸 Evidence: `screenshots/07`–`10` (dashboard, active agent, MITRE detection, server).

### 9.6 Cost note
The server bills for as long as it exists, even when powered off — only **deleting** it (or taking a cheap snapshot and deleting) stops charges. The agent can be removed from the endpoint with:
```powershell
Stop-Service WazuhSvc; msiexec.exe /x $env:tmp\wazuh-agent.msi /qn
```

---

## Next Steps

- Reproduce the brute force with a **real external source IP** between two cloud hosts.
- Add custom Wazuh rules/decoders and a File Integrity Monitoring scenario.
