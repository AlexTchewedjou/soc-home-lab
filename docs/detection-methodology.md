# Detection Methodology

## Overview

This document describes the detection and investigation methods used throughout this security lab. The objective was to examine suspicious activity using multiple data sources rather than relying on a single detection tool.

Four complementary approaches were used:

- **Endpoint monitoring:** Sysmon and Windows Advanced Audit Policy.
- **Offline log analysis:** Hayabusa and custom PowerShell scripts.
- **Network traffic analysis:** Wireshark and tshark.
- **Centralized monitoring:** Wazuh SIEM.

Each approach provided a different view of the activity, from Windows authentication events and process execution to network connections and centralized security alerts.

---

## Detection Approach

The investigation used multiple sources of telemetry to identify and validate suspicious activity.

| Layer | Tool | Data collected |
|---|---|---|
| Endpoint / host | Sysmon + Windows audit policy | Process creation, authentication, account changes |
| Offline log analysis | Hayabusa + custom PowerShell | Sigma-based detections and event correlation |
| Network | Wireshark / tshark | TCP connections and traffic patterns |
| Live SIEM | Wazuh | Centralized event collection, alerting, and MITRE ATT&CK mapping |

The purpose of combining these sources was to compare what each tool could detect and identify situations where additional correlation logic was required.

---

## 1. Host-Based Detection

### Data collection

Windows endpoint logging was configured to capture authentication activity, process execution, account changes, and PowerShell activity.

The following sources were enabled:

- **Sysmon:** Configured using the SwiftOnSecurity configuration to collect process creation events (Event ID 1), DNS queries (Event ID 22), and other relevant system activity.
- **Windows Advanced Audit Policy:** Configured to record successful and failed logons, account management activity, credential validation, and process creation.
- **PowerShell Script Block Logging:** Enabled to record PowerShell script block execution (Event ID 4104).

### Relevant Windows Event IDs

| Event ID | Description | Detection purpose |
|---|---|---|
| 4720 | User account created | Identify account creation activity |
| 4625 | Failed logon | Detect unsuccessful authentication attempts |
| 4740 | User account locked out | Confirm account lockout activity |
| 4776 | NTLM credential validation | Investigate credential validation failures |
| 4688 | Process creation | Identify suspicious process execution and command lines |
| 4104 | PowerShell script block logging | Review PowerShell activity |

These events provided the underlying telemetry used during subsequent detection and investigation.

---

## 2. Offline Log Analysis with Hayabusa

[Hayabusa](https://github.com/Yamato-Security/hayabusa) was used to analyze exported Windows Event Log files (`.evtx`) against Sigma-based detection rules.

The tool generates a prioritized timeline containing relevant events, severity information, and MITRE ATT&CK mappings.

### Analysis process

1. Export the Windows Security and Sysmon event logs:

   ```powershell
   wevtutil epl <channel> <file.evtx>
   ```

2. Update the Hayabusa detection rules:

   ```powershell
   hayabusa update-rules
   ```

3. Generate a forensic timeline:

   ```powershell
   hayabusa dfir-timeline -f <file.evtx> -o <timeline.csv> -m medium -w -U
   ```

### Results

Approximately 36,000 raw events were processed. Hayabusa generated a smaller set of prioritized findings, allowing the investigation to focus on events that warranted further review.

The analysis identified activity related to account configuration changes and system discovery.

### Detection triage

Each finding was reviewed against the underlying event data before assigning a verdict.

| Detection | Verdict | Investigation findings |
|---|---|---|
| Event Log Clearing / Configuration Change | Benign true positive | The event was associated with authorized audit-policy configuration. |
| Whoami Group Reconnaissance | Benign true positive | The command was executed intentionally during lab validation (T1033). |
| Password Reset by Administrator | Benign true positive | The password change was part of test-account preparation. |
| AdFind AD Enumeration | False positive | The detection matched a `net accounts` keyword, but no AdFind execution or Active Directory environment was present. |

**Investigation note:** A detection name does not automatically establish malicious activity. Each alert was compared with its underlying command line and execution context before being classified.

---

## 3. Custom Detection Engineering

### Identifying a detection gap

During the offline analysis, the default Sigma rules did not generate a single correlated brute-force alert for the sequence of failed Windows logons.

Individual Event ID 4625 records were available, but the desired detection required identifying repeated failures against the same account within a defined time period.

This led to the development of additional detection logic.

### Detection rules and scripts

Three files were created:

- `detection-rules/bruteforce_failed_logon_4625.yml`

  A Sigma-style rule documenting the intended threshold-based detection logic using `count()` grouped by `TargetUserName`.

- `detection-rules/failed_logon_4625.yml`

  A simplified rule designed to identify individual Event ID 4625 records in Hayabusa.

- `scripts/Detect-BruteForce.ps1`

  A PowerShell script implementing the correlation logic by grouping failed logons by target account within a sliding time window and checking for a corresponding account lockout event.

The aggregation rule documents the intended detection logic; the PowerShell script performs the actual correlation because the standalone scanner does not evaluate this aggregation in the same way.

### Detection logic

> Five or more failed logon events (4625) against the same account within five minutes trigger an alert.

The script also checks for Event ID 4740 to determine whether the account was subsequently locked out.

### Validation result

During testing, the script identified six failed logon events against the test account and correlated them with the corresponding account lockout event.

The activity was mapped to:

- **T1110:** Brute Force
- **T1110.001:** Password Guessing

This provided a way to identify repeated authentication failures as a single investigation rather than reviewing each event independently.

---

## 4. Network Traffic Analysis with Wireshark

A separate controlled SSH brute-force exercise was performed against the local SSH service to examine how repeated authentication attempts appeared at the network level.

Wireshark and tshark were used to capture and inspect the traffic.

### Capture procedure

1. Start a packet capture on the loopback interface, filtering for TCP port 22:

   ```bash
   tshark -i <loopback> -f "tcp port 22" -w ssh-bruteforce.pcapng
   ```

2. Generate repeated unsuccessful SSH authentication attempts against `127.0.0.1`.

3. Review the captured TCP connection attempts:

   ```bash
   tshark -r ssh-bruteforce.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0"
   ```

### Observed network pattern

The capture contained eight connection attempts within a short period.

The traffic showed:

- Repeated TCP connection attempts to destination port 22.
- Multiple short-lived sessions originating from the same source address.
- Connections being established and closed within a short interval.

This pattern can be useful when investigating repeated SSH connection attempts, particularly when combined with authentication logs from the target endpoint.

### Investigation limitation

SSH encrypts its authentication traffic. As a result, the packet capture does not expose the passwords entered during authentication.

The network capture provides information about connection timing, source and destination addresses, ports, and TCP behavior. It does not independently confirm whether an authentication attempt succeeded or failed.

In this exercise, the source address was `127.0.0.1` because the activity was generated locally. An externally initiated attack would normally show the corresponding remote source IP address.

---

## 5. Live Detection with Wazuh SIEM

A Wazuh 4.14 SIEM environment was deployed on a Hetzner cloud server running Ubuntu 24.04 with 8 GB of RAM.

The deployment included:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Wazuh Agent installed on the Windows endpoint

The Windows agent forwarded the Security and Sysmon event channels to the manager over the configured secure connection.

### Deployment and security configuration

The Wazuh installation was performed using the official installation assistant:

```bash
bash wazuh-install.sh -a
```

The cloud server was configured with several access restrictions:

- UFW firewall configured with a default-deny inbound policy.
- SSH access restricted to the analyst's home IP.
- Dashboard access restricted to the analyst's home IP.
- Agent communication ports 1514 and 1515 restricted to the required source address.
- SSH password authentication disabled in favor of key-based authentication.
- The dashboard was not made publicly accessible.

The Windows endpoint agent was installed using the MSI package and configured to forward:

- `Security`
- `Microsoft-Windows-Sysmon/Operational`

### Detection validation

The controlled SSH brute-force scenario was replayed while monitoring the Windows endpoint through Wazuh.

Within seconds, the dashboard displayed:

- **8 authentication failures**
- **0 successful logons**
- MITRE ATT&CK mapping to **T1110 — Brute Force**
- Built-in Wazuh rule **60204**, titled "Multiple Windows Logon Failures", with level 10.
- Individual logon-failure events associated with rule **60122**, with level 5.

The results showed that Wazuh could identify the repeated authentication failures and correlate them into a higher-level alert without requiring the separate PowerShell correlation script used in the offline workflow.

### Comparison with Hayabusa

The two tools served different purposes during the investigation.

| Capability | Hayabusa | Wazuh |
|---|---|---|
| Analysis mode | Offline | Live / centralized |
| Input | Exported EVTX files | Forwarded endpoint events |
| Sigma-based detection | Yes | Rule-based detection and integrations |
| Brute-force correlation in this lab | Custom PowerShell script | Built-in rule 60204 |
| Centralized dashboard | No | Yes |
| MITRE ATT&CK mapping | Available | Available |

Hayabusa was useful for reviewing exported logs and building a forensic timeline. Wazuh provided continuous event collection and built-in correlation for the tested authentication scenario.

Using both approaches made it possible to compare offline forensic analysis with centralized SIEM monitoring.

---

## 6. Detection Summary

The following table summarizes how the controlled attack scenario was investigated across the different layers.

| Attack or investigation stage | Detection source | Evidence |
|---|---|---|
| Failed authentication attempts | Windows Security logs | Event ID 4625 |
| Brute-force correlation (offline) | Custom PowerShell script | Five-or-more failures within five minutes |
| Brute-force correlation (live) | Wazuh | Rule 60204 |
| Account lockout | Windows Security logs | Event ID 4740 |
| Network connection pattern | Wireshark / tshark | Repeated TCP connections to port 22 |
| Process and command activity | Sysmon / Windows audit logs | Process creation and command-line events |

The investigation demonstrated how different telemetry sources can contribute to the same detection workflow.

Windows event logs provided authentication and account activity, PowerShell added correlation to the offline analysis, Wireshark exposed the network connection pattern, and Wazuh provided centralized alerting.

Rather than relying on one detection source, the lab used these tools together to validate suspicious activity and understand what each layer could identify.
