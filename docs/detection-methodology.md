# Detection Methodology

This document explains how security events were detected and investigated in this lab, across four complementary layers: host event logs, a SIEM-style log scanner, network traffic analysis, and a live Wazuh SIEM.

---

## Detection Philosophy

A single data source is rarely enough. This lab combines three layers so that an attack is visible from more than one angle:

| Layer | Tool | What it sees |
|---|---|---|
| **Endpoint / host** | Sysmon + Windows audit policy | Process creation, logons, account changes |
| **Offline log analysis** | Hayabusa (Sigma rules) + custom PowerShell | Correlated detections across many events |
| **Network** | Wireshark / tshark | Connection patterns on the wire |
| **Live SIEM** | Wazuh (cloud server + endpoint agent) | Real-time alerts, MITRE ATT&CK mapping, native correlation |

---

## 1. Host-Based Detection

### Data sources enabled
- **Sysmon** (native Windows 11 feature) with the SwiftOnSecurity configuration — process creation (Event ID 1), DNS queries (22), and more.
- **Windows advanced audit policy** — logon success/failure (4624/4625), account lockout (4740), account creation (4720), credential validation (4776), process creation with command line (4688).
- **PowerShell Script Block Logging** (4104).

### Key Event IDs used in this lab

| Event ID | Meaning | Role in detection |
|---|---|---|
| 4720 | Account created | Start of the attack timeline |
| 4625 | Failed logon | Core brute-force indicator |
| 4740 | Account locked out | Confirms the defensive control fired |
| 4776 | Credential validation failed | Corroborates failed authentication |
| 4688 | Process created (with command line) | Detects discovery commands (e.g. whoami) |

---

## 2. Log Analysis with Hayabusa

[Hayabusa](https://github.com/Yamato-Security/hayabusa) applies ~4,800 Sigma detection rules to exported `.evtx` files and produces a prioritized CSV timeline with severity levels and MITRE ATT&CK mappings.

### Process
1. Export the Security and Sysmon logs: `wevtutil epl <channel> <file.evtx>`.
2. Update rules: `hayabusa update-rules`.
3. Scan: `hayabusa dfir-timeline -f <file.evtx> -o <timeline.csv> -m medium -w -U`.

### Result
Hayabusa reduced ~36,000 raw events to a handful of prioritized detections (over 99% data reduction). It surfaced configuration changes and discovery activity.

### Triage outcome

| Detection | Verdict | Reasoning |
|---|---|---|
| Eventlog Clearing / Config Change | Benign true positive | Authorized audit-policy setup |
| Whoami group reconnaissance | Benign true positive | Lab validation command (T1033) |
| Password Reset By Admin | Benign true positive | Setting the test account password |
| AdFind AD Enumeration | False positive | Rule matched `net accounts` keyword; no AdFind or AD present |

**Key finding:** every detection was verified against the underlying command line before a verdict was assigned. Alert titles alone are not conclusive.

---

## 3. Custom Detection Rule (Detection Gap)

The off-the-shelf Sigma rules did **not** raise a brute-force alert for the burst of failed logons, because they do not correlate multiple 4625 events by account within a time window.

### Rules authored
- `detection-rules/bruteforce_failed_logon_4625.yml` — the ideal Sigma rule using `count() by TargetUserName >= 5`. Documents the intended logic. Standalone scanners cannot evaluate this aggregation.
- `detection-rules/failed_logon_4625.yml` — a simplified rule Hayabusa can run, surfacing each 4625.
- `scripts/Detect-BruteForce.ps1` — a PowerShell script that implements the full correlation: groups 4625 events by target account inside a sliding window and alerts when the count meets the threshold, then correlates with the 4740 lockout.

### Logic
> 5 or more failed logons (4625) against the same account within 5 minutes → alert.

### Result
The script detected 6 failed logons against the test account, correlated with the account lockout, and mapped it to **MITRE ATT&CK T1110 / T1110.001**.

---

## 4. Network Analysis with Wireshark

A separate controlled SSH brute force was run against the local SSH service to demonstrate network-level detection.

### Process
1. Capture on the loopback interface, filtered to port 22:
   `tshark -i <loopback> -f "tcp port 22" -w ssh-bruteforce.pcapng`
2. Run repeated failed SSH logons against `127.0.0.1`.
3. Analyze connection attempts:
   `tshark -r ssh-bruteforce.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0"`

### Network signature of a brute force
- Many **short-lived TCP sessions** to port 22 from one source, in rapid succession.
- Sequential source ports, each session tearing down quickly after authentication fails.
- In this capture: 8 connection attempts within seconds, each a small, quickly-closed session.

### Honest limitation
SSH is encrypted, so the packet payload does not reveal the attempted passwords. The **connection pattern** — not the content — is the detectable signature. The source is `127.0.0.1` because the attack was generated locally; in a real incident this would be an external IP.

---

## 5. Live Detection with Wazuh (SIEM)

A full Wazuh 4.14 SIEM (manager + indexer + dashboard) was deployed on a hardened Hetzner cloud server (Ubuntu 24.04, 8 GB RAM). The Windows endpoint ran the Wazuh agent, forwarding its Security and Sysmon event channels over TLS.

### Deployment & hardening
- One-line Wazuh installer (`wazuh-install.sh -a`) on a fresh Ubuntu server.
- **UFW firewall:** default deny inbound; SSH (22), dashboard (443), and agent ports (1514/1515) each restricted to the analyst's single home IP.
- **Key-only SSH**, no password authentication. Dashboard never exposed to the open internet.
- Agent installed on the endpoint via MSI, pointed at the manager IP, forwarding `Security` and `Microsoft-Windows-Sysmon/Operational`.

### Result
The same controlled brute force was replayed. Within seconds Wazuh showed:
- **8 authentication failures, 0 successes** (the attack failed).
- Automatic mapping to **MITRE ATT&CK: Brute Force (T1110)**.
- Built-in rule **60204 "Multiple Windows Logon Failures"** (level 10) correlating the burst into one alert, alongside the individual **60122** logon-failure events (level 5).

### Key comparison
Hayabusa's default Sigma rules **did not** correlate the failed-logon burst — a custom rule was needed. **Wazuh correlated it natively, out of the box.** Running both shows an understanding of the trade-offs: a lightweight offline scanner vs. a stateful, real-time SIEM.

---

## Summary

| Attack stage | Detected by |
|---|---|
| Account targeted | Host logs (4625) |
| Burst correlated as brute force (offline) | Custom PowerShell rule |
| Burst correlated as brute force (live) | Wazuh rule 60204, auto-mapped to MITRE T1110 |
| Defensive control confirmed | Host logs (4740) |
| Network pattern | Wireshark (SYN burst to port 22) |

Each layer reinforces the others: the host logs show *who* and *what*, the custom rule and Wazuh turn raw events into single correlated alerts, and the network capture shows the attack *on the wire*.
