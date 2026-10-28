# Detection Methodology

This document explains how security events were detected and investigated in this lab, across three complementary layers: host event logs, a SIEM-style log scanner, and network traffic analysis.

---

## Detection Philosophy

A single data source is rarely enough. This lab combines three layers so that an attack is visible from more than one angle:

| Layer | Tool | What it sees |
|---|---|---|
| **Endpoint / host** | Sysmon + Windows audit policy | Process creation, logons, account changes |
| **Log analysis / SIEM** | Hayabusa (Sigma rules) + custom PowerShell | Correlated detections across many events |
| **Network** | Wireshark / tshark | Connection patterns on the wire |

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

## Summary

| Attack stage | Detected by |
|---|---|
| Account targeted | Host logs (4625) |
| Burst correlated as brute force | Custom PowerShell rule |
| Defensive control confirmed | Host logs (4740) |
| Network pattern | Wireshark (SYN burst to port 22) |

Each layer reinforces the others: the host logs show *who* and *what*, the custom rule turns raw events into a single alert, and the network capture shows the attack *on the wire*.
