# SOC Home Lab — Security Monitoring & Incident Detection

A hands-on Security Operations Center (SOC) home lab that monitors a Windows endpoint, generates a controlled attack, and detects and investigates it across three layers: host event logs, a SIEM-style log scanner, and network traffic analysis. Built on a resource-constrained laptop (8 GB RAM) using free and open-source tools.

> **Ethics & scope:** Every action in this lab was performed on a system I own, against a dedicated test account created for the purpose. No production systems, real credentials, or third-party networks were involved. Simulated activity is clearly labeled as such throughout.

---

## Table of Contents
- [Overview](#overview)
- [Objectives](#objectives)
- [Architecture](#architecture)
- [Tools](#tools)
- [Detection Scenario: Brute-Force Attack](#detection-scenario-brute-force-attack)
- [Investigation Methodology](#investigation-methodology)
- [Evidence](#evidence)
- [Repository Structure](#repository-structure)
- [Setup](#setup)
- [Limitations](#limitations)
- [Lessons Learned](#lessons-learned)
- [Cloud SIEM (Wazuh)](#cloud-siem-wazuh)
- [Credits & License](#credits--license)

---

## Overview

This project simulates a mini SOC workflow end to end:

1. Instrument a Windows 11 endpoint with Sysmon, an advanced audit policy, and PowerShell logging.
2. Generate a **controlled brute-force attack** against a dedicated test account.
3. Detect it four ways: **Hayabusa** (Sigma rules), a **custom detection rule**, **Wireshark**, and a **Wazuh SIEM** running on a hardened cloud server.
4. Investigate, triage, and document the incident as a SOC analyst would.

A key theme is **honesty about scope**: the default Hayabusa rule set did *not* flag the brute force, so I identified that detection gap and wrote a custom correlation rule to fill it. Wazuh, by contrast, correlated the same burst natively (rule 60204) — a concrete comparison of two SIEM approaches.

---

## Objectives

- [x] Endpoint security monitoring (Sysmon + Windows Event Logs)
- [x] Windows event log collection and analysis
- [x] Basic SIEM concepts and alert triage (Hayabusa)
- [x] Detection of repeated failed logins and suspicious activity
- [x] Custom detection rule development
- [x] Network traffic analysis (Wireshark)
- [x] Incident investigation and timeline creation
- [x] Incident response documentation and remediation recommendations
- [x] Professional GitHub documentation
- [x] Centralized SIEM dashboard (Wazuh) on a hardened cloud server, with the endpoint forwarding live logs

---

## Architecture

The lab was designed around a real constraint: **8 GB of RAM**, with only ~2 GB free after cleanup. A traditional multi-VM lab (Kali attacker + Windows victim + Linux SIEM) could not run locally. The architecture was adapted to a **host-based endpoint + cloud SIEM** design that delivers the same outcomes without overloading the laptop.

```
   +--------------------------------------------------+
   |          Windows 11 Host (monitored endpoint)    |
   |                                                  |
   |   +------------+   +----------------+            |
   |   |  Sysmon    |   | Audit Policy   |            |
   |   | (native)   |   | 4625/4740/4688 |            |
   |   +-----+------+   +-------+--------+            |
   |         |                  |                     |
   |         v                  v                     |
   |     +---------------------------+                |
   |     |   Windows Event Logs      |                |
   |     +------------+--------------+                |
   |                  |                               |
   |      +-----+-----+-----+-------------+           |
   |      |     |     |     |             |           |
   |      v     v     v     |   Wazuh agent (TLS)     |
   |  Hayabusa Custom Wire- |        |                |
   |  (Sigma)  rule   shark |        |                |
   +------------------------|--------|-----------------+
                            |        | ports 1514/1515
                            |        v   (firewalled to home IP)
                            |   +-----------------------------+
                            |   |   Hetzner cloud server      |
                            |   |   Ubuntu 24.04, 8 GB        |
                            |   |   Wazuh manager + indexer   |
                            |   |   + dashboard (HTTPS 443)   |
                            |   +-----------------------------+
```

**Why this design?** See [`docs/setup-guide.md`](docs/setup-guide.md) for the full RAM assessment and rationale. The local host handles endpoint logging and offline analysis (Hayabusa, Wireshark, the custom rule); a small cloud server runs the full Wazuh SIEM, so the laptop never has to host it. Security controls (Memory Integrity / VBS, Microsoft Defender) were kept **enabled** throughout, and the cloud server's ports are **firewalled to a single home IP** — the dashboard is never exposed to the open internet.

---

## Tools

| Tool | Role | Cost |
|---|---|---|
| **Sysmon** (native Windows 11 feature) | Endpoint telemetry (process, DNS, etc.) | Free |
| **Windows Advanced Audit Policy** | Logon, lockout, process-creation auditing | Built-in |
| **PowerShell Script Block Logging** | Captures executed PowerShell | Built-in |
| **Hayabusa** (Yamato Security) | Sigma-based log scanner / timeline | Free / OSS |
| **Custom PowerShell + Sigma rule** | Brute-force correlation | Authored here |
| **Wireshark / tshark** | Network packet analysis | Free / OSS |
| **Wazuh 4.14** (manager + indexer + dashboard) | Live SIEM — real-time alerts, MITRE ATT&CK mapping | Free / OSS |
| **Hetzner Cloud (Ubuntu 24.04)** | Hardened host for the Wazuh server | ~$0.12/hr |

---

## Detection Scenario: Brute-Force Attack

A password-guessing attack was simulated against a dedicated local test account, then detected and investigated.

| Stage | Event ID | Evidence |
|---|---|---|
| Test account created | 4720 | Security log |
| 6 failed logons in ~5 seconds | 4625 ×6 | Security log |
| Account locked out | 4740 | Security log |
| Network connection burst (SSH variant) | — | `ssh-bruteforce.pcapng` |

**Custom detection output:**

```
[!] BRUTE-FORCE DETECTED
TargetUser    : <test account>
FailedCount   : 6
FirstAttempt  : 2026-10-27 15:21:12
LastAttempt   : 2026-10-27 15:21:17
AccountLocked : True
MITRE ATT&CK  : T1110 / T1110.001
```

Full write-up: [`incident-reports/sample-incident-report.md`](incident-reports/sample-incident-report.md)

---

## Investigation Methodology

Detection used four complementary layers, each reinforcing the others:

1. **Host logs** show *who* and *what* (failed logons, the lockout).
2. **Hayabusa** reduced ~36,000 raw events to 7 prioritized detections (>99% data reduction), which were then triaged.
3. **A custom rule** correlated the failed-logon burst that off-the-shelf Hayabusa rules missed.
4. **Wireshark** showed the attack pattern on the wire (a burst of short-lived connections).
5. **Wazuh** ingested the same events live and raised them in real time — 8 authentication failures, 0 successes, automatically mapped to **MITRE ATT&CK: Brute Force (T1110)**, and correlated into a single alert by its built-in rule **60204 "Multiple Windows Logon Failures"**.

A useful comparison emerged: Hayabusa's default Sigma rules **could not** correlate the failed-logon burst (which is why I wrote a custom rule), whereas **Wazuh did it natively**. Seeing where each tool succeeds and fails is a core SOC skill.

Triage was done honestly: of 7 raw Hayabusa detections, 5 were **benign true positives** (my own authorized setup) and 2 were **false positives** (a rule matched a legitimate `net accounts` command). Every verdict was verified against the underlying command line.

Full methodology: [`docs/detection-methodology.md`](docs/detection-methodology.md)

---

## Evidence

Screenshots (with hostnames/usernames redacted) are in [`screenshots/`](screenshots/):

| File | Shows |
|---|---|
| `01-sysmon-event-id-1.png` | Sysmon process-creation logging working |
| `02-event-4625-failed-logon.png` | A failed logon (4625) during the attack |
| `04b-hayabusa-security-summary.png` | Hayabusa detection summary |
| `05-bruteforce-detection.png` | Custom rule firing on the attack |
| `06-wireshark-ssh-bruteforce.png` | Network connection burst to port 22 |
| `07-wazuh-dashboard-overview.png` | Wazuh SIEM dashboard overview |
| `08-wazuh-agent-active.png` | Windows endpoint connected to Wazuh (agent active) |
| `09-wazuh-bruteforce-mitre.png` | Wazuh brute-force detection + MITRE ATT&CK mapping |
| `09b-wazuh-bruteforce-events.png` | Individual Wazuh alerts (rule 60204 / 60122) |
| `10-hetzner-server.png` | The hardened Hetzner cloud server running Wazuh |

> Raw event logs (`.evtx`) are **not committed** — they contain full system activity. Only filtered, redacted evidence is published.

---

## Repository Structure

```
soc-home-lab/
├── README.md
├── LICENSE
├── .gitignore
├── configs/
│   └── sysmonconfig.xml              # Sysmon config (SwiftOnSecurity baseline)
├── docs/
│   ├── setup-guide.md                # Phase 1–2: environment + endpoint logging
│   └── detection-methodology.md      # How detection works across 3 layers
├── detection-rules/
│   ├── bruteforce_failed_logon_4625.yml   # Ideal Sigma rule (count aggregation)
│   └── failed_logon_4625.yml              # Hayabusa-compatible rule
├── scripts/
│   └── Detect-BruteForce.ps1         # Correlation script (the real detection)
├── incident-reports/
│   └── sample-incident-report.md     # IR-2026-001
├── screenshots/
└── logs/
    └── README.md                     # Why raw logs are not published
```

---

## Setup

Reproduce the endpoint instrumentation with [`docs/setup-guide.md`](docs/setup-guide.md). In brief:

1. Enable native Sysmon and apply the config in `configs/`.
2. Apply the advanced audit policy (commands in the setup guide).
3. Enable PowerShell Script Block Logging.
4. Generate the controlled attack and export the logs.
5. Scan with Hayabusa and run `scripts/Detect-BruteForce.ps1`.

Every step in the guide was executed and validated on the lab machine.

---

## Limitations

This project is honest about what it is and isn't:

- **The attacker is local (`localhost`), not a separate machine.** The RAM constraint ruled out a dedicated attacker VM. Events show `::1` / `127.0.0.1` as the source. In a real incident this would be an external IP.
- **SSH traffic is encrypted**, so the Wireshark capture shows the *connection pattern*, not the guessed passwords.
- **Hayabusa cannot evaluate Sigma `count()` aggregations**, which is exactly why the custom PowerShell correlation script exists (and why Wazuh's native correlation is a useful contrast).
- **The Wazuh server is a lab deployment.** It uses the installer's self-signed certificate, and its exposure is limited by a host-IP firewall rather than a full production hardening baseline.

These constraints were turned into design decisions and documented, rather than hidden.

---

## Lessons Learned

- **Off-the-shelf detection has gaps.** A burst of failed logons needed a custom correlation rule to be flagged. Knowing *what the tools miss* is as important as running them.
- **Triage is the real skill.** Most alerts were benign or false positives; verifying command lines separated signal from noise.
- **Detective + preventive controls work together.** Logging made the attack visible; the lockout policy stopped it.
- **Constraints force good engineering.** Working within 8 GB of RAM produced a leaner, better-understood lab than a copy-paste multi-VM build would have — the SIEM moved to a small, firewalled cloud server instead.
- **The same attack looks different in different tools.** Hayabusa needed a custom rule to flag the brute force; Wazuh correlated it out of the box. Comparing them is more valuable than running just one.

---

## Cloud SIEM (Wazuh)

A full Wazuh SIEM was deployed on a hardened Hetzner cloud server (Ubuntu 24.04, 8 GB), and the Windows endpoint was connected as an agent forwarding Security and Sysmon events over TLS.

- **Hardening:** UFW firewall denies all inbound by default; SSH (22), dashboard (443), and agent ports (1514/1515) are each restricted to a single home IP. Key-only SSH, no password login. The dashboard is never exposed to the open internet.
- **Result:** the controlled brute force appeared in Wazuh in real time — 8 authentication failures, automatically mapped to MITRE ATT&CK Brute Force (T1110) and correlated by built-in rule 60204.
- See `screenshots/07`–`10` for the dashboard, the active agent, the MITRE mapping, and the server.

### Roadmap (v3)

- [ ] Reproduce the brute force with a **real external source IP** between two cloud hosts.
- [ ] Capture that network-based attack in Wireshark and correlate it with the Wazuh alert.
- [ ] Add custom Wazuh rules/decoders and a File Integrity Monitoring scenario.

---

## Credits & License

- Sysmon configuration baseline: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- Detection engine: [Hayabusa by Yamato Security](https://github.com/Yamato-Security/hayabusa)
- Sigma detection format: [SigmaHQ](https://github.com/SigmaHQ/sigma)
- SIEM platform: [Wazuh](https://github.com/wazuh/wazuh)

Licensed under the [MIT License](LICENSE). This is a personal learning portfolio project, not professional work experience.
