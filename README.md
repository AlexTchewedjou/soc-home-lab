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
- [Roadmap (v2)](#roadmap-v2)
- [Credits & License](#credits--license)

---

## Overview

This project simulates a mini SOC workflow end to end:

1. Instrument a Windows 11 endpoint with Sysmon, an advanced audit policy, and PowerShell logging.
2. Generate a **controlled brute-force attack** against a dedicated test account.
3. Detect it with **Hayabusa** (Sigma rules), a **custom detection rule**, and **Wireshark**.
4. Investigate, triage, and document the incident as a SOC analyst would.

A key theme is **honesty about scope**: the default rule set did *not* flag the brute force, so I identified that detection gap and wrote a custom correlation rule to fill it.

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
- [ ] Centralized SIEM dashboard (Wazuh) — *planned for v2, see [Roadmap](#roadmap-v2)*

---

## Architecture

The lab was designed around a real constraint: **8 GB of RAM**, with only ~2 GB free after cleanup. A traditional multi-VM lab (Kali attacker + Windows victim + Linux SIEM) could not run. The architecture was adapted to a **host-based** design that delivers the same learning outcomes without overloading the machine.

```
                 +--------------------------------------------------+
                 |          Windows 11 Host (monitored endpoint)    |
                 |                                                  |
   Controlled    |   +------------+   +----------------+            |
   attack  ----->|   |  Sysmon    |   | Audit Policy   |            |
   (localhost)   |   | (native)   |   | 4625/4740/4688 |            |
                 |   +-----+------+   +-------+--------+            |
                 |         |                  |                     |
                 |         v                  v                     |
                 |     +---------------------------+                |
                 |     |   Windows Event Logs      |                |
                 |     +------------+--------------+                |
                 |                  |                               |
                 |      +-----------+-----------+                   |
                 |      |           |           |                   |
                 |      v           v           v                   |
                 |  Hayabusa   Custom rule   Wireshark              |
                 |  (Sigma)    (PowerShell)  (tshark)               |
                 +--------------------------------------------------+

   Planned (v2):  Wazuh SIEM on a cloud VM  <---- Wazuh agent forwards logs
```

**Why host-based instead of VMs?** See [`docs/setup-guide.md`](docs/setup-guide.md) for the full RAM assessment and the decision rationale. Security controls (Memory Integrity / VBS, Microsoft Defender) were kept **enabled** throughout.

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

Detection used three complementary layers, each reinforcing the others:

1. **Host logs** show *who* and *what* (failed logons, the lockout).
2. **Hayabusa** reduced ~36,000 raw events to 7 prioritized detections (>99% data reduction), which were then triaged.
3. **A custom rule** correlated the failed-logon burst that off-the-shelf rules missed.
4. **Wireshark** showed the attack pattern on the wire (a burst of short-lived connections).

Triage was done honestly: of 7 raw Hayabusa detections, 5 were **benign true positives** (my own authorized setup) and 2 were **false positives** (a rule matched a legitimate `net accounts` command). Every verdict was verified against the underlying command line.

Full methodology: [`docs/detection-methodology.md`](docs/detection-methodology.md)

---

## Evidence

Screenshots (with hostnames/usernames redacted) are in [`screenshots/`](screenshots/):

| File | Shows |
|---|---|
| `01-sysmon-event-id-1.png` | Sysmon process-creation logging working |
| `02-event-4625-failed-logon.png` | A failed logon (4625) during the attack |
| `03-event-4625-lockout.png` | The account-lockout event (4740) |
| `04b-hayabusa-security-summary.png` | Hayabusa detection summary |
| `05-bruteforce-detection.png` | Custom rule firing on the attack |
| `06-wireshark-ssh-bruteforce.png` | Network connection burst to port 22 |

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
- **No centralized SIEM dashboard yet.** Wazuh is planned for v2 (see below). Detection here uses Hayabusa + a custom script instead.
- **SSH traffic is encrypted**, so the Wireshark capture shows the *connection pattern*, not the guessed passwords.
- **Hayabusa cannot evaluate Sigma `count()` aggregations**, which is exactly why the custom PowerShell correlation script exists.

These constraints were turned into design decisions and documented, rather than hidden.

---

## Lessons Learned

- **Off-the-shelf detection has gaps.** A burst of failed logons needed a custom correlation rule to be flagged. Knowing *what the tools miss* is as important as running them.
- **Triage is the real skill.** Most alerts were benign or false positives; verifying command lines separated signal from noise.
- **Detective + preventive controls work together.** Logging made the attack visible; the lockout policy stopped it.
- **Constraints force good engineering.** Working within 8 GB of RAM produced a leaner, better-understood lab than a copy-paste multi-VM build would have.

---

## Roadmap (v2)

- [ ] Deploy **Wazuh** (manager + indexer + dashboard) on a cloud VM.
- [ ] Install the Wazuh agent on the endpoint and forward Security + Sysmon logs.
- [ ] Reproduce the brute force with a **real external source IP** between two cloud hosts.
- [ ] Capture that network-based attack in Wireshark and correlate it with the Wazuh alert.

---

## Credits & License

- Sysmon configuration baseline: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- Detection engine: [Hayabusa by Yamato Security](https://github.com/Yamato-Security/hayabusa)
- Sigma detection format: [SigmaHQ](https://github.com/SigmaHQ/sigma)

Licensed under the [MIT License](LICENSE). This is a personal learning portfolio project, not professional work experience.
