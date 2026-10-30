# SOC Home Lab — Security Monitoring & Incident Detection

This project documents the development of a small Security Operations Center (SOC) home lab built on a Windows 11 laptop with 8 GB of RAM. It uses a combination of open-source security tools and cloud infrastructure to monitor endpoint activity, investigate suspicious events, and test detection capabilities.

The lab covers several areas of security operations, including:

- Windows endpoint monitoring and event collection.
- Security event analysis using Hayabusa and Sigma rules.
- Custom detection logic using PowerShell.
- Network traffic investigation with Wireshark.
- Centralized monitoring and alerting with Wazuh.
- Incident investigation, documentation, and remediation.
- Threat intelligence collection using a Cowrie SSH/Telnet honeypot.

The initial phase focused on a controlled brute-force scenario against a dedicated Windows test account. I configured endpoint logging, generated authentication failures, and investigated the resulting events using different detection tools.

I later extended the environment with a Cowrie honeypot connected to Wazuh. This allowed me to collect unsolicited connections from the internet, examine attacker commands, and capture a malware sample for static analysis.

> **Ethics and scope:** All controlled testing was performed on infrastructure I own, using a dedicated test account. The honeypot was deliberately exposed to receive unsolicited connections. No third-party systems were targeted. Captured malware was handled without execution.

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Architecture](#architecture)
- [Tools and Technologies](#tools-and-technologies)
- [Detection Scenario: Brute-Force Attack](#detection-scenario-brute-force-attack)
- [Detection and Investigation Methodology](#detection-and-investigation-methodology)
- [Evidence and Screenshots](#evidence-and-screenshots)
- [Repository Structure](#repository-structure)
- [Setup and Reproduction](#setup-and-reproduction)
- [Limitations](#limitations)
- [Lessons Learned](#lessons-learned)
- [Cloud SIEM Deployment — Wazuh](#cloud-siem-deployment--wazuh)
- [Live Honeypot — Threat Intelligence](#live-honeypot--threat-intelligence)
- [Future Improvements](#future-improvements)
- [Credits and License](#credits-and-license)

---

## Overview

The project was developed in several stages, starting with endpoint monitoring and progressing to centralized detection and threat intelligence collection.

The initial workflow involved:

1. Configuring a Windows 11 endpoint with Sysmon, Windows Advanced Audit Policy, and PowerShell Script Block Logging.
2. Creating a dedicated test account and generating controlled authentication failures.
3. Collecting and analyzing Windows Security and Sysmon events.
4. Using Hayabusa, custom PowerShell detection logic, Wireshark, and Wazuh to investigate the activity.
5. Documenting the findings in an incident report, including the timeline, evidence, impact assessment, and remediation.

The project was subsequently extended with a Cowrie honeypot to collect activity from external internet sources.

One finding from the initial investigation was that Hayabusa's default detection rules did not generate a consolidated brute-force alert for the tested sequence of failed logons. I developed a PowerShell script to perform the required correlation. During a separate replay, Wazuh identified the authentication burst using its built-in rule 60204.

The honeypot phase provided another perspective by collecting unsolicited authentication attempts, commands, file uploads, and a malware sample from external sources.

---

## Objectives

The main objectives of this lab were to:

- Configure endpoint security monitoring using Sysmon and Windows Event Logs.
- Enable Windows authentication and process-creation auditing.
- Collect PowerShell execution telemetry.
- Analyze exported Windows event logs using Hayabusa and Sigma rules.
- Develop custom detection logic for repeated failed authentication attempts.
- Examine network connection patterns using Wireshark.
- Deploy a centralized Wazuh SIEM on cloud infrastructure.
- Forward Windows endpoint events to the SIEM over TLS.
- Investigate and document a simulated security incident.
- Deploy a Cowrie honeypot to collect unsolicited internet activity.
- Perform preliminary static analysis of a captured malware sample.
- Develop custom Wazuh detection rules for Cowrie events.

---

## Architecture

The lab was designed around a hardware limitation: the laptop has 8 GB of RAM, with approximately 2 GB available after initial system optimization.

Running multiple virtual machines locally would have placed unnecessary pressure on the host. Instead, I used a host-based monitoring architecture and moved the SIEM components to a cloud server.

### Main detection architecture

```text
       +--------------------------------------------+
       |       Windows 11 Host — Endpoint           |
       |                                            |
       |  +------------+   +--------------------+   |
       |  |  Sysmon    |   |  Windows Audit     |   |
       |  |            |   |  Policy             |   |
       |  +-----+------+   +---------+----------+   |
       |        |                    |              |
       |        v                    v              |
       |  +--------------------------------------+  |
       |  |         Windows Event Logs           |  |
       |  +------------------+-------------------+  |
       |                     |                      |
       |      +--------------+--------------+       |
       |      |              |              |       |
       |      v              v              v       |
       |   Hayabusa       PowerShell     Wireshark  |
       |   (Sigma)        Detection       / tshark  |
       |                     |                      |
       |              Wazuh Agent                   |
       +---------------------+----------------------+
                             |
                             | TLS
                             | Ports 1514 / 1515
                             v
                 +--------------------------+
                 |    Hetzner Cloud         |
                 |    Ubuntu 24.04          |
                 |                          |
                 |    Wazuh Manager         |
                 |    Wazuh Indexer         |
                 |    Wazuh Dashboard       |
                 +--------------------------+
```

### Honeypot architecture

A separate cloud server hosts Cowrie and a Wazuh agent. External connections to SSH/Telnet are directed to the simulated environment, while Cowrie events are forwarded to the SIEM.

```text
       Internet — External Sources
                   |
                   | SSH / Telnet
                   v
          +----------------------+
          |  Cowrie Honeypot     |
          |  Hetzner Cloud       |
          |  Ubuntu 24.04        |
          |                      |
          |  Simulated Shell     |
          |  Wazuh Agent         |
          +----------+-----------+
                     |
                     | TLS
                     v
              +-------------+
              |  Wazuh SIEM |
              |             |
              |  Manager    |
              |  Indexer    |
              |  Dashboard  |
              +-------------+
```

### Architecture decisions

The Windows endpoint handles event collection and offline analysis. Wazuh runs on a separate cloud server, avoiding the need to host the full SIEM locally.

Memory Integrity (VBS) and Microsoft Defender remained enabled throughout the setup.

The cloud infrastructure was also configured with firewall restrictions. Administrative SSH, dashboard access, and agent communication ports were restricted to the required source IP addresses rather than being exposed indiscriminately to the internet.

For the complete environment assessment and configuration steps, see [`docs/setup-guide.md`](docs/setup-guide.md).

---

## Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| Sysmon | Endpoint telemetry, process creation, DNS activity |
| Windows Advanced Audit Policy | Authentication, account management, and process auditing |
| PowerShell Script Block Logging | PowerShell execution monitoring |
| Hayabusa | Offline Windows event log analysis using Sigma rules |
| Sigma | Detection rule format |
| Custom PowerShell | Brute-force correlation and event analysis |
| Wireshark / tshark | Network traffic capture and analysis |
| Wazuh 4.14 | Centralized SIEM, alerting, and MITRE ATT&CK mapping |
| Cowrie | SSH/Telnet honeypot |
| Hetzner Cloud | Hosting for the Wazuh SIEM and honeypot |
| Ubuntu 24.04 | Cloud server operating system |
| MITRE ATT&CK | Classification of observed adversary techniques |

**Infrastructure:** Hetzner Cloud servers were used for the SIEM and honeypot deployments. The server configurations differed according to their workloads.

---

## Detection Scenario: Brute-Force Attack

The first attack scenario involved repeated password attempts against a dedicated local Windows test account.

The objective was to generate authentication events, verify the account lockout policy, and determine whether the activity could be identified using the available detection tools.

### Observed activity

| Event | Windows Event ID | Result |
|---|---|---|
| Test account creation | 4720 | Account created |
| Failed authentication | 4625 | 6 events recorded |
| Account lockout | 4740 | Lockout triggered |
| Network connection activity | — | Captured with Wireshark |

### Custom detection output

```text
[!] BRUTE-FORCE DETECTED

TargetUser    : <test account>
FailedCount   : 6
FirstAttempt  : 2026-10-27 15:21:12
LastAttempt   : 2026-10-27 15:21:17
AccountLocked : True
MITRE ATT&CK  : T1110 / T1110.001
```

The custom PowerShell script identified six failed logons against the same account within the configured five-minute window.

The Windows account lockout policy was triggered, and no successful authentication was identified during the investigation.

A separate replay through Wazuh recorded eight authentication failures and zero successful logons.

**Full incident report:** [`incident-reports/sample-incident-report.md`](incident-reports/sample-incident-report.md)

---

## Detection and Investigation Methodology

The investigation used multiple sources of telemetry to examine authentication activity, endpoint events, and network connections.

### 1. Host-Based Monitoring

Sysmon and Windows Advanced Audit Policy were configured to collect relevant endpoint activity.

The main event sources included:

- Event ID 4625 — Failed logon.
- Event ID 4740 — Account lockout.
- Event ID 4720 — User account creation.
- Event ID 4688 — Process creation.
- Event ID 4104 — PowerShell Script Block Logging.
- Sysmon Event ID 1 — Process creation.
- Sysmon Event ID 22 — DNS query.

### 2. Offline Log Analysis — Hayabusa

Hayabusa was used to analyze exported Windows event logs against Sigma-based detection rules.

Approximately 36,000 raw events were processed, producing seven prioritized findings for manual review.

The investigation identified events associated with:

- Account and audit-policy configuration.
- System discovery.
- Administrative password changes.
- Potential Active Directory enumeration.

The findings were reviewed against the underlying event data before being classified as benign true positives or false positives.

### 3. Custom Detection Development

The default Hayabusa rules did not generate a consolidated alert for the tested sequence of repeated failed logons.

To address this, I developed a PowerShell script that:

- Groups Event ID 4625 records by target account.
- Evaluates the number of failures within a sliding time window.
- Generates an alert when the configured threshold is reached.
- Checks for a corresponding Event ID 4740 account lockout.

The detection threshold was five failed logons against the same account within five minutes.

### 4. Network Analysis — Wireshark

Wireshark and tshark were used to examine the network activity associated with a controlled SSH brute-force exercise.

The capture showed repeated TCP connections to port 22 from the local source address.

Because SSH encrypts authentication traffic, the capture provided connection metadata rather than the passwords entered during the attempts.

### 5. Live SIEM Monitoring — Wazuh

The Windows endpoint was connected to Wazuh through its agent.

During a separate replay of the brute-force scenario, Wazuh generated eight authentication-failure events and correlated them using built-in rule 60204, *Multiple Windows Logon Failures*.

The alert was automatically mapped to MITRE ATT&CK T1110 — Brute Force.

### Comparison

The testing highlighted a difference between the tools:

- Hayabusa was useful for offline event analysis and forensic timelines, but additional correlation logic was needed for the tested brute-force sequence.
- The custom PowerShell script performed the required threshold-based correlation.
- Wazuh generated a consolidated alert through its built-in correlation rule during the separate replay.

This comparison helped identify where additional detection logic was necessary and how centralized monitoring could support the investigation.

**Full methodology:** [`docs/detection-methodology.md`](docs/detection-methodology.md)

---

## Evidence and Screenshots

The repository includes screenshots documenting the configuration, detection process, and investigation results.

| Screenshot | Description |
|---|---|
| `01-sysmon-event-id-1.png` | Sysmon process-creation logging |
| `02-event-4625-failed-logon.png` | Windows failed authentication event |
| `04b-hayabusa-security-summary.png` | Hayabusa detection summary |
| `05-bruteforce-detection.png` | Custom PowerShell detection output |
| `06-wireshark-ssh-bruteforce.png` | SSH connection activity in Wireshark |
| `07-wazuh-dashboard-overview.png` | Wazuh SIEM dashboard |
| `08-wazuh-agent-active.png` | Windows endpoint connected to Wazuh |
| `09-wazuh-bruteforce-mitre.png` | Wazuh brute-force alert and MITRE mapping |
| `09b-wazuh-bruteforce-events.png` | Individual Wazuh authentication alerts |
| `10-hetzner-server.png` | Cloud server running Wazuh |
| `11-wazuh-cowrie-overview.png` | Cowrie events and MITRE breakdown |
| `12-wazuh-cowrie-events.png` | Individual honeypot alerts |

Browse the complete collection in [`screenshots/`](screenshots/).

> Raw Windows event logs (`.evtx`) and policy backups are not published because they may contain personal information and full system activity. Only reviewed and appropriately redacted evidence is included.

---

## Repository Structure

```text
soc-home-lab/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── configs/
│   └── sysmonconfig.xml
│
├── docs/
│   ├── setup-guide.md
│   ├── detection-methodology.md
│   ├── honeypot-analysis.md
│   └── wazuh-threat-hunting-report.pdf
│
├── detection-rules/
│   ├── bruteforce_failed_logon_4625.yml
│   ├── failed_logon_4625.yml
│   └── cowrie_rules.xml
│
├── scripts/
│   └── Detect-BruteForce.ps1
│
├── incident-reports/
│   └── sample-incident-report.md
│
├── screenshots/
│   ├── 01-sysmon-event-id-1.png
│   ├── 02-event-4625-failed-logon.png
│   └── ...
│
└── logs/
    └── README.md
```

The `evidence/` directory is maintained locally and excluded from the public repository.

---

## Setup and Reproduction

The endpoint configuration and Wazuh deployment are documented in [`docs/setup-guide.md`](docs/setup-guide.md).

The main setup process is:

1. Assess available system resources.
2. Enable Sysmon and apply the configuration in `configs/`.
3. Configure Windows Advanced Audit Policy.
4. Enable PowerShell Script Block Logging.
5. Increase relevant Windows event log retention sizes.
6. Deploy the Wazuh SIEM on the cloud server.
7. Install and connect the Wazuh agent on the Windows endpoint.
8. Generate the controlled authentication scenario.
9. Export and analyze the Windows event logs.
10. Run the custom PowerShell detection script.

The guide includes the commands, configuration files, validation checks, and rollback procedures used during implementation.

---

## Limitations

The lab was developed with specific hardware and testing constraints. These limitations are documented because they affect how the results should be interpreted.

**Local attack generation**

The original brute-force scenario was generated locally rather than from a separate attacker virtual machine. The source address was therefore `::1` or `127.0.0.1`, depending on the test.

**Encrypted SSH traffic**

Wireshark captured the TCP connection pattern but could not reveal the passwords entered through SSH.

**Offline correlation**

Hayabusa's default rules did not provide the required aggregation for the tested failed-logon sequence. A custom PowerShell script was used for that purpose.

**Cloud SIEM configuration**

Wazuh was deployed for lab use on a cloud server. Its dashboard used a self-signed certificate, and access was restricted through firewall rules to the permitted source IP.

**Honeypot attribution**

The honeypot recorded 104 unique source IP addresses. These represent observed network sources, not 104 confirmed individual attackers. Network ownership and geolocation information do not establish the identity of an operator.

**Malware analysis**

The captured sample was inspected using static analysis tools. Its suspected runtime behavior was not verified through execution.

These limitations define the scope of the testing and identify areas for further development.

---

## Lessons Learned

Working through the different stages of this lab provided several practical observations.

- **Detection coverage needs to be tested.** The default Hayabusa rules did not generate the required brute-force correlation, so additional detection logic was necessary.
- **Alert investigation requires context.** Reviewing the original event records and command lines helped distinguish legitimate administrative activity from suspicious behavior.
- **Preventive and detective controls serve different purposes.** Windows logging provided visibility into the authentication attempts, while the account lockout policy stopped further password guessing.
- **Resource constraints influence architecture.** Moving Wazuh to a cloud server allowed the laptop to remain dedicated to endpoint monitoring and offline analysis.
- **Different tools provide different perspectives.** Hayabusa, PowerShell, Wireshark, and Wazuh each contributed different information during the investigation.
- **External telemetry provides additional investigative opportunities.** The Cowrie deployment collected activity that could not be reproduced through the original localhost scenario, including external source IPs, credential attempts, command sequences, and a malware sample.

---

## Cloud SIEM Deployment — Wazuh

A centralized Wazuh SIEM was deployed on a Hetzner cloud server running Ubuntu 24.04.

The deployment included:

- Wazuh Manager.
- Wazuh Indexer.
- Wazuh Dashboard.
- Windows Wazuh Agent.

### Security configuration

The server was configured with:

- UFW firewall using a default-deny inbound policy.
- SSH access restricted to the permitted home IP.
- Dashboard access restricted to the permitted home IP.
- Agent communication ports 1514 and 1515 restricted to the required source address.
- SSH key authentication instead of password authentication.

The Windows endpoint forwarded Security and Sysmon events to the manager over the configured connection.

### Validation

During the separate brute-force replay, Wazuh recorded:

- 8 authentication failures.
- 0 successful authentications.
- Built-in rule 60204 — Multiple Windows Logon Failures.
- Automatic MITRE ATT&CK mapping to T1110.

The agent connection and alert generation were verified through the Wazuh dashboard.

Supporting evidence is available in `screenshots/07`–`10`.

---

## Live Honeypot — Threat Intelligence

After completing the initial detection exercises, I extended the lab with a Cowrie SSH/Telnet honeypot.

The objective was to collect unsolicited activity from external sources rather than relying exclusively on locally generated attacks.

Cowrie was deployed on a separate hardened Hetzner cloud server and connected to the Wazuh SIEM through its agent.

Within minutes of becoming publicly accessible, the honeypot began receiving automated connections.

### Results — First 18 Hours

| Metric | Observed value |
|---|---:|
| Cowrie events | ~28,000 |
| Wazuh alerts | ~12,800 |
| Unique source IPs | 104 |
| Login attempts | ~3,350 |
| Commands entered | ~4,250 |
| Unique malware samples | 1 |
| Malware upload occurrences | 24 |

### Key observations

- **Repeated connections:** Two IP addresses from the same Netherlands /24 network generated approximately 1,200 connections each.
- **Credential guessing:** Common usernames and passwords included `root`, `admin`, `123456`, and `password`. The usernames `claude` and `codex` also appeared in the captured authentication attempts.
- **Command execution:** Several sessions followed a sequence involving system discovery, file uploads, permission changes, and execution attempts.
- **Malware collection:** Cowrie captured a 3.3 MB UPX-packed, statically linked x86-64 ELF sample classified as a cryptocurrency miner through preliminary static inspection.
- **Network activity:** Some sessions attempted SSH tunneling to `google.com:443`.
- **Honeypot detection:** Certain commands appeared designed to examine shell behavior and identify whether the environment was simulated.

### Wazuh integration

Custom Wazuh rules were configured to process Cowrie JSON events and generate severity-rated alerts with MITRE ATT&CK mappings.

Approximately 12,800 alerts were recorded during the first 18 hours.

The captured malware was handled read-only and was never executed.

**Detailed analysis:**
[`docs/honeypot-analysis.md`](docs/honeypot-analysis.md)

**Generated SIEM report:**
[`docs/wazuh-threat-hunting-report.pdf`](docs/wazuh-threat-hunting-report.pdf)

**Supporting screenshots:**
- `screenshots/11-wazuh-cowrie-overview.png`
- `screenshots/12-wazuh-cowrie-events.png`

---

## Future Improvements

The next development stages will focus on extending the existing detection and investigation capabilities.

- Reproduce the brute-force scenario using an external source IP between two controlled cloud hosts.
- Capture external network attack traffic in Wireshark and correlate it with Wazuh alerts.
- Develop additional custom Wazuh rules and decoders.
- Add a File Integrity Monitoring (FIM) scenario.
- Perform further malware analysis in an isolated environment.
- Expand detection coverage for additional MITRE ATT&CK techniques.

---

## Credits and License

This project uses several open-source tools and community resources:

- Sysmon configuration: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- Windows event log analysis: [Hayabusa — Yamato Security](https://github.com/Yamato-Security/hayabusa)
- Detection rule format: [SigmaHQ](https://github.com/SigmaHQ/sigma)
- SIEM platform: [Wazuh](https://github.com/wazuh/wazuh)
- SSH/Telnet honeypot: [Cowrie](https://github.com/cowrie/cowrie)

Licensed under the [MIT License](LICENSE).
