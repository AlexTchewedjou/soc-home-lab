# Honeypot Threat Intelligence — Cowrie → Wazuh

## Overview

I deployed a live SSH/Telnet honeypot using **Cowrie**, connected to a **Wazuh SIEM**, to observe and analyze unsolicited activity targeting an internet-facing system.

Unlike the previous phases of this lab, which relied on simulated attacks from localhost, this deployment allowed me to collect activity originating from external IP addresses. Over the first approximately 18 hours, the honeypot recorded authentication attempts, shell commands, file uploads, and a malware sample.

This report documents the activity observed during that period, the analysis performed, and how the collected events were integrated into Wazuh for detection and investigation.

> **Ethics and scope:** The honeypot runs on infrastructure I own and deliberately expose to attract opportunistic attackers. Cowrie operates as a medium-interaction honeypot, providing a simulated shell rather than access to the underlying operating system. No third-party systems were targeted. Captured malware was handled in a read-only manner and was never executed. IP addresses are documented as observed sources, not as confirmed identities of attackers.

---

## 1. Objective

The objective of this phase was to move beyond simulated attack scenarios and observe how automated systems interact with an exposed SSH/Telnet service.

I wanted to investigate several aspects of attacker activity:

- Which source IP addresses were connecting to the honeypot?
- What usernames and passwords were being attempted?
- Which commands were entered after authentication?
- Were attackers attempting to upload or execute malicious files?
- Could the captured activity be detected and classified through custom Wazuh rules?

The collected data would also provide an opportunity to investigate a real malware sample without executing it.

---

## 2. Architecture

The deployment consists of a cloud-hosted Cowrie instance and a separate Wazuh SIEM environment.

```text
       Internet (external scanners / bots)
                    |
                    | Port 22
                    v
       +---------------------------+
       |     Honeypot Server       |
       | Hetzner CPX11             |
       | Ubuntu 24.04              |
       |                           |
       | Cowrie (SSH/Telnet)       |
       | Wazuh Agent               |
       |                           |
       | Admin SSH: Port 64295     |
       +-------------+-------------+
                     |
                     | TLS (1514)
                     v
              +-------------+
              |  Wazuh SIEM |
              |             |
              | Manager     |
              | Indexer     |
              | Dashboard   |
              +-------------+
                     |
                     v
             Custom Cowrie Rules
                     |
                     v
              MITRE ATT&CK
             mapped alerts
```

### Security configuration

Before exposing Cowrie on port 22, I moved administrative SSH access to port **64295** and restricted it through firewall rules to my home IP address.

This separation ensures that external connections to port 22 interact with Cowrie rather than the server's administrative SSH service.

Additional precautions included:

- Keeping the Wazuh dashboard inaccessible from the public internet.
- Using the Wazuh agent to forward Cowrie logs to the SIEM over TLS.
- Restricting administrative access through firewall rules.
- Keeping captured malware contained and avoiding execution.

**Configuration references:**
- Setup guide: `docs/setup-guide.md`
- Custom detection rules: `detection-rules/cowrie_rules.xml`

---

## 3. Activity Overview — First 18 Hours

The following figures summarize the activity recorded during the initial deployment period.

| Metric | Observed value |
|---|---:|
| Total Cowrie events | ~28,000 |
| Total Wazuh alerts | ~12,800 |
| Unique source IP addresses | **104** |
| Login attempts | ~3,350 |
| Cowrie successful login events | 3,311 |
| Commands entered | ~4,250 |
| Unique malware samples captured | 1 |
| Malware upload occurrences | 24 |

Cowrie reported 3,311 successful authentication events. These should not be interpreted as successful compromises of a real operating system. Cowrie accepts authentication attempts within its simulated environment to allow subsequent attacker interactions to be observed.

The first automated connection was recorded within minutes of making the service publicly accessible.

One observation from this initial period was the volume of automated activity targeting a newly exposed SSH service.

---

## 4. Source IP Analysis

The following table lists the highest-volume source IP addresses observed during the collection period.

| Source IP | Connections | Geolocation / Network attribution |
|---|---:|---|
| 109.160.32.133 | 1,198 | Netherlands — TechTies Inc. |
| 109.160.32.131 | 1,198 | Netherlands — TechTies Inc. |
| 195.178.110.218 | 785 | Andorra — Techoff SRV Limited |
| 195.178.110.30 | 96 | Andorra — Techoff SRV Limited |
| 80.94.92.179 | 23 | Netherlands — Unmanaged LTD |
| 35.210.149.174 | 10 | Belgium — Google Cloud |

### Observations

Two IP addresses, `109.160.32.133` and `109.160.32.131`, generated approximately 1,200 connections each. Both belong to the same reported /24 network range.

Their connection volumes and proximity within the same network range suggest similar or potentially coordinated automated activity. However, this alone does not establish that they belong to the same botnet or operator.

Another source, `35.210.149.174`, was associated with Google Cloud infrastructure. Its presence demonstrates that attack traffic can originate from cloud-hosted infrastructure, although the available logs do not establish whether the instance was compromised or intentionally used for scanning.

These observations highlight why source IP attribution should be treated carefully. Geolocation and network ownership provide useful investigative context, but they do not independently identify the person or organization responsible for an attack.

---

## 5. Authentication Analysis

Cowrie recorded several username and password combinations commonly associated with automated SSH brute-force and credential-guessing activity.

### Most frequently attempted usernames

- `root` (959 attempts)
- `ubuntu`
- `admin`
- `user`
- `deploy`
- `postgres`
- `test`
- `guest`
- `claude` (24 attempts)
- `codex` (24 attempts)

The presence of `claude` and `codex` was particularly interesting because these usernames are associated with AI development tools. However, their appearance in the logs does not establish why they were targeted.

### Commonly attempted passwords

- `123456`
- `123`
- `1234`
- `12345678`
- `password`
- `root`
- `null`

### Common username/password combinations

| Username | Password |
|---|---|
| root | null |
| root | 123456 |
| ubuntu | 123456 |
| super | super |
| admin | admin |
| grid | grid |
| codex | codex |

### Analysis

The credentials observed are consistent with automated dictionary-based guessing and attempts using common default credentials.

The results reinforce the importance of disabling password-based SSH authentication where possible, using strong unique credentials, and implementing additional access controls such as rate limiting and authentication restrictions.

It is important to distinguish these observations from a successful compromise. Cowrie records authentication and subsequent interactions inside its simulated environment; the results do not demonstrate that these credentials would have provided access to a real system.

---

## 6. Attacker Activity and MITRE ATT&CK Mapping

After authentication, several sources entered commands that followed a recognizable sequence: system discovery, file transfer, permission changes, execution attempts, and network tunneling.

The following table maps the observed activity to relevant MITRE ATT&CK techniques.

| Activity | Observed behavior | MITRE ATT&CK |
|---|---|---|
| System discovery | `uname -s -v -n -r -m` (3,262 occurrences) | T1082 — System Information Discovery |
| File transfer | Upload of hidden file `.16` (24 occurrences) | T1105 — Ingress Tool Transfer |
| Privilege escalation attempt | `echo '<guessed-pw>' \| sudo -S chmod +x /root/.16` | T1548 — Abuse Elevation Control Mechanism |
| Execution attempt | `chmod +x /root/.16` followed by execution | T1059 — Command and Scripting Interpreter |
| Network tunneling | SSH tunnel attempts targeting `google.com:443` (11 occurrences) | T1090 — Proxy |
| Sandbox detection | Arithmetic and shell-scope probes | T1497 — Virtualization/Sandbox Evasion |

### Observed command sequence

One of the recurring sequences involved:

1. Retrieving system information using `uname`.
2. Uploading a hidden file named `.16`.
3. Attempting to change the file's permissions.
4. Using `sudo -S` with a guessed password.
5. Attempting to execute the uploaded file.

The activity suggests an automated deployment process intended to install and run a payload on the target system.

There were also attempts to establish SSH tunnels targeting `google.com:443`. This behavior is consistent with attempts to use the host as an intermediary for network traffic. The logs establish that tunneling was attempted, but do not independently demonstrate that a functional open relay was established.

Some commands also appeared designed to test shell behavior and identify whether the environment was a honeypot.

---

## 7. Malware Analysis

During the investigation, Cowrie captured a file repeatedly uploaded by external sources under the name `.16`.

I performed an initial static inspection to identify its file format and characteristics.

### Sample information

| Attribute | Result |
|---|---|
| SHA-256 | `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` |
| File size | 3.3 MB |
| Format | ELF 64-bit LSB |
| Architecture | x86-64 |
| Linking | Statically linked |
| Binary status | Stripped |
| Packer | UPX |
| Classification | Cryptocurrency miner (cryptojacking) |

The static inspection also identified references to `libcurl`, suggesting network communication functionality associated with the sample.

### Notable findings

One particularly interesting finding was the presence of strings referencing `fail2ban`, including:

- `maxretry=3`
- `bantime=-1`
- iptables-based banning

These strings suggest that the malware may attempt to configure firewall-based blocking through fail2ban.

If implemented as indicated, this could prevent competing connections or other automated processes from accessing the infected host. In a cryptocurrency-mining context, such behavior could help maintain the attacker's access to system resources.

However, because the sample was not executed, the actual runtime behavior and effectiveness of this configuration were not verified.

The binary was also UPX-packed, statically linked, and stripped. These characteristics can make initial inspection more difficult and allow the executable to run without relying on the same external library dependencies as a dynamically linked binary.

> **Handling procedure:** The sample was inspected using read-only tools such as `file` and `strings`. It was never executed. Further analysis could include submitting its SHA-256 hash to VirusTotal and performing controlled dynamic analysis inside an isolated malware-analysis sandbox.

---

## 8. Wazuh Detection and Alerting

To integrate Cowrie activity into the SIEM, I configured custom Wazuh rules to parse the JSON logs generated by Cowrie.

The objective was to convert individual honeypot events into structured alerts that could be investigated and correlated through the Wazuh dashboard.

### Custom detection rules

| Rule ID | Detected event | Level | MITRE ATT&CK |
|---|---|---:|---|
| 100101 | Failed login | 5 | T1110 |
| 100102 | Successful login (simulated shell access) | 10 | T1110 |
| 100103 | Command executed | 8 | T1059 |
| 100104 | File download / malware transfer | 12 | T1105 |
| 100105 | New connection | 3 | — |

**Detection configuration:** `detection-rules/cowrie_rules.xml`

### SIEM results

During the first 18 hours, Wazuh generated approximately 12,800 alerts from the collected Cowrie events.

The alerts were categorized across several activity types, including:

- Brute Force
- Command and Scripting Interpreter
- Ingress Tool Transfer

The custom rules allowed authentication attempts, command execution, file transfers, and new connections to appear as structured events in the SIEM.

**Supporting evidence:** `screenshots/11`–`12`

### Wazuh threat-hunting report

I also generated a report using Wazuh's built-in report functionality.

The report, available at `docs/wazuh-threat-hunting-report.pdf`, includes the custom rules that triggered, their descriptions, severity levels, and event counts.

One example of a generated alert description was:

> Cowrie: SUCCESSFUL login — attacker got a shell from 195.178.110.218 [admin/admin]

This provides supporting evidence that the custom detection rules were processing events collected from the live honeypot.

---

## 9. Indicators of Compromise (IOCs)

The investigation produced several indicators that can be retained for reference and further analysis.

### File indicator

| Type | Value |
|---|---|
| SHA-256 | `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` |
| File | `.16` |
| Classification | ELF cryptocurrency miner |

### High-volume source IP addresses

```text
109.160.32.133
109.160.32.131
195.178.110.218
195.178.110.30
80.94.92.179
```

### Behavioral indicators

- Hidden payload uploaded as `/root/.16`.
- Attempts to modify file permissions using `chmod +x`.
- Use of `sudo -S` with guessed credentials.
- SSH tunneling attempts targeting `google.com:443`.
- References to fail2ban configuration and firewall-based IP blocking within the malware sample.

These indicators describe activity observed during this deployment. They should not be treated as proof that every listed source IP is malicious outside the context of the investigation.

---

## 10. Lessons Learned

This deployment provided several observations that were not available during the earlier simulated attack scenarios.

**1. Publicly exposed services attract automated activity quickly.**

The first automated connection occurred within minutes of exposing the SSH service. Within approximately 18 hours, Cowrie had recorded 104 unique source IP addresses. This demonstrates the volume of automated scanning and authentication activity that internet-facing services can receive.

**2. Default credentials remain a common attack vector.**

Many of the attempted username/password combinations relied on predictable values such as `root:123456` and `admin:admin`. This reinforces the importance of strong authentication controls, disabling unnecessary password-based access, and restricting administrative services.

**3. Attackers follow recognizable automated sequences.**

The captured commands showed a recurring progression from system discovery to file transfer, permission modification, and execution attempts. Recognizing these patterns helps analysts identify suspicious behavior and develop detection rules around the sequence of events.

**4. Malware analysis requires more than identifying a file.**

The captured sample contained references to network communication, UPX packing, and fail2ban configuration. Even without executing it, static inspection provided useful information about its structure and potential functionality. It also demonstrated the importance of separating observed characteristics from behavior that has not been verified.

**5. SIEM integration makes the collected activity easier to investigate.**

Integrating Cowrie with Wazuh allowed raw honeypot events to be converted into structured alerts. Custom rules and MITRE ATT&CK mappings provided a way to classify the activity and review it through the SIEM dashboard.

Overall, this phase helped me understand how honeypot telemetry can complement traditional SOC monitoring by providing additional visibility into external reconnaissance, credential-guessing activity, command execution attempts, and malware delivery.

---

## 11. Safe Teardown

After completing the collection period, the honeypot environment is taken offline to prevent the infrastructure from remaining available for unintended use.

The teardown procedure includes stopping Cowrie and deleting the cloud server once any required evidence or snapshots have been retained.

```bash
# Stop Cowrie on the honeypot
cowrie stop

# After preserving required evidence:
# Delete the cloud server through the Hetzner console.
```

Captured malware remains contained in Cowrie's downloads directory. It is not executed or redistributed.

---

**Project scope:** This phase focused on collecting external attack telemetry, analyzing authentication and command activity, performing preliminary static malware inspection, and integrating the resulting events into Wazuh for detection and investigation.
