# Honeypot Threat Intelligence — Cowrie → Wazuh

A live SSH/Telnet honeypot (Cowrie) deployed on the internet, feeding a Wazuh SIEM, to capture and analyze **real** attacker behavior. This document reports the findings from the first ~18 hours of operation.

> **Ethics & scope:** The honeypot is infrastructure I own, deliberately exposed to attract opportunistic attackers. It is a **medium-interaction** honeypot: attackers interact with a sandboxed fake shell and never reach a real system. No third parties were attacked. Captured malware is handled read-only and never executed. Attacker IPs are reported as observed indicators of compromise.

---

## 1. Why a Honeypot

The earlier phases of this lab used a *simulated* attack from localhost. A honeypot removes that limitation: it collects **genuine, unsolicited attacks from the internet**, with real source IPs, real credential dictionaries, and real malware — the kind of data a SOC analyst works with daily.

---

## 2. Architecture

```
   Internet (real attackers / bots)
            │  port 22 (exposed on purpose)
            ▼
   ┌───────────────────────────┐
   │  Honeypot server          │   Hetzner CPX11, Ubuntu 24.04
   │  Cowrie (SSH/Telnet)      │   admin SSH moved to port 64295
   │  + Wazuh agent  ──────────┼────TLS (1514)───▶ Wazuh SIEM
   └───────────────────────────┘                  (manager+indexer+dashboard)
                                                   custom Cowrie rules →
                                                   MITRE-mapped alerts
```

**Hardening:** real admin SSH was moved to port **64295** (firewalled to my home IP) *before* Cowrie took port 22, so the honeypot never exposes real access. Cowrie's fake shell keeps attackers sandboxed. The Wazuh dashboard is never exposed to the internet.

Setup steps: [`docs/setup-guide.md`](setup-guide.md) · Detection rules: [`detection-rules/cowrie_rules.xml`](../detection-rules/cowrie_rules.xml)

---

## 3. Volume (first ~18 hours)

| Metric | Value |
|---|---|
| Total Cowrie events | ~28,000 |
| Total Wazuh alerts | ~12,800 |
| Unique attacker IPs | **104** |
| Login attempts | ~3,350 (3,311 "successful" — Cowrie accepts to observe behavior) |
| Commands executed by attackers | ~4,250 |
| Malware samples captured | 1 (uploaded 24×) |

The honeypot received its first automated attack **within minutes** of going live.

---

## 4. Top Attackers

| Source IP | Connections | Geolocation / ISP |
|---|---|---|
| 109.160.32.133 | 1,198 | Netherlands — TechTies Inc. |
| 109.160.32.131 | 1,198 | Netherlands — TechTies Inc. |
| 195.178.110.218 | 785 | Andorra — Techoff SRV Limited |
| 195.178.110.30 | 96 | Andorra — Techoff SRV Limited |
| 80.94.92.179 | 23 | Netherlands — Unmanaged LTD |
| 35.210.149.174 | 10 | Belgium — Google Cloud (abused instance) |

Two IPs from the same Netherlands /24 hammered the honeypot ~1,200 times each — a coordinated botnet pair. One attacker was an **abused Google Cloud instance**, a compromised cloud VM repurposed to attack others.

---

## 5. Credentials Attempted

**Top usernames:** `root` (959), `ubuntu`, `admin`, `user`, `deploy`, `postgres`, `test`, `guest` — and notably **`claude`** and **`codex`** (24× each): bots now probe for AI-tool-related accounts.

**Top passwords:** `123456`, `123`, `1234`, `12345678`, `password`, `root`, `null` — standard weak-credential dictionaries.

**Most common login pairs:** `root:null`, `root:123456`, `ubuntu:123456`, `super:super`, `admin:admin`, `grid:grid`, `codex:codex`.

**Takeaway:** every credential tried would have failed against a system with even a moderately strong password — reinforcing the Phase-1 finding that password strength + lockout policy stop the overwhelming majority of real attacks.

---

## 6. Attacker Behavior (the kill chain)

The commands captured show a consistent automated playbook:

| Stage | Observed command | MITRE ATT&CK |
|---|---|---|
| **Reconnaissance** | `uname -s -v -n -r -m` (3,262×) | T1082 System Information Discovery |
| **Staging** | upload hidden file `.16` (24×) | T1105 Ingress Tool Transfer |
| **Privilege escalation** | `echo '<guessed-pw>' \| sudo -S chmod +x /root/.16` | T1548 Abuse Elevation Control |
| **Execution** | `chmod +x /root/.16` then run | T1059 Command and Scripting |
| **Proxy abuse** | SSH tunnel attempts to `google.com:443` (11×) | T1090 Proxy |
| **Anti-analysis** | arithmetic/shell-scope probes to detect honeypots | T1497 Virtualization/Sandbox Evasion |

Attackers also attempted to use the box as an **open relay** (tunneling to Google) — testing whether the compromised host could anonymize further attacks or spam.

---

## 7. Malware Analysis

Cowrie captured the payload attackers repeatedly uploaded (the `.16` file).

| Attribute | Value |
|---|---|
| **SHA-256** | `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` |
| **Size** | 3.3 MB |
| **File type** | ELF 64-bit LSB, x86-64, statically linked, **stripped** |
| **Packer** | UPX |
| **Classification** | Cryptocurrency miner (cryptojacking) with C2 (libcurl) |

**Notable behavior (from static strings):** the malware installs **fail2ban** (`maxretry=3`, `bantime=-1`, iptables banning) upon infection — it **locks out rival attackers** to monopolize the CPU for mining. It is statically linked and stripped to run on any x86-64 Linux host and resist analysis.

> The sample was analyzed **read-only** (`file`, `strings`) and never executed. In a production workflow the hash would be submitted to VirusTotal and the binary detonated only in an isolated sandbox.

---

## 8. Detection in Wazuh

Custom rules ([`detection-rules/cowrie_rules.xml`](../detection-rules/cowrie_rules.xml)) parse Cowrie's JSON and raise severity-rated, MITRE-mapped alerts:

| Rule ID | Event | Level | MITRE |
|---|---|---|---|
| 100101 | Failed login | 5 | T1110 |
| 100102 | **Successful login (shell obtained)** | 10 | T1110 |
| 100103 | Command executed | 8 | T1059 |
| 100104 | **File download (malware)** | 12 | T1105 |
| 100105 | New connection | 3 | — |

These produced the live dashboard: ~12,800 alerts auto-classified across Brute Force, Command and Scripting, and Ingress Tool Transfer. Evidence: `screenshots/11`–`12`.

A full auto-generated SIEM report (Wazuh "Generate report") is included at [`docs/wazuh-threat-hunting-report.pdf`](wazuh-threat-hunting-report.pdf). It lists every custom rule that fired with its resolved description, level, and count — e.g. *"Cowrie: SUCCESSFUL login — attacker got a shell from 195.178.110.218 [admin/admin]"* — demonstrating the rules working against live attack data.

---

## 9. Indicators of Compromise (IOCs)

**Malware hash:**
- `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` (ELF cryptominer)

**High-volume attacker IPs:**
- `109.160.32.133`, `109.160.32.131`, `195.178.110.218`, `195.178.110.30`, `80.94.92.179`

**Behavioral IOCs:**
- Hidden payload at `/root/.16`
- `sudo -S` privilege escalation using guessed passwords
- fail2ban abused for attacker competitor-exclusion

---

## 10. Lessons Learned

- **Attacks are constant and automated.** An unknown host on the internet is found and attacked within minutes, 104 distinct attackers in under a day.
- **Weak credentials are the entire game.** Every attempt relied on default/weak passwords; strong passwords + lockout (from Phase 1) defeat essentially all of it.
- **Real malware is messy and clever.** The captured miner packs itself (UPX), hides (`.16`, stripped), escalates with the victim's own guessed password, and even blocks competitors — detail you only appreciate from a real sample.
- **A honeypot turns theory into evidence.** Instead of a simulated `::1` attack, this produced genuine source IPs, credential dictionaries, a malware sample, and IOCs — exactly the artifacts a SOC analyst triages.

---

## 11. Safe Teardown

When finished, the honeypot is destroyed so it cannot be abused:
```bash
# stop and remove
cowrie stop        # on the honeypot
# then delete the cloud server (snapshot first if keeping)
```
Captured malware stays contained in the Cowrie downloads directory and is never executed or redistributed.
