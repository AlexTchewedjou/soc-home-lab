# Incident Report — Brute-Force Attack and Account Lockout

| Field | Value |
|---|---|
| **Report ID** | IR-2026-001 |
| **Date of report** | 2026-10-27 |
| **Analyst** | Alex Tchewedjou |
| **Classification** | Simulated incident (controlled lab) |
| **Severity** | High (simulated detection scenario) |
| **Status** | Closed — contained, no compromise |
| **MITRE ATT&CK** | T1110 / T1110.001 (Brute Force / Password Guessing) |

> **Exercise scope:** This investigation was conducted in a controlled home lab using infrastructure owned by the analyst. The activity targeted a dedicated test account on a Windows 11 endpoint. No production systems, real user accounts, or third-party networks were involved. The report follows a standard incident investigation format to document the detection, analysis, and response process.

---

## 1. Executive Summary

On October 27, 2026, a series of failed authentication attempts targeted a local Windows account named `Anissa`. Six failed logon events were recorded within approximately five seconds, originating from the local machine (`::1`).

The account lockout policy was triggered after the configured threshold was reached, preventing further password attempts. No successful authentication was identified during the investigation, and no compromise occurred.

The activity was identified using a custom PowerShell correlation script developed after the initial Hayabusa analysis did not produce a consolidated brute-force alert. The detection logic grouped failed logon events by target account within a defined time window and checked for a corresponding account lockout event.

The same attack scenario was subsequently replayed with the endpoint connected to Wazuh. During this separate test, Wazuh generated a real-time alert using its built-in correlation rule for multiple Windows logon failures.

The investigation also identified an account security configuration weakness during the initial assessment: no account lockout threshold had been configured before remediation.

---

## 2. Timeline of Events

All timestamps are recorded in America/Toronto local time. UTC equivalents are retained in the raw evidence.

| Time (local) | Event ID | Description |
|---|---|---|
| 15:14:10 | 4720 | Local test account `Anissa` created |
| 15:21:12 | 4625 | Failed logon #1 — incorrect password (`0xC000006A`) |
| 15:21:13 | 4625 | Failed logon #2 |
| 15:21:14 | 4625 | Failed logon #3 |
| 15:21:15 | 4625 | Failed logon #4 |
| 15:21:16 | 4740 | **Account `Anissa` locked out** |
| 15:21:16 | 4625 | Failed logon #5 — account locked (`0xC0000234`) |
| 15:21:17 | 4625 | Failed logon #6 — account locked (`0xC0000234`) |

### Timeline analysis

The sequence shows repeated authentication failures against the same account within a short period.

The failure status changed from `0xC000006A` (incorrect password) to `0xC0000234` (account locked out). This is consistent with the account lockout policy being triggered during the sequence.

Event ID 4740 provides additional confirmation that Windows registered the account lockout.

---

## 3. Detection

### 3.1 Detection methodology

The investigation used two offline detection approaches, followed by a separate validation using the live Wazuh SIEM.

**Step 1 — Hayabusa analysis**

The exported Windows Security event log was analyzed using Hayabusa and its Sigma-based detection rules.

The scan identified events related to configuration changes and system discovery. However, it did not produce a consolidated brute-force alert for the sequence of failed logons.

The limitation was related to the correlation logic required: identifying repeated Event ID 4625 records against the same account within a specific time window.

**Step 2 — Custom PowerShell detection**

To address this gap, I developed `Detect-BruteForce.ps1`.

The script groups failed logon events by target account within a sliding time window and generates an alert when the configured threshold is reached. It also checks for Event ID 4740 to identify whether Windows subsequently locked the account.

**Step 3 — Wazuh validation**

The attack scenario was replayed separately after connecting the Windows endpoint to Wazuh.

During this replay, Wazuh recorded eight authentication failures and zero successful logons. Its built-in rule **60204 — Multiple Windows Logon Failures** (level 10) correlated the activity and mapped it to MITRE ATT&CK T1110.

Supporting evidence:

- `screenshots/09-wazuh-bruteforce-mitre.png`
- `screenshots/09b-wazuh-bruteforce-events.png`

### 3.2 Custom detection logic

The PowerShell script implements the following threshold:

> Five or more failed logon events (Event ID 4625) against the same target account within a five-minute window trigger a brute-force alert.

The script also checks for Event ID 4740 to determine whether the account was locked out during the observed activity.

### 3.3 Detection output

The original six-event test generated the following output:

```text
[!] BRUTE-FORCE DETECTED
TargetUser    : Anissa
FailedCount   : 6
FirstAttempt  : 2026-10-27 15:21:12
LastAttempt   : 2026-10-27 15:21:17
SourceIP      : ::1
LogonType     : 2
AccountLocked : True
LockoutTime   : 2026-10-27 15:21:16
MITRE ATT&CK  : T1110 / T1110.001
```

The output identified the targeted account, number of failed logons, source address, and account lockout status.

---

## 4. Evidence Collection

The investigation relied on Windows Security logs, PowerShell detection output, and network traffic captures.

| Artifact | Source | Location |
|---|---|---|
| Raw Security event log | `wevtutil epl Security` | `evidence/Security-*.evtx` (not published) |
| Failed logon event | Windows Security log (4625) | `screenshots/02-event-4625-failed-logon.png` |
| Detection output | `Detect-BruteForce.ps1` | `screenshots/05-bruteforce-detection.png` |
| Network connection activity | Wireshark | `screenshots/06-wireshark-ssh-bruteforce.png` |
| Wazuh MITRE detection | Wazuh dashboard | `screenshots/09-wazuh-bruteforce-mitre.png` |
| Wazuh authentication events | Wazuh dashboard | `screenshots/09b-wazuh-bruteforce-events.png` |

### Relevant Event ID 4625 fields

The failed logon events contained the following information:

- **Target account:** `Anissa`
- **Logon Type:** 2 — Interactive
- **Source Network Address:** `::1`
- **Initial failure status:** `0xC000006A` — Incorrect password
- **Subsequent failure status:** `0xC0000234` — Account locked out

### Source address

All authentication attempts originated from `::1`, the IPv6 loopback address.

This is consistent with the controlled lab setup, where the attack was generated locally rather than from an external machine.

In an external incident, the source address would provide an important starting point for investigating the origin of the authentication attempts. However, even an external IP address would not independently establish the identity of the person responsible.

---

## 5. Investigation and Analysis

The investigation followed a sequence of validation steps to establish what happened and determine whether the account had been compromised.

**1. Identified the suspicious activity**

The custom PowerShell script reported six failed authentication events targeting the account `Anissa` within the configured five-minute window.

**2. Validated the event records**

The Windows Security log was reviewed to confirm the presence of six Event ID 4625 records and one Event ID 4740 event.

The timestamps were consistent with the detection output.

**3. Examined the source**

All six attempts originated from `::1`. This matched the expected source address for the locally generated test activity.

**4. Checked for successful authentication**

The Security log was reviewed for Event ID 4624 associated with the target account during the investigation window.

No corresponding successful logon was identified.

**5. Verified account lockout**

Event ID 4740 confirmed that Windows registered the account lockout at approximately 15:21:16.

The account lockout policy therefore operated as intended during the test.

### Impact assessment

| Category | Finding |
|---|---|
| Target | Local test account `Anissa` |
| Attack type | Password guessing / brute force |
| Successful authentication | None identified |
| Account compromise | None |
| Data exposure | None identified |
| Defensive response | Account lockout triggered |
| Overall impact | No compromise |

### Severity assessment

The incident was classified as High for the purposes of the simulated detection scenario because repeated authentication attempts against a valid account represent a security concern.

However, the actual impact was limited: the activity originated locally, no successful authentication was identified, and the account lockout mechanism prevented further attempts.

---

## 6. Root-Cause Analysis

During the initial environment assessment, the local account policy was reviewed using:

```powershell
net accounts
```

The output showed:

```text
Lockout threshold: Never
```

This meant that repeated password attempts could continue without triggering an automatic account lockout.

The absence of this control represented a configuration weakness in the initial endpoint setup.

Before conducting the attack simulation, I applied the following account lockout settings:

| Policy | Configured value |
|---|---|
| Account lockout threshold | 5 invalid attempts |
| Account lockout duration | 15 minutes |
| Reset account lockout counter after | 15 minutes |

The subsequent simulation demonstrated that the account lockout policy was functioning as configured.

---

## 7. Containment and Remediation

The immediate response focused on confirming that the authentication attempts had not resulted in a successful login and ensuring that the test account was no longer available after the exercise.

### Actions performed

| Action | Status |
|---|---|
| Applied account lockout policy (5 / 15 / 15) | Completed — validated through Event ID 4740 |
| Reviewed authentication logs for successful logons | Completed — none identified |
| Confirmed account lockout | Completed — Event ID 4740 |
| Disabled the dedicated test account | Completed — `Disable-LocalUser Anissa` |

### Recommendations for a production environment

The following measures would help reduce exposure to similar attacks:

1. **Enforce account lockout controls:** Configure appropriate thresholds and reset periods based on the organization's authentication requirements.
2. **Strengthen password requirements:** Enforce sufficiently long, unique passwords and prevent the use of commonly compromised credentials.
3. **Implement SIEM correlation:** Configure alerts for repeated failed logons against the same account within a defined period.
4. **Correlate authentication and lockout events:** Investigate sequences involving Event ID 4625 followed by Event ID 4740.
5. **Protect internet-facing authentication services:** Use MFA, rate limiting, and appropriate access restrictions to reduce the risk of automated password guessing.

---

## 8. Lessons Learned

**Detection rules need to be validated against actual event sequences.**

The initial Hayabusa analysis identified individual events but did not generate the consolidated brute-force alert required for this scenario. The custom PowerShell script addressed this gap by correlating multiple failed logons against the same account.

**Alert triage requires examination of the underlying evidence.**

Some detections generated during the wider lab investigation were associated with legitimate administrative activity or incorrect rule matches. Reviewing the original command lines and event context helped distinguish expected behavior from suspicious activity.

**Preventive and detective controls serve different purposes.**

The Windows Security logs and Wazuh provided visibility into the authentication attempts. The account lockout policy provided the preventive control that stopped further password guessing against the account.

**Centralized monitoring improves investigation efficiency.**

The Wazuh replay demonstrated how multiple authentication failures could be grouped into a higher-level alert, reducing the need to investigate each failed logon independently.

---

## 9. False Positives and Benign Detections

During the broader Hayabusa investigation, additional detections were reviewed and classified based on their underlying event data.

| Detection | Verdict | Investigation findings |
|---|---|---|
| PUA — Active Directory Enumeration via AdFind | False positive | The rule matched `net.exe accounts`, which was used to inspect account policy settings. No AdFind binary execution or Active Directory environment was identified. |
| Suspicious Event Log Clearing / Configuration Change | Benign true positive | The event was associated with the analyst's authorized audit-policy configuration. |

These findings demonstrate why detection alerts must be investigated in context. A rule match alone does not establish malicious activity.

---

## 10. Investigation Limitations

This exercise was conducted in a controlled local environment. Consequently, several aspects of a production brute-force investigation were not represented.

- **Source attribution:** All authentication attempts originated from `::1` (localhost). No external attacker IP address was involved.
- **Network visibility:** The Wireshark capture showed repeated SSH connection attempts, but encrypted SSH traffic did not expose the authentication credentials.
- **Account scope:** The activity targeted a dedicated local test account rather than a production or domain account.
- **Detection coverage:** The custom PowerShell script and Wazuh rule were validated against the tested authentication sequence. Additional testing would be required to evaluate distributed attempts, multiple targeted accounts, and slower password-guessing activity.
- **Wazuh replay:** The eight authentication failures recorded by Wazuh came from a separate replay of the scenario and should not be confused with the original six-event investigation.

The results demonstrate that the detection and account-lockout workflow functioned in the tested environment. They do not establish effectiveness against every possible brute-force scenario.

---

## 11. Final Outcome

**Incident status: Closed.**

The investigation confirmed repeated failed authentication attempts against the dedicated test account. The configured account lockout policy was triggered, no successful authentication was identified, and the test account was disabled after the exercise.

The custom PowerShell script successfully identified the original six-event sequence. A separate replay demonstrated that Wazuh could also correlate repeated authentication failures using its built-in detection rule.

No compromise occurred during the exercise.

**Final classification:** Simulated brute-force activity — detected, contained, and investigated.
