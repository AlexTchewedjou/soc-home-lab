# Incident Report — Brute-Force Attack and Account Lockout

| Field | Value |
|---|---|
| **Report ID** | IR-2026-001 |
| **Date of report** | 2026-10-27 |
| **Analyst** | Alex Tchewedjou |
| **Classification** | Simulated incident (controlled lab) |
| **Severity** | High |
| **Status** | Closed — contained, no compromise |
| **MITRE ATT&CK** | T1110 / T1110.001 (Brute Force / Password Guessing) |

> **Nature of this exercise:** This incident was generated in a controlled home lab on a system the analyst owns, against a dedicated test account created for the purpose. No production systems, real user accounts, or third-party networks were involved. It is documented in the format of a real incident report to demonstrate detection and investigation methodology.

---

## 1. Executive Summary

On 2026-10-27, a burst of six failed logon attempts was directed at a single local account (`Anissa`) on a Windows 11 endpoint within approximately five seconds. The account's lockout policy triggered after the fifth attempt, locking the account and blocking any further guessing. No successful logon occurred, and no compromise resulted.

The activity was detected through a custom correlation rule built for this lab, after confirming that the standard Sigma rule set did not raise a brute-force alert for the event burst. Investigation also surfaced a configuration weakness that existed before the account lockout policy was applied.

---

## 2. Timeline of Events

All times are local (America/Toronto). UTC equivalents are recorded in the raw evidence.

| Time (local) | Event ID | Description |
|---|---|---|
| 15:14:10 | 4720 | Test account `Anissa` created |
| 15:21:12 | 4625 | Failed logon #1 — reason: unknown user name or bad password (0xC000006A) |
| 15:21:13 | 4625 | Failed logon #2 |
| 15:21:14 | 4625 | Failed logon #3 |
| 15:21:15 | 4625 | Failed logon #4 |
| 15:21:16 | 4740 | **Account `Anissa` locked out** |
| 15:21:16 | 4625 | Failed logon #5 — reason: account locked out (0xC0000234) |
| 15:21:17 | 4625 | Failed logon #6 — reason: account locked out (0xC0000234) |

The shift in failure reason — from "bad password" (attempts 1–4) to "account locked out" (attempts 5–6) — is the signature of a guessing attack colliding with a lockout threshold.

---

## 3. Detection

### 3.1 Method

Logs were collected from the Windows Security channel and analyzed in two passes:

1. **Hayabusa** (Sigma-based scanner) was run against the exported event log. It produced detections for configuration changes and discovery activity, but **did not raise a brute-force alert** for the failed-logon burst, because the default rule set does not correlate multiple 4625 events by account within a time window.
2. A **custom PowerShell correlation script** (`Detect-BruteForce.ps1`) was written to fill this gap. It groups failed logons by target account within a sliding window and alerts when the count meets a threshold.

### 3.2 Custom detection logic

> Rule: 5 or more failed logons (Event ID 4625) against the same account within a 5-minute window.

### 3.3 Detection output

```
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

---

## 4. Evidence

| Artifact | Source | Location |
|---|---|---|
| Raw Security event log | `wevtutil epl Security` | `evidence/Security-*.evtx` (not published) |
| Failed logon (4625) | Windows Security log | `screenshots/02-event-4625-failed-logon.png` |
| Detection output | `Detect-BruteForce.ps1` | `screenshots/05-bruteforce-detection.png` |
| Network connection burst | Wireshark | `screenshots/06-wireshark-ssh-bruteforce.png` |

**Key event fields (Event 4625):**
- Target account: `Anissa`
- Logon Type: 2 (interactive credential use)
- Source Network Address: `::1`
- Failure reasons: `0xC000006A` (bad password), then `0xC0000234` (locked out)

> **Note on source address:** The source is `::1` (localhost) because the attack was generated locally in a controlled environment. In a real-world incident, this field would contain the external IP address of the attacking host, which would be the primary pivot for blocking and attribution.

---

## 5. Investigation & Analysis

1. **Identified the alert** from the custom detection script: 6 failed logons against `Anissa`.
2. **Validated against raw logs:** confirmed 6 × Event 4625 and 1 × Event 4740 in the Security log, matching timestamps.
3. **Checked the source:** all attempts originated from `::1` (localhost) — consistent with the controlled lab setup.
4. **Confirmed no success:** no Event 4624 (successful logon) for `Anissa` exists in the window. The attack failed.
5. **Confirmed containment:** Event 4740 shows the account locked after 5 attempts, stopping further guessing automatically.

### Assessment

- **Impact:** None. No successful authentication; account locked before compromise.
- **Severity rationale:** Rated High because brute-force against a valid account is a serious technique, even though this instance was contained.

---

## 6. Root-Cause Finding

During setup, the endpoint's account policy was reviewed (`net accounts`) and found to have **no lockout threshold configured** (`Lockout threshold: Never`). Without a threshold, an attacker could attempt unlimited password guesses against local accounts.

This weakness was remediated before the attack simulation by applying a lockout policy (5 attempts / 15-minute lockout / 15-minute window). The simulation then confirmed the control works: the account locked as designed.

---

## 7. Containment & Remediation

| Action | Status |
|---|---|
| Account lockout policy applied (5 / 15 / 15) | ✅ Done — verified by Event 4740 |
| Confirmed no successful logon | ✅ Done |
| Test account to be disabled after exercise | ⏳ Planned |

### Recommendations (for a production environment)

1. **Enforce an account lockout policy** on all systems (threshold 5–10, with a reasonable reset window).
2. **Set a strong minimum password length** (12+ characters); the lab host had a minimum of 0.
3. **Alert on failed-logon bursts** in the SIEM using correlation logic like the custom rule, not just single-event rules.
4. **Correlate 4625 → 4740** so lockouts caused by attacks are investigated, not just cleared.
5. For internet-facing services, add **MFA** and **rate limiting / IP blocking** on repeated failures.

---

## 8. Lessons Learned

- Off-the-shelf detection rules do not cover everything. A burst of failed logons needed a **custom correlation rule** to be flagged as an attack.
- **Triage matters:** of 7 raw detections, 5 were benign-but-real (authorized lab setup) and 2 were false positives (the AdFind rule matched a legitimate `net accounts` command). Verifying command lines separated real signal from noise.
- A **detective control** (logging) and a **preventive control** (lockout policy) worked together: logging made the attack visible, and the lockout stopped it.

---

## 9. False Positives Noted During Investigation

| Alert | Verdict | Explanation |
|---|---|---|
| PUA – ActiveDirectory Enumeration via AdFind | False positive | Rule matched `net.exe accounts` (the lockout-policy command). No AdFind binary or Active Directory is present. |
| Suspicious Eventlog Clearing / Config Change | Benign true positive | Caused by the analyst's own authorized audit-policy configuration. |
