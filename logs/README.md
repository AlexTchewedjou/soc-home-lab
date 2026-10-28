# Logs — Not Published

Raw event logs from this lab are **intentionally excluded** from this repository.

The exported `.evtx` and `.pcapng` files contain the **full activity** of a personal machine — every process, DNS lookup, logon and network connection during the capture window — so publishing them would leak the real hostname, username, installed software and other personal details.

## What is published instead
- Filtered, redacted **screenshots** of the specific events that matter (`../screenshots/`).
- The **detection logic** (`../detection-rules/`, `../scripts/`) anyone can run on their own logs.
- The **incident report** (`../incident-reports/`) summarizing findings without raw data.

## How raw logs were handled locally
- Kept in a separate `evidence/` folder outside the repository.
- Excluded from version control via `.gitignore` (`*.evtx`, `*.pcapng`, `evidence/`).
- Only events tied to the dedicated lab test account and lab time window were used.

This mirrors real SOC practice: evidence is preserved securely, while reports and detections are shared.
