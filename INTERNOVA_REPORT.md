# INTERNOVA CYBERSECURITY INTERNSHIP
## Project 3 — One-Page Submission Report

---

**Intern Name   :** *(Your Name)*
**Program       :** Cybersecurity Internship — InternNova
**Project No.   :** Project 3
**Project Title :** Security Log Analyzer & Suspicious Activity Detector
**Submission Date:** October 2024
**Language Used :** Python 3
**Tools Used    :** Python Standard Library (re, csv, os, sys, datetime, collections)

---

## 1. Objective

To build a beginner-level cybersecurity tool that reads security log files from an authorized training environment, detects suspicious activity such as brute-force attacks, port scanning, and unauthorized access attempts, assigns severity levels, and generates a professional CSV security report — all using Python standard libraries.

---

## 2. Features Implemented

| # | Feature | Status |
|---|---|---|
| 1 | Read and parse security log file | ✅ Done |
| 2 | Extract Timestamp, IP, Username, Event Type | ✅ Done |
| 3 | Detect repeated failed login attempts | ✅ Done |
| 4 | Detect possible brute-force activity | ✅ Done |
| 5 | Detect suspicious port scanning activity | ✅ Done |
| 6 | Count suspicious events by IP address | ✅ Done |
| 7 | Assign LOW / MEDIUM / HIGH severity | ✅ Done |
| 8 | Display detected alerts in terminal | ✅ Done |
| 9 | Generate CSV security report | ✅ Done |
| 10 | Include recommended defensive actions | ✅ Done |
| 11 | Error handling for missing/invalid log files | ✅ Done |
| 12 | Beginner-friendly comments throughout code | ✅ Done |

---

## 3. Methodology

The project follows a 6-step pipeline:

**Step 1 — Read:** The tool reads `sample_security.log` line by line using Python's built-in file I/O.

**Step 2 — Parse:** A regular expression (`re` module) extracts four fields from each line: Timestamp | Source IP | Username | Event Type.

**Step 3 — Count:** Using `collections.defaultdict`, events are grouped and counted per IP address for three categories: `LOGIN_FAILED`, `PORT_SCAN`, and `SUSPICIOUS_ACCESS`.

**Step 4 — Detect:** Counts are compared against configurable thresholds (Brute-Force: ≥5, Port Scan: ≥5, Suspicious Access: ≥3).

**Step 5 — Alert:** For each flagged IP, an alert is generated with severity (HIGH if count ≥ 2× threshold, MEDIUM if at threshold, LOW otherwise) and a recommended defensive action.

**Step 6 — Report:** Results are displayed in the terminal and exported to `security_report.csv`.

---

## 4. Detection Rules

| Threat | Trigger | Severity Scale |
|---|---|---|
| Brute-Force Attack | ≥ 5 failed logins from same IP | MEDIUM → HIGH |
| Port Scan | ≥ 5 PORT_SCAN events from same IP | MEDIUM → HIGH |
| Suspicious Access | ≥ 3 SUSPICIOUS_ACCESS events | MEDIUM → HIGH |

---

## 5. Analysis Results (Training Data)

**Log file:** `sample_security.log` — 76 events, 8 unique IPs

| IP Address | Threat Detected | Event Count | Severity |
|---|---|---|---|
| 192.168.1.10 | Brute-Force Attack | 11 | HIGH |
| 172.16.0.50 | Brute-Force Attack | 10 | HIGH |
| 192.168.1.20 | Port Scan | 11 | HIGH |
| 10.0.0.99 | Port Scan | 12 | HIGH |
| 192.168.1.30 | Suspicious Access | 7 | HIGH |
| 10.0.0.22 | Brute-Force Attack | 6 | MEDIUM |
| 192.168.1.45 | Port Scan | 6 | MEDIUM |

**Total Alerts:** 7 (HIGH: 5 | MEDIUM: 2)

---

## 6. Project Files

```
Security-Log-Analyzer/
├── log_analyzer.py        # Main Python script
├── sample_security.log    # Training log data (76 events)
├── security_report.csv    # Auto-generated CSV report
├── README.md              # Project documentation
└── requirements.txt       # Standard library — no pip install
```

---

## 7. Key Learnings

- Understanding of log file structures used in real-world SIEM tools
- Application of regular expressions for log parsing
- Threshold-based anomaly detection techniques
- Severity classification in cybersecurity (LOW / MEDIUM / HIGH)
- Defensive recommendations for common attack vectors
- Python best practices: error handling, modular functions, comments

---

## 8. Limitations & Future Improvements

**Limitations:** Works only with pipe-separated log format; no real-time monitoring; no database persistence.

**Future Improvements:** Time-window detection (e.g., 5 failures in 60 seconds), HTML report generation, Flask web dashboard, geolocation of IPs, and email alerts for HIGH-severity events.

---

## 9. Disclaimer

> This project was built entirely in an authorized training environment using synthetic log data. No real network scanning, exploitation, or attacks were performed at any stage of this project.

---

*InternNova Cybersecurity Internship | Project 3 | Python Security Tool*
