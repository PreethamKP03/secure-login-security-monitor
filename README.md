# 🔐 Security Log Analyzer & Suspicious Activity Detector

> **InternNova Cybersecurity Internship – Project 3**  
> *Authorized Training Environment Only*

---

## 📌 Project Objective

The **Security Log Analyzer** is a beginner-friendly Python tool that reads security log files, parses authentication and network events, and automatically detects suspicious activity such as brute-force login attempts, port scanning, and unauthorized access. It generates a professional CSV security report with severity levels and recommended defensive actions.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Log Parsing** | Reads and parses structured security log files |
| **Brute-Force Detection** | Flags IPs with 5+ failed login attempts |
| **Port Scan Detection** | Flags IPs with 5+ PORT_SCAN events |
| **Suspicious Access Detection** | Flags IPs with 3+ SUSPICIOUS_ACCESS events |
| **Severity Assignment** | Assigns LOW / MEDIUM / HIGH severity per alert |
| **IP Aggregation** | Groups all events by source IP address |
| **CSV Report** | Exports findings to `security_report.csv` |
| **Defensive Recommendations** | Provides actionable steps for each threat type |
| **Error Handling** | Gracefully handles missing or invalid log files |
| **Beginner-Friendly** | Detailed inline comments throughout the code |

---

## 🛠 Technologies Used

- **Language:** Python 3.6+
- **Libraries:** Standard Library only — no pip installs needed
  - `re` — Regular expressions for log parsing
  - `csv` — CSV report generation
  - `os` — File existence checking
  - `sys` — Graceful error exits
  - `datetime` — Timestamp parsing
  - `collections.defaultdict` — Event aggregation

---

## 📁 Project Structure

```
Security-Log-Analyzer/
│
├── log_analyzer.py        # Main Python script
├── sample_security.log    # Realistic training log data
├── security_report.csv    # Auto-generated CSV report (after running)
├── README.md              # This file
└── requirements.txt       # Notes on dependencies (standard lib only)
```

---

## 🧠 Methodology

```
1. READ   →  Load the log file line by line
2. PARSE  →  Use regex to extract: Timestamp | IP | Username | Event
3. COUNT  →  Aggregate events per IP address per event type
4. DETECT →  Compare counts against configurable thresholds
5. ALERT  →  Generate structured alerts with severity + recommendations
6. REPORT →  Display terminal output + save CSV report
```

---

## 🔍 Detection Rules

| Threat Type | Trigger Condition | LOW | MEDIUM | HIGH |
|---|---|---|---|---|
| **Brute-Force** | ≥ 5 failed logins from same IP | 5–9 | 10–14 | ≥ 10 |
| **Port Scan** | ≥ 5 PORT_SCAN events from same IP | 5–9 | 10–14 | ≥ 10 |
| **Suspicious Access** | ≥ 3 SUSPICIOUS_ACCESS events | 3–5 | 6–8 | ≥ 6 |

> Thresholds can be adjusted in the `CONFIGURATION` section at the top of `log_analyzer.py`.

---

## ⚙️ Installation

**No installation required!** This project uses only Python's standard library.

1. Make sure Python 3.6 or above is installed:
   ```bash
   python --version
   ```

2. Clone or download this project folder.

3. Ensure `sample_security.log` is in the **same directory** as `log_analyzer.py`.

---

## 🚀 Usage

Open a terminal, navigate to the project folder, and run:

```bash
python log_analyzer.py
```

Or on Linux/macOS:

```bash
python3 log_analyzer.py
```

The tool will:
1. Read `sample_security.log`
2. Print a full analysis report in the terminal
3. Save results to `security_report.csv`

---

## 📊 Sample Output

```
==============================================================
   SECURITY LOG ANALYZER & SUSPICIOUS ACTIVITY DETECTOR
       InternNova Cybersecurity Project | Training Use Only
==============================================================

  Reading log file: sample_security.log
  74 log lines loaded successfully.
  74 events parsed.

ANALYSIS SUMMARY
------------------------------------------------------------
  Log File Analysed   : sample_security.log
  Total Events Parsed : 74
  Failed Logins       : 30
  Port Scan Events    : 30
  Suspicious Access   : 7
  Alerts Generated    : 7  (HIGH: 5 | MEDIUM: 2)
------------------------------------------------------------

SUSPICIOUS ACTIVITY ALERTS
------------------------------------------------------------

  Alert #1
  ------------------------------------------------------
  IP Address            : 192.168.1.10
  Activity              : Repeated Failed Logins
  Event Count           : 11
  Severity              : *** HIGH ***
  Threat                : Possible Brute-Force Attack
  Recommended Actions   :
    -> Block IP with firewall
    -> Enable account lockout policy
    -> Enforce MFA (Multi-Factor Authentication)

  Alert #2
  ------------------------------------------------------
  IP Address            : 10.0.0.99
  Activity              : Port Scanning Activity
  Event Count           : 12
  Severity              : *** HIGH ***
  Threat                : Possible Network Reconnaissance / Port Scan
  ...
```

---

## 📄 Log File Format

The log file must follow this pipe-separated format:

```
YYYY-MM-DD HH:MM:SS | IP_ADDRESS | USERNAME | EVENT_TYPE
```

**Example entries:**
```
2024-01-15 08:03:11 | 192.168.1.10 | root      | LOGIN_FAILED
2024-01-15 08:07:10 | 192.168.1.20 | SCANNER   | PORT_SCAN
2024-01-15 08:11:20 | 192.168.1.30 | unknown   | SUSPICIOUS_ACCESS
2024-01-15 08:06:05 | 192.168.1.5  | alice     | LOGIN_SUCCESS
```

**Supported Event Types:**
- `LOGIN_SUCCESS` — Successful authentication
- `LOGIN_FAILED` — Failed login attempt
- `PORT_SCAN` — Port scanning probe detected
- `SUSPICIOUS_ACCESS` — Unauthorized or unusual access attempt

---

## 📋 CSV Report Format

After running, `security_report.csv` will contain:

| IP Address | Activity | Event Count | Severity | Threat | Recommendation |
|---|---|---|---|---|---|
| 192.168.1.10 | Repeated Failed Logins | 11 | HIGH | Possible Brute-Force Attack | Block IP with firewall \| Enable account lockout... |
| 192.168.1.20 | Port Scanning Activity | 11 | HIGH | Possible Network Reconnaissance | Block IP immediately \| Enable IDS/IPS rules... |

---

## ⚠️ Limitations

- Designed for **training purposes only** using sample log data
- Does not process live network traffic
- Log format must follow the pipe-separated structure exactly
- No database backend — analysis results are not persisted beyond the CSV
- Timestamp-based correlation (time-window analysis) not yet implemented

---

## 🚧 Future Improvements

- [ ] Add time-window-based detection (e.g., 5 failures within 60 seconds)
- [ ] Support additional log formats (Apache, Windows Event Log, syslog)
- [ ] Add HTML report generation
- [ ] Integrate geolocation lookup for IP addresses
- [ ] Build a simple web dashboard using Flask
- [ ] Add email alerts for HIGH-severity events
- [ ] Implement whitelist/allowlist for trusted IP addresses

---

## ⚖️ Disclaimer

> This project is intended solely for **educational and training purposes** in an authorized environment. It does **not** perform any real network scanning, exploitation, or attacks. All log data used is synthetic and generated for learning purposes only. Always obtain proper authorization before analyzing any real system logs.

---

## 👤 Author

**InternNova Cybersecurity Internship Program**  
Project 3: Security Log Analyzer & Suspicious Activity Detector

---

*Made with Python | No external dependencies | Beginner-friendly*
