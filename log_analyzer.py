#!/usr/bin/env python3
"""
Security Log Analyzer & Suspicious Activity Detector
InternNova Cybersecurity Internship - Project 3 (Defensive Security)

Reads Linux auth logs (SSH), firewall logs (UFW) and web-server access logs,
detects brute-force attempts, port scans and suspicious access, and writes
a dark-theme HTML security report (+ optional JSON).

Python standard library only. Use on logs you own or a training lab.

Usage:
    python log_analyzer.py --generate            # create sample logs in ./sample_logs
    python log_analyzer.py                       # analyze ./sample_logs -> security_report.html
    python log_analyzer.py --logs /var/log --out report.html --json alerts.json
"""

import argparse
import html
import json
import random
import re
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path

# ----------------------------------------------------------------------------
# 1. Log patterns (regex)
# ----------------------------------------------------------------------------
IP = r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
SYSLOG_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"

RE_SSH_FAIL = re.compile(SYSLOG_TS + r".*sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) from " + IP)
RE_SSH_OK   = re.compile(SYSLOG_TS + r".*sshd\[\d+\]: Accepted (?:password|publickey) for (?P<user>\S+) from " + IP)
RE_FIREWALL = re.compile(SYSLOG_TS + r".*\[UFW BLOCK\].*SRC=" + IP + r".*DPT=(?P<port>\d+)")
RE_WEB      = re.compile(
    r"^" + IP + r" \S+ \S+ \[(?P<ts>[^\]\s]+)[^\]]*\] \"(?P<method>[A-Z]+) (?P<path>\S+)[^\"]*\" (?P<status>\d{3})"
)

SENSITIVE_PATHS = ("/admin", "/.env", "/etc/passwd", "/wp-login", "/phpmyadmin", "/.git", "/config", "/backup")

# ----------------------------------------------------------------------------
# 2. Detection rules  (count of events from ONE source IP -> severity)
# ----------------------------------------------------------------------------
RULES = {
    "FAILED_LOGIN": {
        "activity": "Repeated Failed Logins",
        "threat":   "Possible Brute-Force Attack",
        "high": 10, "medium": 5, "low": 3,
        "actions": [
            "Block IP with firewall",
            "Enable account lockout policy",
            "Enforce MFA (Multi-Factor Authentication)",
        ],
    },
    "PORT_SCAN": {
        "activity": "Port Scanning Activity",
        "threat":   "Possible Network Reconnaissance / Port Scan",
        "high": 10, "medium": 5, "low": 3,
        "actions": [
            "Block IP immediately",
            "Enable IDS/IPS rules",
            "Review firewall ingress rules",
        ],
    },
    "SUSPICIOUS_ACCESS": {
        "activity": "Suspicious Unauthorized Access",
        "threat":   "Possible Unauthorized Access Attempt",
        "high": 5, "medium": 3, "low": 2,
        "actions": [
            "Investigate immediately",
            "Check access-control lists",
            "Review authentication logs",
            "Isolate affected systems",
        ],
    },
}
TYPE_ORDER = list(RULES)
SEV_RANK   = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Event:
    timestamp: datetime
    ip:        str
    etype:     str    # FAILED_LOGIN | SUCCESS_LOGIN | PORT_SCAN | SUSPICIOUS_ACCESS
    detail:    str


@dataclass
class Alert:
    ip:         str
    etype:      str
    activity:   str
    count:      int
    severity:   str
    threat:     str
    actions:    list
    first_seen: str
    last_seen:  str


# ----------------------------------------------------------------------------
# 3. Parsing
# ----------------------------------------------------------------------------
def parse_syslog_ts(text, year):
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line, year):
    """Return an Event for one log line, or None if the line is not interesting."""
    m = RE_SSH_FAIL.search(line)
    if m:
        return Event(parse_syslog_ts(m["ts"], year), m["ip"], "FAILED_LOGIN", f"user={m['user']}")

    m = RE_SSH_OK.search(line)
    if m:
        return Event(parse_syslog_ts(m["ts"], year), m["ip"], "SUCCESS_LOGIN", f"user={m['user']}")

    m = RE_FIREWALL.search(line)
    if m:
        return Event(parse_syslog_ts(m["ts"], year), m["ip"], "PORT_SCAN", f"dport={m['port']}")

    m = RE_WEB.search(line)
    if m:
        path, status = m["path"], int(m["status"])
        bad_path = path.lower().startswith(SENSITIVE_PATHS) or "../" in path
        if bad_path and status in (401, 403, 404):
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S")
            return Event(ts, m["ip"], "SUSPICIOUS_ACCESS", f"{m['method']} {path} -> {status}")

    return None


def load_events(log_dir):
    year   = datetime.now().year
    events = []
    files  = [p for p in Path(log_dir).rglob("*") if p.is_file() and p.suffix in (".log", ".txt", "")]
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    ev = parse_line(line.rstrip("\n"), year)
                    if ev:
                        events.append(ev)
        except OSError:
            continue
    events.sort(key=lambda e: e.timestamp)
    return events, len(files)


# ----------------------------------------------------------------------------
# 4. Detection
# ----------------------------------------------------------------------------
def severity_for(count, rule):
    if count >= rule["high"]:
        return "HIGH"
    if count >= rule["medium"]:
        return "MEDIUM"
    if count >= rule["low"]:
        return "LOW"
    return None


def detect(events):
    groups = defaultdict(list)
    for ev in events:
        if ev.etype in RULES:
            groups[(ev.etype, ev.ip)].append(ev)

    alerts = []
    for (etype, ip), evs in groups.items():
        rule = RULES[etype]
        sev  = severity_for(len(evs), rule)
        if sev:
            alerts.append(Alert(
                ip=ip, etype=etype, activity=rule["activity"], count=len(evs), severity=sev,
                threat=rule["threat"], actions=rule["actions"],
                first_seen=evs[0].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                last_seen=evs[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            ))
    alerts.sort(key=lambda a: (SEV_RANK[a.severity], TYPE_ORDER.index(a.etype), -a.count))
    return alerts


# ----------------------------------------------------------------------------
# 5. HTML report
# ----------------------------------------------------------------------------
CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0e1a;--surface:#111827;--surface2:#1a2235;--border:#1e2d45;--text:#e2e8f0;--muted:#64748b;--accent:#38bdf8;--red:#f87171;--yellow:#fbbf24;--green:#4ade80}
html{scroll-behavior:smooth}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
header{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 50%,#0f172a 100%);border-bottom:1px solid var(--border);padding:48px 40px 40px;position:relative;overflow:hidden}
header::before{content:'';position:absolute;top:-60px;right:-60px;width:300px;height:300px;background:radial-gradient(circle,rgba(56,189,248,.12) 0%,transparent 70%);pointer-events:none}
.header-top{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;max-width:1200px;margin:0 auto}
.logo-area{display:flex;align-items:center;gap:14px}
.shield-icon{width:52px;height:52px;background:linear-gradient(135deg,var(--accent),#0ea5e9);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:26px;box-shadow:0 0 24px rgba(56,189,248,.35)}
h1{font-size:1.7rem;font-weight:800;letter-spacing:-.5px}h1 span{color:var(--accent)}
.subtitle{color:var(--muted);font-size:.85rem;margin-top:2px}
.meta-pill{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.25);color:var(--accent);padding:4px 14px;border-radius:20px;font-size:.78rem;font-weight:500}
.pill.warning{background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.3);color:var(--red)}
.generated{color:var(--muted);font-size:.78rem;margin-top:6px}
main{max-width:1200px;margin:0 auto;padding:36px 40px 60px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:40px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px 20px;text-align:center;transition:transform .2s,box-shadow .2s}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 30px rgba(0,0,0,.3)}
.stat-card.red{border-color:rgba(248,113,113,.4)}.stat-card.yellow{border-color:rgba(251,191,36,.4)}.stat-card.green{border-color:rgba(74,222,128,.4)}.stat-card.blue{border-color:rgba(56,189,248,.4)}
.stat-num{font-size:2.6rem;font-weight:800;line-height:1}
.stat-num.red{color:var(--red)}.stat-num.yellow{color:var(--yellow)}.stat-num.green{color:var(--green)}.stat-num.blue{color:var(--accent)}
.stat-label{color:var(--muted);font-size:.78rem;margin-top:6px;text-transform:uppercase;letter-spacing:.05em;font-weight:500}
.section-title{font-size:1.05rem;font-weight:700;margin-bottom:18px;display:flex;align-items:center;gap:10px}
.section-title::after{content:'';flex:1;height:1px;background:var(--border)}
.severity-summary{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;margin-bottom:36px}
.sev-bar-row{display:flex;align-items:center;gap:14px;margin-bottom:14px}.sev-bar-row:last-child{margin-bottom:0}
.sev-bar-label{width:70px;font-size:.82rem;font-weight:600}
.sev-bar-track{flex:1;height:10px;background:var(--surface2);border-radius:10px;overflow:hidden}
.sev-bar-fill{height:100%;border-radius:10px;transition:width 1s ease}
.sev-bar-count{width:30px;text-align:right;font-size:.82rem;font-weight:700}
.filter-bar{display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap}
.filter-btn{padding:6px 18px;border-radius:20px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);cursor:pointer;font-size:.82rem;font-family:'Inter',sans-serif;font-weight:500;transition:all .2s}
.filter-btn:hover{color:var(--text);border-color:var(--accent)}
.filter-btn.active{background:rgba(56,189,248,.15);border-color:var(--accent);color:var(--accent)}
.filter-btn.red-btn.active{background:rgba(248,113,113,.15);border-color:var(--red);color:var(--red)}
.filter-btn.yellow-btn.active{background:rgba(251,191,36,.15);border-color:var(--yellow);color:var(--yellow)}
.filter-btn.green-btn.active{background:rgba(74,222,128,.15);border-color:var(--green);color:var(--green)}
.table-wrap{overflow-x:auto;border-radius:16px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;background:var(--surface)}
thead tr{background:var(--surface2);border-bottom:2px solid var(--border)}
th{padding:14px 16px;text-align:left;font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600;white-space:nowrap}
td{padding:14px 16px;font-size:.875rem;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr.alert-row{transition:background .15s}tr.alert-row:hover{background:rgba(255,255,255,.03)}
tr.sev-high-row:hover{background:rgba(248,113,113,.06)}tr.sev-med-row:hover{background:rgba(251,191,36,.06)}
.num{color:var(--muted);font-size:.8rem;text-align:center;width:40px}.center{text-align:center}
.when{display:block;color:var(--muted);font-size:.72rem;margin-top:2px}
code.ip{font-family:'JetBrains Mono',monospace;background:rgba(56,189,248,.1);color:var(--accent);padding:2px 8px;border-radius:6px;font-size:.82rem;white-space:nowrap}
.badge{display:inline-block;padding:3px 12px;border-radius:12px;font-size:.75rem;font-weight:700;letter-spacing:.05em}
.sev-high{background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.4)}
.sev-med{background:rgba(251,191,36,.15);color:var(--yellow);border:1px solid rgba(251,191,36,.4)}
.sev-low{background:rgba(74,222,128,.15);color:var(--green);border:1px solid rgba(74,222,128,.4)}
ul.recs{list-style:none;padding:0}
ul.recs li{font-size:.8rem;color:var(--muted);padding:2px 0 2px 14px;position:relative}
ul.recs li::before{content:'\\2192';position:absolute;left:0;color:var(--accent)}
.hidden{display:none}
.empty{padding:28px;text-align:center;color:var(--muted)}
footer{text-align:center;padding:24px;color:var(--muted);font-size:.78rem;border-top:1px solid var(--border);margin-top:40px}
footer strong{color:var(--accent)}
"""

JS = """
function filterAlerts(sev, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.alert-row').forEach(row => {
    row.classList.toggle('hidden', !(sev === 'ALL' || row.dataset.sev === sev));
  });
}
"""

SEV_CLASS = {"HIGH": "high", "MEDIUM": "med", "LOW": "low"}
SEV_COLOR = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def stat_card(color, number, label):
    return (f'<div class="stat-card {color}"><div class="stat-num {color}">{number}</div>'
            f'<div class="stat-label">{label}</div></div>')


def build_report(events, alerts, title="Security Log Analyzer"):
    esc = html.escape
    counts     = defaultdict(int)
    for ev in events:
        counts[ev.etype] += 1
    sev_counts = {s: sum(1 for a in alerts if a.severity == s) for s in SEV_RANK}
    total_alerts = len(alerts)

    cards = "".join([
        stat_card("blue",   len(events),                   "Total Events"),
        stat_card("red",    counts["FAILED_LOGIN"],         "Failed Logins"),
        stat_card("yellow", counts["PORT_SCAN"],            "Port Scans"),
        stat_card("yellow", counts["SUSPICIOUS_ACCESS"],    "Suspicious Access"),
        stat_card("green",  counts["SUCCESS_LOGIN"],        "Successful Logins"),
        stat_card("red",    total_alerts,                   "Total Alerts"),
    ])

    bars = ""
    for sev in ("HIGH", "MEDIUM", "LOW"):
        width = round(100 * sev_counts[sev] / total_alerts) if total_alerts else 0
        var   = f"var(--{SEV_COLOR[sev]})"
        bars += (f'<div class="sev-bar-row">'
                 f'<div class="sev-bar-label" style="color:{var}">{sev}</div>'
                 f'<div class="sev-bar-track"><div class="sev-bar-fill" style="width:{width}%;background:{var}"></div></div>'
                 f'<div class="sev-bar-count" style="color:{var}">{sev_counts[sev]}</div></div>')

    rows = ""
    for i, a in enumerate(alerts, 1):
        k    = SEV_CLASS[a.severity]
        recs = "".join(f"<li>{esc(x)}</li>" for x in a.actions)
        rows += (
            f'<tr class="alert-row sev-{k}-row" data-sev="{a.severity}">'
            f'<td class="num">{i}</td>'
            f'<td><code class="ip">{esc(a.ip)}</code></td>'
            f'<td>{esc(a.activity)}'
            f'<span class="when">{esc(a.first_seen)} &rarr; {esc(a.last_seen)}</span></td>'
            f'<td class="center"><strong>{a.count}</strong></td>'
            f'<td class="center"><span class="badge sev-{k}">{a.severity}</span></td>'
            f'<td>{esc(a.threat)}</td>'
            f'<td><ul class="recs">{recs}</ul></td></tr>'
        )
    if not rows:
        rows = '<tr><td colspan="7" class="empty">No suspicious activity detected.</td></tr>'

    now  = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
    warn = (f'<span class="pill warning">&#9888; {sev_counts["HIGH"]} HIGH Alerts</span>'
            if sev_counts["HIGH"] else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Security Analysis Report | InternNova Project 3</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>{CSS}</style>
</head>
<body>
<header><div class="header-top">
  <div class="logo-area"><div class="shield-icon">&#128272;</div>
    <div><h1>Security <span>Log Analyzer</span></h1>
    <div class="subtitle">Suspicious Activity Detection Report &nbsp;|&nbsp; InternNova Project 3</div></div></div>
  <div><div class="meta-pill"><span class="pill">&#128013; Python 3</span><span class="pill">Training Environment</span>{warn}</div>
  <div class="generated">Generated: {now}</div></div>
</div></header>
<main>
  <div class="stats-grid">{cards}</div>
  <div class="section-title">Severity Breakdown</div>
  <div class="severity-summary">{bars}</div>
  <div class="section-title">Detected Alerts</div>
  <div class="filter-bar">
    <button class="filter-btn active"     onclick="filterAlerts('ALL',    this)">All ({total_alerts})</button>
    <button class="filter-btn red-btn"    onclick="filterAlerts('HIGH',   this)">&#128308; HIGH ({sev_counts['HIGH']})</button>
    <button class="filter-btn yellow-btn" onclick="filterAlerts('MEDIUM', this)">&#128993; MEDIUM ({sev_counts['MEDIUM']})</button>
    <button class="filter-btn green-btn"  onclick="filterAlerts('LOW',    this)">&#128994; LOW ({sev_counts['LOW']})</button>
  </div>
  <div class="table-wrap"><table id="alertsTable">
    <thead><tr><th>#</th><th>IP Address</th><th>Activity</th><th class="center">Count</th>
    <th class="center">Severity</th><th>Threat</th><th>Recommended Actions</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</main>
<footer><strong>{esc(title)}</strong> &nbsp;|&nbsp; InternNova Cybersecurity Internship &mdash; Project 3 &nbsp;|&nbsp;
Authorized Training Environment Only &nbsp;|&nbsp; Built with Python Standard Library</footer>
<script>{JS}</script>
</body>
</html>"""


# ----------------------------------------------------------------------------
# 6. Sample log generator (fake data for a safe training lab)
# ----------------------------------------------------------------------------
def generate_sample_logs(out_dir):
    random.seed(7)
    out  = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)

    def at(minutes):
        return base + timedelta(minutes=minutes, seconds=random.randint(0, 59))

    def syslog(dt, rest):
        return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} server {rest}"

    # --- auth.log (SSH brute-force attempts) ----------------------------
    auth      = []
    fail_plan = {
        "192.168.1.10": 11,
        "172.16.0.50":  10,
        "10.0.0.22":     6,
        "203.0.113.7":   1,
        "198.51.100.4":  1,
        "192.168.1.77":  1,
    }
    users = ["admin", "root", "ubuntu", "test", "oracle", "user"]
    for ip, n in fail_plan.items():
        start = random.randint(0, 300)
        for j in range(n):
            dt = at(start + j * (1 if n > 3 else 40))
            auth.append((dt, syslog(dt,
                f"sshd[{random.randint(1000, 9999)}]: Failed password for "
                f"{random.choice(users)} from {ip} port {random.randint(30000, 60000)} ssh2")))

    for ip, user in [
        ("10.0.0.5", "alice"), ("10.0.0.6", "bob"),   ("10.0.0.7", "carol"),
        ("10.0.0.5", "alice"), ("10.0.0.8", "dave"),   ("10.0.0.6", "bob"),
        ("10.0.0.9", "eve"),   ("10.0.0.7", "carol"),  ("10.0.0.5", "alice"),
        ("10.0.0.8", "dave"),
    ]:
        dt = at(random.randint(0, 420))
        auth.append((dt, syslog(dt,
            f"sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} "
            f"from {ip} port {random.randint(30000, 60000)} ssh2")))

    auth.sort()
    (out / "auth.log").write_text("\n".join(l for _, l in auth) + "\n")

    # --- firewall.log (port scans) -------------------------------------
    fw    = []
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5900, 8080]
    for ip, n in {"192.168.1.20": 11, "10.0.0.99": 12, "192.168.1.45": 6}.items():
        start = random.randint(0, 300)
        for j, port in enumerate(random.sample(ports, n)):
            dt = base + timedelta(minutes=start, seconds=j * 2)
            fw.append((dt, syslog(dt,
                f"kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 "
                f"PROTO=TCP SPT={random.randint(30000, 60000)} DPT={port}")))
    fw.sort()
    (out / "firewall.log").write_text("\n".join(l for _, l in fw) + "\n")

    # --- access.log (web server suspicious path attempts) --------------
    web = []
    for path in ["/admin", "/.env", "/etc/passwd", "/wp-login.php",
                 "/phpmyadmin", "/admin/config", "/.git/config"]:
        dt = at(random.randint(200, 400))
        web.append((dt,
            f'192.168.1.30 - - [{dt:%d/%b/%Y:%H:%M:%S} +0000] '
            f'"GET {path} HTTP/1.1" 403 199'))
    for path in ["/", "/index.html", "/about"]:
        dt = at(random.randint(0, 400))
        web.append((dt,
            f'10.0.0.5 - - [{dt:%d/%b/%Y:%H:%M:%S} +0000] '
            f'"GET {path} HTTP/1.1" 200 1024'))
    web.sort()
    (out / "access.log").write_text("\n".join(l for _, l in web) + "\n")

    print(f"[+] Sample logs written to {out.resolve()}  (auth.log, firewall.log, access.log)")


# ----------------------------------------------------------------------------
# 7. CLI entry point
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Security Log Analyzer & Suspicious Activity Detector"
    )
    ap.add_argument("--logs",     default="sample_logs",
                    help="folder containing log files (default: sample_logs)")
    ap.add_argument("--out",      default="security_report.html",
                    help="HTML report path (default: security_report.html)")
    ap.add_argument("--json",     help="also write alerts to this JSON file")
    ap.add_argument("--generate", action="store_true",
                    help="create sample logs in --logs folder first, then analyse")
    args = ap.parse_args()

    if args.generate:
        generate_sample_logs(args.logs)

    if not Path(args.logs).is_dir():
        raise SystemExit(
            f"[!] Log folder not found: {args.logs}  "
            f"(run with --generate to create sample logs)"
        )

    print(f"[+] Reading logs from: {Path(args.logs).resolve()}")
    events, nfiles = load_events(args.logs)
    alerts         = detect(events)

    Path(args.out).write_text(build_report(events, alerts), encoding="utf-8")

    if args.json:
        Path(args.json).write_text(
            json.dumps([asdict(a) for a in alerts], indent=2), encoding="utf-8"
        )
        print(f"[+] JSON report saved: {Path(args.json).resolve()}")

    # ---- Terminal summary -----------------------------------------------
    print()
    print("=" * 62)
    print("   SECURITY LOG ANALYZER & SUSPICIOUS ACTIVITY DETECTOR")
    print("   InternNova Cybersecurity Project 3 | Training Use Only")
    print("=" * 62)
    print(f"  Files scanned   : {nfiles}")
    print(f"  Events parsed   : {len(events)}")
    print(f"  Alerts raised   : {len(alerts)}")
    print("-" * 62)

    if alerts:
        for a in alerts:
            print(f"  [{a.severity:<6}]  {a.ip:<16}  {a.activity:<32}  x{a.count}")
            print(f"           First: {a.first_seen}  |  Last: {a.last_seen}")
    else:
        print("  No suspicious activity detected above threshold levels.")

    print("-" * 62)
    print(f"[+] HTML report saved: {Path(args.out).resolve()}")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()
