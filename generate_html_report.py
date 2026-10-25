"""
============================================================
  HTML REPORT GENERATOR
  Reads security_report.csv and generates a styled HTML report
  Run: python generate_html_report.py
============================================================
"""

import csv
import os
from datetime import datetime

# ---- Configuration ----------------------------------------------------------
CSV_FILE   = "security_report.csv"
HTML_FILE  = "security_report.html"
LOG_FILE   = "sample_security.log"

# ---- Read CSV data ----------------------------------------------------------
def read_csv(filepath):
    """Read alerts from the CSV report file."""
    alerts = []
    if not os.path.exists(filepath):
        print(f"[ERROR] '{filepath}' not found. Run log_analyzer.py first.")
        return alerts
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alerts.append(row)
    return alerts

# ---- Read log stats ---------------------------------------------------------
def read_log_stats(filepath):
    """Count total events and event types from the log file."""
    stats = {"total": 0, "LOGIN_SUCCESS": 0, "LOGIN_FAILED": 0,
             "PORT_SCAN": 0, "SUSPICIOUS_ACCESS": 0}
    if not os.path.exists(filepath):
        return stats
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            stats["total"] += 1
            for event in ["LOGIN_SUCCESS", "LOGIN_FAILED", "PORT_SCAN", "SUSPICIOUS_ACCESS"]:
                if event in line:
                    stats[event] += 1
                    break
    return stats

# ---- Generate HTML ----------------------------------------------------------
def generate_html(alerts, stats):
    """Build the full HTML report as a string."""
    now       = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
    high_cnt  = sum(1 for a in alerts if a.get("Severity") == "HIGH")
    med_cnt   = sum(1 for a in alerts if a.get("Severity") == "MEDIUM")
    low_cnt   = sum(1 for a in alerts if a.get("Severity") == "LOW")

    # Build alert rows
    rows_html = ""
    for i, alert in enumerate(alerts, 1):
        sev = alert.get("Severity", "LOW")
        sev_class = {"HIGH": "sev-high", "MEDIUM": "sev-med", "LOW": "sev-low"}.get(sev, "sev-low")
        badge     = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(sev, sev)
        recs = alert.get("Recommendation", "").split(" | ")
        rec_html = "".join(f"<li>{r}</li>" for r in recs)

        rows_html += f"""
        <tr class="alert-row {sev_class}-row" data-sev="{sev}">
            <td class="num">{i}</td>
            <td><code class="ip">{alert.get('IP Address','')}</code></td>
            <td>{alert.get('Activity','')}</td>
            <td class="center"><strong>{alert.get('Event Count','')}</strong></td>
            <td class="center"><span class="badge {sev_class}">{badge}</span></td>
            <td>{alert.get('Threat','')}</td>
            <td><ul class="recs">{rec_html}</ul></td>
        </tr>
        """

    # Donut chart data (simple CSS trick)
    total_alerts = len(alerts)
    high_pct  = round((high_cnt  / total_alerts * 100) if total_alerts else 0)
    med_pct   = round((med_cnt   / total_alerts * 100) if total_alerts else 0)
    low_pct   = round((low_cnt   / total_alerts * 100) if total_alerts else 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Security Analysis Report | InternNova Project 3</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
  <style>
    /* ── Reset & Base ── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:        #0a0e1a;
      --surface:   #111827;
      --surface2:  #1a2235;
      --border:    #1e2d45;
      --text:      #e2e8f0;
      --muted:     #64748b;
      --accent:    #38bdf8;
      --red:       #f87171;
      --red-dim:   #7f1d1d;
      --yellow:    #fbbf24;
      --yellow-dim:#78350f;
      --green:     #4ade80;
      --green-dim: #14532d;
      --cyan:      #22d3ee;
    }}
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }}

    /* ── Header ── */
    header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f172a 100%);
      border-bottom: 1px solid var(--border);
      padding: 48px 40px 40px;
      position: relative;
      overflow: hidden;
    }}
    header::before {{
      content: '';
      position: absolute;
      top: -60px; right: -60px;
      width: 300px; height: 300px;
      background: radial-gradient(circle, rgba(56,189,248,0.12) 0%, transparent 70%);
      pointer-events: none;
    }}
    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
      max-width: 1200px;
      margin: 0 auto;
    }}
    .logo-area {{ display: flex; align-items: center; gap: 14px; }}
    .shield-icon {{
      width: 52px; height: 52px;
      background: linear-gradient(135deg, var(--accent), #0ea5e9);
      border-radius: 14px;
      display: flex; align-items: center; justify-content: center;
      font-size: 26px;
      box-shadow: 0 0 24px rgba(56,189,248,0.35);
    }}
    h1 {{ font-size: 1.7rem; font-weight: 800; letter-spacing: -0.5px; }}
    h1 span {{ color: var(--accent); }}
    .subtitle {{ color: var(--muted); font-size: 0.85rem; margin-top: 2px; }}
    .meta-pill {{
      display: flex; gap: 10px; flex-wrap: wrap; align-items: center;
    }}
    .pill {{
      background: rgba(56,189,248,0.1);
      border: 1px solid rgba(56,189,248,0.25);
      color: var(--accent);
      padding: 4px 14px;
      border-radius: 20px;
      font-size: 0.78rem;
      font-weight: 500;
    }}
    .pill.warning {{ background: rgba(248,113,113,0.1); border-color: rgba(248,113,113,0.3); color: var(--red); }}
    .generated {{ color: var(--muted); font-size: 0.78rem; margin-top: 6px; }}

    /* ── Layout ── */
    main {{ max-width: 1200px; margin: 0 auto; padding: 36px 40px 60px; }}

    /* ── Stat Cards ── */
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 40px;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px 20px;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }}
    .stat-card:hover {{ transform: translateY(-3px); box-shadow: 0 8px 30px rgba(0,0,0,0.3); }}
    .stat-card.red   {{ border-color: rgba(248,113,113,0.4); }}
    .stat-card.yellow{{ border-color: rgba(251,191,36,0.4);  }}
    .stat-card.green {{ border-color: rgba(74,222,128,0.4);  }}
    .stat-card.blue  {{ border-color: rgba(56,189,248,0.4);  }}
    .stat-num  {{ font-size: 2.6rem; font-weight: 800; line-height: 1; }}
    .stat-num.red    {{ color: var(--red);    }}
    .stat-num.yellow {{ color: var(--yellow); }}
    .stat-num.green  {{ color: var(--green);  }}
    .stat-num.blue   {{ color: var(--accent); }}
    .stat-label {{ color: var(--muted); font-size: 0.78rem; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500; }}

    /* ── Section Title ── */
    .section-title {{
      font-size: 1.05rem; font-weight: 700;
      color: var(--text);
      margin-bottom: 18px;
      display: flex; align-items: center; gap: 10px;
    }}
    .section-title::after {{
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }}

    /* ── Filter Bar ── */
    .filter-bar {{
      display: flex; gap: 10px; margin-bottom: 18px; flex-wrap: wrap;
    }}
    .filter-btn {{
      padding: 6px 18px;
      border-radius: 20px;
      border: 1px solid var(--border);
      background: var(--surface2);
      color: var(--muted);
      cursor: pointer;
      font-size: 0.82rem;
      font-family: 'Inter', sans-serif;
      font-weight: 500;
      transition: all 0.2s;
    }}
    .filter-btn:hover {{ color: var(--text); border-color: var(--accent); }}
    .filter-btn.active {{ background: rgba(56,189,248,0.15); border-color: var(--accent); color: var(--accent); }}
    .filter-btn.red-btn.active    {{ background: rgba(248,113,113,0.15); border-color: var(--red);    color: var(--red);    }}
    .filter-btn.yellow-btn.active {{ background: rgba(251,191,36,0.15);  border-color: var(--yellow); color: var(--yellow); }}
    .filter-btn.green-btn.active  {{ background: rgba(74,222,128,0.15);  border-color: var(--green);  color: var(--green);  }}

    /* ── Alerts Table ── */
    .table-wrap {{ overflow-x: auto; border-radius: 16px; border: 1px solid var(--border); }}
    table {{
      width: 100%; border-collapse: collapse;
      background: var(--surface);
    }}
    thead tr {{
      background: var(--surface2);
      border-bottom: 2px solid var(--border);
    }}
    th {{
      padding: 14px 16px;
      text-align: left;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      font-weight: 600;
      white-space: nowrap;
    }}
    td {{
      padding: 14px 16px;
      font-size: 0.875rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr.alert-row {{ transition: background 0.15s; }}
    tr.alert-row:hover {{ background: rgba(255,255,255,0.03); }}
    tr.sev-high-row:hover {{ background: rgba(248,113,113,0.06); }}
    tr.sev-med-row:hover  {{ background: rgba(251,191,36,0.06);  }}

    .num    {{ color: var(--muted); font-size: 0.8rem; text-align: center; width: 40px; }}
    .center {{ text-align: center; }}

    code.ip {{
      font-family: 'JetBrains Mono', monospace;
      background: rgba(56,189,248,0.1);
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 0.82rem;
      white-space: nowrap;
    }}

    .badge {{
      display: inline-block;
      padding: 3px 12px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
    }}
    .sev-high {{ background: rgba(248,113,113,0.15); color: var(--red);    border: 1px solid rgba(248,113,113,0.4); }}
    .sev-med  {{ background: rgba(251,191,36,0.15);  color: var(--yellow); border: 1px solid rgba(251,191,36,0.4);  }}
    .sev-low  {{ background: rgba(74,222,128,0.15);  color: var(--green);  border: 1px solid rgba(74,222,128,0.4);  }}

    ul.recs {{ list-style: none; padding: 0; }}
    ul.recs li {{
      font-size: 0.8rem;
      color: var(--muted);
      padding: 2px 0 2px 14px;
      position: relative;
    }}
    ul.recs li::before {{
      content: '→';
      position: absolute;
      left: 0;
      color: var(--accent);
    }}

    .hidden {{ display: none; }}

    /* ── Severity Summary Bars ── */
    .severity-summary {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      margin-bottom: 36px;
    }}
    .sev-bar-row {{ display: flex; align-items: center; gap: 14px; margin-bottom: 14px; }}
    .sev-bar-row:last-child {{ margin-bottom: 0; }}
    .sev-bar-label {{ width: 70px; font-size: 0.82rem; font-weight: 600; }}
    .sev-bar-track {{
      flex: 1; height: 10px;
      background: var(--surface2);
      border-radius: 10px;
      overflow: hidden;
    }}
    .sev-bar-fill {{
      height: 100%;
      border-radius: 10px;
      transition: width 1s ease;
    }}
    .sev-bar-count {{ width: 30px; text-align: right; font-size: 0.82rem; font-weight: 700; }}

    /* ── Footer ── */
    footer {{
      text-align: center;
      padding: 24px;
      color: var(--muted);
      font-size: 0.78rem;
      border-top: 1px solid var(--border);
      margin-top: 40px;
    }}
    footer strong {{ color: var(--accent); }}
  </style>
</head>
<body>

<!-- ═══════ HEADER ═══════ -->
<header>
  <div class="header-top">
    <div class="logo-area">
      <div class="shield-icon">🔐</div>
      <div>
        <h1>Security <span>Log Analyzer</span></h1>
        <div class="subtitle">Suspicious Activity Detection Report &nbsp;|&nbsp; InternNova Project 3</div>
      </div>
    </div>
    <div>
      <div class="meta-pill">
        <span class="pill">🐍 Python 3</span>
        <span class="pill">Training Environment</span>
        <span class="pill warning">⚠ {high_cnt} HIGH Alerts</span>
      </div>
      <div class="generated">Generated: {now}</div>
    </div>
  </div>
</header>

<!-- ═══════ MAIN ═══════ -->
<main>

  <!-- Stat Cards -->
  <div class="stats-grid">
    <div class="stat-card blue">
      <div class="stat-num blue">{stats['total']}</div>
      <div class="stat-label">Total Events</div>
    </div>
    <div class="stat-card red">
      <div class="stat-num red">{stats['LOGIN_FAILED']}</div>
      <div class="stat-label">Failed Logins</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-num yellow">{stats['PORT_SCAN']}</div>
      <div class="stat-label">Port Scans</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-num yellow">{stats['SUSPICIOUS_ACCESS']}</div>
      <div class="stat-label">Suspicious Access</div>
    </div>
    <div class="stat-card green">
      <div class="stat-num green">{stats['LOGIN_SUCCESS']}</div>
      <div class="stat-label">Successful Logins</div>
    </div>
    <div class="stat-card red">
      <div class="stat-num red">{len(alerts)}</div>
      <div class="stat-label">Total Alerts</div>
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="section-title">Severity Breakdown</div>
  <div class="severity-summary" style="margin-bottom:36px;">
    <div class="sev-bar-row">
      <div class="sev-bar-label" style="color:var(--red);">HIGH</div>
      <div class="sev-bar-track">
        <div class="sev-bar-fill" style="width:{high_pct}%;background:var(--red);"></div>
      </div>
      <div class="sev-bar-count" style="color:var(--red);">{high_cnt}</div>
    </div>
    <div class="sev-bar-row">
      <div class="sev-bar-label" style="color:var(--yellow);">MEDIUM</div>
      <div class="sev-bar-track">
        <div class="sev-bar-fill" style="width:{med_pct}%;background:var(--yellow);"></div>
      </div>
      <div class="sev-bar-count" style="color:var(--yellow);">{med_cnt}</div>
    </div>
    <div class="sev-bar-row">
      <div class="sev-bar-label" style="color:var(--green);">LOW</div>
      <div class="sev-bar-track">
        <div class="sev-bar-fill" style="width:{low_pct}%;background:var(--green);"></div>
      </div>
      <div class="sev-bar-count" style="color:var(--green);">{low_cnt}</div>
    </div>
  </div>

  <!-- Filter + Table -->
  <div class="section-title">Detected Alerts</div>

  <div class="filter-bar">
    <button class="filter-btn active"    onclick="filterAlerts('ALL',    this)">All ({len(alerts)})</button>
    <button class="filter-btn red-btn"   onclick="filterAlerts('HIGH',   this)">🔴 HIGH ({high_cnt})</button>
    <button class="filter-btn yellow-btn"onclick="filterAlerts('MEDIUM', this)">🟡 MEDIUM ({med_cnt})</button>
    <button class="filter-btn green-btn" onclick="filterAlerts('LOW',    this)">🟢 LOW ({low_cnt})</button>
  </div>

  <div class="table-wrap">
    <table id="alertsTable">
      <thead>
        <tr>
          <th>#</th>
          <th>IP Address</th>
          <th>Activity</th>
          <th class="center">Count</th>
          <th class="center">Severity</th>
          <th>Threat</th>
          <th>Recommended Actions</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

</main>

<footer>
  <strong>Security Log Analyzer</strong> &nbsp;|&nbsp;
  InternNova Cybersecurity Internship — Project 3 &nbsp;|&nbsp;
  Authorized Training Environment Only &nbsp;|&nbsp;
  Built with Python Standard Library
</footer>

<script>
  function filterAlerts(sev, btn) {{
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Show/hide rows
    document.querySelectorAll('.alert-row').forEach(row => {{
      if (sev === 'ALL' || row.dataset.sev === sev) {{
        row.classList.remove('hidden');
      }} else {{
        row.classList.add('hidden');
      }}
    }});
  }}
</script>
</body>
</html>"""
    return html

# ---- Main -------------------------------------------------------------------
def main():
    print("\n  Generating HTML security report...")
    alerts = read_csv(CSV_FILE)
    stats  = read_log_stats(LOG_FILE)

    if not alerts:
        print(f"  [!] No alerts found in '{CSV_FILE}'. Run log_analyzer.py first.\n")
        return

    html = generate_html(alerts, stats)

    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  HTML report saved  ->  {HTML_FILE}")
    print(f"  Open it in any browser to view the styled report.\n")

if __name__ == "__main__":
    main()
