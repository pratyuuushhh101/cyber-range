#!/usr/bin/env python3
"""
Cyber Range Dashboard & Orchestration Server (v3)
"""

import os
import subprocess
import threading
import datetime
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

ATTACK_LOG = "/home/kali/attack_log.txt"
DETECTION_LOG = "/home/kali/detection_log.txt"

is_running = False

HTML_PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Range — Attack & Detection Platform</title>
    <style>
        :root {
            --bg-base: #0a0d14; --bg-surface: #121824; --border: #1e293b;
            --text-main: #f1f5f9; --text-muted: #94a3b8;
            --attack: #f43f5e; --attack-bg: #88133722;
            --defense: #38bdf8; --defense-bg: #0369a122;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
        body { background: var(--bg-base); color: var(--text-main); min-height: 100vh; padding: 20px; }

        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 16px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
        .header-title h1 { font-size: 22px; font-weight: 700; }
        .header-title p { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
        .badge-live { padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; background: #065f46; color: #6ee7b7; border: 1px solid #10b981; }

        .controls { display: flex; gap: 14px; align-items: center; background: var(--bg-surface); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--border); margin-bottom: 20px; }
        .btn { padding: 10px 22px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; border: none; transition: 0.2s all; display: flex; align-items: center; gap: 8px; }
        .btn-launch { background: var(--attack); color: white; }
        .btn-launch:hover:not(:disabled) { background: #e11d48; transform: translateY(-1px); }
        .btn-launch:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-report { background: #1e293b; color: var(--text-main); border: 1px solid var(--border); }
        .btn-report:hover:not(.btn-disabled) { background: #334155; }
        .btn-disabled { opacity: 0.35; cursor: not-allowed !important; pointer-events: none; }
        .status-indicator { font-size: 13px; color: var(--text-muted); margin-left: auto; }

        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .panel { background: var(--bg-surface); border-radius: 10px; border: 1px solid var(--border); display: flex; flex-direction: column; height: 480px; overflow: hidden; }
        .panel-header { padding: 12px 18px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 14px; }
        .panel-attack .panel-header { background: var(--attack-bg); color: var(--attack); }
        .panel-detection .panel-header { background: var(--defense-bg); color: var(--defense); }
        .log-box { flex: 1; padding: 14px; overflow-y: auto; font-size: 12px; line-height: 1.6; background: #090c12; font-family: monospace; white-space: pre-wrap; word-break: break-word; }
        .log-attack { color: #fecdd3; }
        .log-detection { color: #bae6fd; }

        .timeline-section { background: var(--bg-surface); border-radius: 10px; border: 1px solid var(--border); padding: 16px; margin-bottom: 20px; }
        .timeline-section h2 { font-size: 15px; margin-bottom: 12px; }
        .timeline-list { max-height: 250px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; }
        .timeline-item { display: flex; gap: 12px; font-size: 12px; padding: 8px 12px; border-radius: 6px; background: #090c12; border-left: 3px solid var(--border); }
        .timeline-item.attack { border-left-color: var(--attack); }
        .timeline-item.defense { border-left-color: var(--defense); }
        .timeline-time { color: var(--text-muted); min-width: 65px; }
        .timeline-tag { font-weight: 700; min-width: 80px; text-transform: uppercase; font-size: 11px; }
        .timeline-tag.attack { color: var(--attack); }
        .timeline-tag.defense { color: var(--defense); }
    </style>
</head>
<body>
    <header>
        <div class="header-title">
            <h1>🛡️ Two-Sided Cyber Range Platform</h1>
            <p>Automated Attack Simulation & Real-Time Traffic Detection • Target: 10.0.100.20 • Attacker: 10.0.100.10</p>
        </div>
        <span class="badge-live">● Range Active</span>
    </header>

    <div class="controls">
        <button id="launch-btn" class="btn btn-launch" onclick="launchChain()">🚀 Launch Attack Chain</button>
        <button id="report-btn" class="btn btn-report btn-disabled" onclick="openReport()">📄 View Incident Report</button>
        <span id="status-text" class="status-indicator">Ready to execute.</span>
    </div>

    <div class="grid">
        <div class="panel panel-attack">
            <div class="panel-header">
                <span>⚔️ ATTACK ENGINE (Recon → Enum → Brute Force → Shell)</span>
                <span id="attack-count" style="font-size:11px;opacity:.8;">0 events</span>
            </div>
            <div id="attack-log" class="log-box log-attack">Waiting for attack sequence...</div>
        </div>
        <div class="panel panel-detection">
            <div class="panel-header">
                <span>🛡️ DETECTION ENGINE (Scapy Packet Sniffer)</span>
                <span id="detection-count" style="font-size:11px;opacity:.8;">0 alerts</span>
            </div>
            <div id="detection-log" class="log-box log-detection">Passive sniffer idle...</div>
        </div>
    </div>

    <div class="timeline-section">
        <h2>⏱️ Unified Attack-to-Detection Timeline</h2>
        <div id="timeline" class="timeline-list">
            <div style="color:var(--text-muted);font-size:12px;">Launch an attack to see the correlated timeline.</div>
        </div>
    </div>

    <script>
        let pollingInterval = null;
        let chainRunning = false;
        let chainFinished = false;

        function openReport() {
            if (!chainFinished) return;
            window.open('/report', '_blank');
        }

        function launchChain() {
            if (chainRunning) return;
            chainRunning = true;
            chainFinished = false;

            const btn = document.getElementById('launch-btn');
            const reportBtn = document.getElementById('report-btn');
            btn.disabled = true;
            btn.innerHTML = '⏳ Executing Sequence...';
            document.getElementById('status-text').textContent = 'Attack chain running...';
            reportBtn.classList.add('btn-disabled');

            fetch('/api/launch', { method: 'POST' }).then(r => r.json()).then(() => { startPolling(); });
        }

        function startPolling() {
            if (pollingInterval) clearInterval(pollingInterval);
            pollingInterval = setInterval(updateLogs, 1000);
        }

        function updateLogs() {
            fetch('/api/status').then(r => r.json()).then(data => {
                const attackBox = document.getElementById('attack-log');
                const detectionBox = document.getElementById('detection-log');
                const timeline = document.getElementById('timeline');

                if (data.attack_text) {
                    attackBox.textContent = data.attack_text;
                    attackBox.scrollTop = attackBox.scrollHeight;
                    document.getElementById('attack-count').textContent = data.attack_lines + ' events';
                }
                if (data.detection_text) {
                    detectionBox.textContent = data.detection_text;
                    detectionBox.scrollTop = detectionBox.scrollHeight;
                    document.getElementById('detection-count').textContent = data.detection_lines + ' alerts';
                }

                if (data.timeline && data.timeline.length > 0) {
                    timeline.innerHTML = '';
                    data.timeline.forEach(item => {
                        const row = document.createElement('div');
                        row.className = 'timeline-item ' + (item.source === 'ATTACK' ? 'attack' : 'defense');
                        row.innerHTML = '<span class="timeline-time">' + item.time + '</span>'
                            + '<span class="timeline-tag ' + (item.source === 'ATTACK' ? 'attack' : 'defense') + '">[' + item.source + ']</span>'
                            + '<span>' + item.text + '</span>';
                        timeline.appendChild(row);
                    });
                    timeline.scrollTop = timeline.scrollHeight;
                }

                if (!data.is_running && data.has_run) {
                    chainRunning = false;
                    chainFinished = true;
                    document.getElementById('launch-btn').disabled = false;
                    document.getElementById('launch-btn').innerHTML = '🚀 Launch Attack Chain';
                    document.getElementById('status-text').textContent = 'Complete. Incident report ready.';
                    document.getElementById('report-btn').classList.remove('btn-disabled');
                    clearInterval(pollingInterval);
                }
            });
        }

        updateLogs();
    </script>
</body>
</html>
"""

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Incident Report — Cyber Range</title>
    <style>
        body { font-family: "Segoe UI", Arial, sans-serif; margin: 40px 50px; color: #1e293b; line-height: 1.5; font-size: 13px; }
        h1 { font-size: 22px; border-bottom: 3px solid #f43f5e; padding-bottom: 8px; margin-bottom: 6px; }
        .subtitle { color: #64748b; font-size: 12px; margin-bottom: 24px; }
        h2 { font-size: 15px; margin-top: 28px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; color: #0f172a; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        th, td { border: 1px solid #cbd5e1; padding: 6px 10px; text-align: left; font-size: 12px; }
        th { background: #f1f5f9; font-weight: 600; }
        .sev-crit { background: #fee2e2; color: #991b1b; font-weight: 700; font-size: 11px; padding: 2px 6px; border-radius: 3px; }
        .sev-high { background: #fef3c7; color: #92400e; font-weight: 700; font-size: 11px; padding: 2px 6px; border-radius: 3px; }
        .sev-info { background: #e0f2fe; color: #075985; font-weight: 700; font-size: 11px; padding: 2px 6px; border-radius: 3px; }
        .sev-warn { background: #fef9c3; color: #854d0e; font-weight: 700; font-size: 11px; padding: 2px 6px; border-radius: 3px; }
        .finding { background: #fef2f2; border-left: 3px solid #f43f5e; padding: 8px 12px; margin: 6px 0; font-size: 12px; }
        .remediation { background: #f0fdf4; border-left: 3px solid #22c55e; padding: 8px 12px; margin: 6px 0; font-size: 12px; }
        .footer { margin-top: 30px; font-size: 10px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 8px; }
        @media print { body { margin: 20px; } }
    </style>
</head>
<body>
    <h1>Post-Incident Summary Report</h1>
    <div class="subtitle">
        Generated: {{ timestamp }} | Environment: Isolated Virtual Lab (VirtualBox Internal Network)<br>
        Attacker: 10.0.100.10 (Kali Linux) | Target: 10.0.100.20 (Metasploitable2)
    </div>

    <h2>1. Executive Summary</h2>
    <table>
        <tr><th style="width:200px">Engagement Result</th><td style="color:#dc2626;font-weight:700">TARGET COMPROMISED</td></tr>
        <tr><th>Attack Stages Executed</th><td>{{ attack_lines }} logged events across 4 stages</td></tr>
        <tr><th>Defensive Alerts Raised</th><td>{{ detection_count }} alerts from passive NIDS</td></tr>
        <tr><th>Time to Detection</th><td>First alert triggered within seconds of attack initiation</td></tr>
    </table>

    <h2>2. Kill Chain Progression (MITRE ATT&CK Mapped)</h2>
    <table>
        <tr><th>Stage</th><th>MITRE ID</th><th>Technique</th><th>Tool</th><th>Result</th></tr>
        <tr><td>1. Reconnaissance</td><td>T1046</td><td>Network Service Discovery</td><td>Nmap (SYN + Version)</td><td>23 open ports identified</td></tr>
        <tr><td>2. Enumeration</td><td>T1592</td><td>Gather Host Information</td><td>HTTP/FTP/Telnet Probes</td><td>Vulnerable web apps, FTP access, backdoor found</td></tr>
        <tr><td>3. Credential Attack</td><td>T1110.001</td><td>Password Guessing</td><td>Paramiko (SSH Dict.)</td><td>Valid credential recovered</td></tr>
        <tr><td>4. Exploitation</td><td>T1059.004</td><td>Unix Shell Execution</td><td>SSH Remote Shell</td><td>Interactive shell obtained</td></tr>
        <tr><td>4. Triage</td><td>T1082</td><td>System Info Discovery</td><td>Shell Commands</td><td>OS, users, network data exfiltrated</td></tr>
    </table>

    <h2>3. Intrusion Detection Alerts</h2>
    <table>
        <tr><th style="width:70px">Time</th><th style="width:80px">Severity</th><th>Category</th><th>Details</th></tr>
        {% for a in alerts %}
        <tr>
            <td>{{ a.time }}</td>
            <td><span class="{{ a.sev_class }}">{{ a.severity }}</span></td>
            <td>{{ a.category }}</td>
            <td>{{ a.msg }}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>4. Key Findings</h2>
    <div class="finding"><strong>Critical:</strong> SSH credentials (msfadmin:msfadmin) discovered via dictionary attack — weak, default password in use.</div>
    <div class="finding"><strong>Critical:</strong> Open backdoor shell on port 1524 provides unauthenticated root access.</div>
    <div class="finding"><strong>High:</strong> FTP service running vsftpd 2.3.4 — known backdoor vulnerability (CVE-2011-2523).</div>
    <div class="finding"><strong>High:</strong> 23 network services publicly exposed, many running outdated, vulnerable versions.</div>
    <div class="finding"><strong>Medium:</strong> HTTP server exposes phpMyAdmin, Mutillidae, DVWA — all contain exploitable vulnerabilities.</div>
    <div class="finding"><strong>Info:</strong> System runs Linux kernel 2.6.24 (2008) — end-of-life, no security patches available.</div>

    <h2>5. Remediation & Hardening Recommendations</h2>
    <div class="remediation"><strong>R1 — Enforce Strong Authentication:</strong> Disable password-based SSH login. Enforce Ed25519 key-based authentication only. Set <code>PasswordAuthentication no</code> and <code>PermitRootLogin no</code> in <code>/etc/ssh/sshd_config</code>.</div>
    <div class="remediation"><strong>R2 — Deploy Brute-Force Protection:</strong> Install <code>fail2ban</code> to automatically block IPs after 5 failed SSH login attempts within 10 minutes. Configure <code>MaxStartups 3:50:10</code> in sshd_config to throttle concurrent unauthenticated connections.</div>
    <div class="remediation"><strong>R3 — Eliminate Backdoors & Unnecessary Services:</strong> Remove or disable backdoor shell (port 1524), Telnet (23), rexec/rlogin/rsh (512-514), and any service not required for production. Upgrade vsftpd to a patched version or disable FTP entirely in favor of SFTP.</div>
    <div class="remediation"><strong>R4 — Patch & Upgrade Software:</strong> Upgrade the operating system from Ubuntu 8.04 (kernel 2.6.24, EOL since 2013) to a currently supported LTS release. Update all services (Apache, MySQL, PostgreSQL, OpenSSH, ProFTPD) to current stable versions.</div>
    <div class="remediation"><strong>R5 — Network Segmentation & Firewall Rules:</strong> Implement host-based firewall (iptables/nftables) to allow only required ports. Segment the network so database services (MySQL 3306, PostgreSQL 5432) are not directly reachable from untrusted subnets.</div>
    <div class="remediation"><strong>R6 — Deploy Network Intrusion Detection:</strong> Install a production NIDS (Suricata or Snort) with updated rulesets to detect port scans, brute-force attacks, and exploit traffic in real time. Forward alerts to a centralized SIEM for correlation and incident response.</div>
    <div class="remediation"><strong>R7 — Remove Vulnerable Web Applications:</strong> Uninstall intentionally vulnerable apps (DVWA, Mutillidae, TWiki). Restrict phpMyAdmin access to localhost only or replace with CLI-only database management.</div>

    <div class="footer">
        Cyber Range Platform — Automated Penetration Test & Intrusion Detection Report<br>
        This assessment was conducted in an isolated virtual lab environment for educational purposes only.
    </div>
</body>
</html>
"""

def execute_attack_and_detection():
    global is_running
    is_running = True
    det_proc = subprocess.Popen(["sudo", "python3", "/home/kali/detector.py"])
    threading.Event().wait(2.0)
    subprocess.run(["sudo", "python3", "/home/kali/attack_chain.py"])
    threading.Event().wait(2.0)
    det_proc.terminate()
    is_running = False

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/api/launch", methods=["POST"])
def api_launch():
    global is_running
    if not is_running:
        threading.Thread(target=execute_attack_and_detection, daemon=True).start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already_running"})

@app.route("/api/status")
def api_status():
    attack_text = ""
    detection_text = ""
    timeline = []

    if os.path.exists(ATTACK_LOG):
        with open(ATTACK_LOG, "r") as f:
            attack_text = f.read()
    if os.path.exists(DETECTION_LOG):
        with open(DETECTION_LOG, "r") as f:
            detection_text = f.read()

    for line in attack_text.splitlines():
        if line.startswith("[") and "]" in line:
            timeline.append({"time": line[1:9], "source": "ATTACK", "text": line[11:]})
    for line in detection_text.splitlines():
        if line.startswith("[") and "]" in line:
            timeline.append({"time": line[1:9], "source": "DEFENSE", "text": line[11:]})
    timeline.sort(key=lambda x: x["time"])

    return jsonify({
        "is_running": is_running,
        "has_run": len(attack_text) > 0,
        "attack_text": attack_text,
        "attack_lines": len(attack_text.splitlines()),
        "detection_text": detection_text,
        "detection_lines": len(detection_text.splitlines()),
        "timeline": timeline
    })

@app.route("/report")
def report():
    attack_text = ""
    alerts = []

    if os.path.exists(ATTACK_LOG):
        with open(ATTACK_LOG, "r") as f:
            attack_text = f.read()

    if os.path.exists(DETECTION_LOG):
        with open(DETECTION_LOG, "r") as f:
            for line in f.read().splitlines():
                if not line.startswith("["):
                    continue
                parts = line.split("] [")
                if len(parts) >= 4:
                    time_str = parts[0].strip("[")
                    sev = parts[1]
                    cat = parts[2]
                    msg = "] [".join(parts[3:]).rstrip("]")
                    sev_map = {"CRITICAL": "sev-crit", "HIGH": "sev-high", "WARNING": "sev-warn"}
                    alerts.append({
                        "time": time_str, "severity": sev,
                        "sev_class": sev_map.get(sev, "sev-info"),
                        "category": cat, "msg": msg
                    })

    return render_template_string(
        REPORT_TEMPLATE,
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        attack_lines=len(attack_text.splitlines()),
        detection_count=len(alerts),
        alerts=alerts
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

