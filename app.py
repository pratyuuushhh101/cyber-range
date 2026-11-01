#!/usr/bin/env python3
"""Minimal Mini Cyber Range dashboard with synthetic login-pattern demos."""

import datetime
import os
import subprocess
import sys
import threading
from flask import Flask, jsonify, render_template_string, request

from detector import IntrusionDetector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACK_LOG = os.path.join(BASE_DIR, "attack_log.txt")
DETECTION_LOG = os.path.join(BASE_DIR, "detection_log.txt")
ATTACK_SCRIPT = os.path.join(BASE_DIR, "attack_chain.py")
DETECTOR_SCRIPT = os.path.join(BASE_DIR, "detector.py")
app = Flask(__name__)
state_lock = threading.Lock()
state = {"running": False, "mode": None, "report_ready": False, "error": None}

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mini Cyber Range</title>
<style>
:root{--paper:#f5f5f2;--surface:#fff;--ink:#202522;--muted:#68716b;--line:#dfe3de;--accent:#256b5c;--warn:#995c13}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 24px 56px}header{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:24px}
h1{font-size:24px;line-height:1.2;margin:0 0 6px;font-weight:650;letter-spacing:-.02em}.sub{color:var(--muted);font-size:13px}.status{font-size:13px;border:1px solid var(--line);background:var(--surface);padding:5px 10px;border-radius:4px;white-space:nowrap}
section{background:var(--surface);border:1px solid var(--line);border-radius:6px;margin:16px 0;padding:18px 20px}h2{font-size:16px;margin:0 0 12px;font-weight:620}.hint{color:var(--muted);font-size:13px;margin:-4px 0 14px}
.output-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.output-column{min-width:0}.output-column h3{font-size:13px;font-weight:600;margin:0 0 7px;color:var(--muted)}
.controls{display:flex;gap:9px;flex-wrap:wrap}.btn{font:inherit;font-size:13px;padding:9px 13px;border:1px solid #cbd3cd;border-radius:4px;background:#fff;color:var(--ink);cursor:pointer}.btn.primary{background:var(--accent);border-color:var(--accent);color:white}.btn:hover:not(:disabled){filter:brightness(.96)}.btn:disabled{opacity:.5;cursor:wait}
.result{border-left:3px solid var(--accent);padding:10px 13px;background:#f7faf8;margin-top:14px;font-size:13px}.result strong{font-weight:650}.result small{display:block;color:var(--muted);margin-top:3px}
.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}td.time{white-space:nowrap;color:var(--muted);font-variant-numeric:tabular-nums}.tag{color:var(--accent);font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f8f6;border:1px solid var(--line);padding:12px;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;color:#303833;max-height:360px;overflow:auto;margin:0}footer{color:var(--muted);font-size:12px;padding-top:6px}
@media(max-width:700px){main{padding:22px 14px}header{gap:12px;flex-direction:column}section{padding:15px}.output-grid{grid-template-columns:1fr}}
</style></head><body><main>
<header><div><h1>Mini Cyber Range</h1><div class="sub">Local training demo · Login timing is a heuristic, not identity verification</div></div><div class="status" id="status">Idle</div></header>
<section><h2>Run a demonstration</h2><p class="hint">Login demos create event timings locally. The detector receives failures and timestamps, not the selected button name.</p>
<div class="controls"><button class="btn primary run" data-mode="chain">Run lab attack chain</button><button class="btn run" data-mode="variable">Simulate variable timing</button><button class="btn run" data-mode="rapid">Simulate rapid, regular timing</button><button class="btn" id="clear-display">Clear display</button><button class="btn" id="report-btn" disabled>Print / Save as PDF</button></div>
<div id="result" class="result" hidden></div></section>
<section><h2>Run output</h2><div class="output-grid"><div class="output-column"><h3>Simulator</h3><pre id="attack-raw">—</pre></div><div class="output-column"><h3>Detector</h3><pre id="detection-raw">—</pre></div></div></section>
<section><h2>Event timeline</h2><p class="hint">Simulator events and detector findings are separated for easier comparison.</p><div class="output-grid"><div class="output-column"><h3>Simulator events</h3><div class="tablewrap"><table><thead><tr><th>Time</th><th>Level</th><th>Event</th></tr></thead><tbody id="attack-events"><tr><td colspan="3" class="sub">No run yet.</td></tr></tbody></table></div></div><div class="output-column"><h3>Detector events</h3><div class="tablewrap"><table><thead><tr><th>Time</th><th>Level</th><th>Finding / evidence</th></tr></thead><tbody id="detection-events"><tr><td colspan="3" class="sub">No run yet.</td></tr></tbody></table></div></div></div></section>
<footer>SSH packet observations report connection timing only. SSH authentication contents are encrypted and are not inspected.</footer>
</main><script>
let timer=null, active=false;
let attackOffset=0, detectionOffset=0;
let previousAttackCount=0, previousDetectionCount=0;
const statusEl=document.getElementById('status');
function parseLine(line, component){
  const legacy=line.match(/^\[(\d{2}:\d{2}:\d{2})\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)$/);
  if(legacy)return {time:legacy[1],level:legacy[2],component:legacy[3],text:legacy[5]};
  const current=line.match(/^(\d{2}:\d{2}:\d{2})\s+(INFO|WARN|WARNING|ERROR|CRITICAL|HIGH)\s+(\S+)\s+(.*)$/);
  if(!current)return {time:'',level:'INFO',component,text:line};
  return {time:current[1],level:current[2],component:current[3],text:current[4]};
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
async function refresh(){
 const r=await fetch('/api/status'); const d=await r.json();
 document.getElementById('report-btn').disabled=!d.report_ready;
 const attackLines=(d.attack||'').split('\n').filter(Boolean);
 const detectionLines=(d.detection||'').split('\n').filter(Boolean);
 // A shorter file means a new run truncated the logs; show that run from its start.
 if(attackLines.length<previousAttackCount) attackOffset=0;
 if(detectionLines.length<previousDetectionCount) detectionOffset=0;
 previousAttackCount=attackLines.length;
 previousDetectionCount=detectionLines.length;
 const shownAttack=attackLines.slice(attackOffset);
 const shownDetection=detectionLines.slice(detectionOffset);
 document.getElementById('attack-raw').textContent=shownAttack.join('\n')||'—';
 document.getElementById('detection-raw').textContent=shownDetection.join('\n')||'—';
 function renderEvents(targetId, lines, source){
  const target=document.getElementById(targetId);
  if(!lines.length){target.innerHTML='<tr><td colspan="3" class="sub">No events yet.</td></tr>';return;}
  const entries=lines.map(x=>parseLine(x,source)).sort((a,b)=>a.time.localeCompare(b.time));
  target.innerHTML=entries.map(x=>`<tr><td class="time">${esc(x.time)}</td><td>${esc(x.level)}</td><td>${esc(x.text)}</td></tr>`).join('');
 }
 renderEvents('attack-events',shownAttack,'simulator');
 renderEvents('detection-events',shownDetection,'detector');
 if(!d.running&&active){active=false;clearInterval(timer);timer=null;document.querySelectorAll('.run').forEach(b=>b.disabled=false);statusEl.textContent='Complete';}
}
async function start(mode){if(active)return;active=true;attackOffset=0;detectionOffset=0;previousAttackCount=0;previousDetectionCount=0;document.querySelectorAll('.run').forEach(b=>b.disabled=true);document.getElementById('report-btn').disabled=true;statusEl.textContent='Running';document.getElementById('result').hidden=true;
 try{const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not start');await refresh();if(active)timer=setInterval(refresh,500);}catch(e){active=false;document.querySelectorAll('.run').forEach(b=>b.disabled=false);statusEl.textContent='Error';alert(e.message);}}
document.querySelectorAll('.run').forEach(b=>b.addEventListener('click',()=>start(b.dataset.mode)));
document.getElementById('report-btn').addEventListener('click',()=>{window.open('/report','_blank');});
document.getElementById('clear-display').addEventListener('click',()=>{
 attackOffset=previousAttackCount;
 detectionOffset=previousDetectionCount;
 document.getElementById('attack-raw').textContent='—';
 document.getElementById('detection-raw').textContent='—';
 document.getElementById('attack-events').innerHTML='<tr><td colspan="3" class="sub">Display cleared. New events will appear here.</td></tr>';
 document.getElementById('detection-events').innerHTML='<tr><td colspan="3" class="sub">Display cleared. New events will appear here.</td></tr>';
});
refresh();
</script></body></html>"""


def write_line(path, level, component, message):
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{stamp} {level:<5} {component:<28} {message}\n")


def run_worker(mode):
    detector_proc = None
    try:
        if mode == "chain" and os.geteuid() != 0:
            raise RuntimeError(
                "Packet capture needs elevated privileges. Stop Flask and start it with: sudo python3 app.py"
            )

        open(ATTACK_LOG, "w", encoding="utf-8").close()
        open(DETECTION_LOG, "w", encoding="utf-8").close()

        if mode == "chain":
            # Start passive monitoring before the chain so its first packets are observed.
            detector_proc = subprocess.Popen(
                [sys.executable, DETECTOR_SCRIPT],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            threading.Event().wait(1.0)
            if detector_proc.poll() is not None:
                detail = detector_proc.stderr.read().strip() if detector_proc.stderr else ""
                raise RuntimeError("Detector failed to start" + (f": {detail}" if detail else ". Check Scapy and the interface."))

            proc = subprocess.Popen(
                [sys.executable, ATTACK_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                write_line(ATTACK_LOG, "INFO", "attack-chain", line.strip())
            code = proc.wait()
            if code:
                raise RuntimeError(f"attack chain exited with status {code}")
        else:
            detector = IntrusionDetector()
            delays = [0.8, 2.5, 1.1, 3.0, 1.6, 2.8] if mode == "variable" else [0.35] * 7
            write_line(ATTACK_LOG, "INFO", "simulator", f"starting {mode}-timing login event stream")
            for delay in delays:
                threading.Event().wait(delay)
                detector.process_login_event("demo_user", "login_failed")
                write_line(ATTACK_LOG, "INFO", "event", "login_failed user=demo_user")
            if mode == "variable":
                detector.process_login_event("demo_user", "password_reset_requested")
                write_line(ATTACK_LOG, "INFO", "event", "password_reset_requested user=demo_user")
            write_line(ATTACK_LOG, "INFO", "simulator", "event stream complete")
    except Exception as exc:
        with state_lock:
            state["error"] = str(exc)
        write_line(ATTACK_LOG, "ERROR", "runner", str(exc))
    finally:
        if detector_proc is not None and detector_proc.poll() is None:
            detector_proc.terminate()
            try:
                detector_proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                detector_proc.kill()
                detector_proc.wait()
        with state_lock:
            state["running"] = False
            state["report_ready"] = state["error"] is None

@app.get("/")
def index():
    return render_template_string(PAGE)


@app.post("/api/run")
def api_run():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode")
    if mode not in {"chain", "variable", "rapid"}:
        return jsonify({"error": "Unknown run mode"}), 400
    with state_lock:
        if state["running"]:
            return jsonify({"error": "A run is already active"}), 409
        state.update(running=True, mode=mode, report_ready=False, error=None)
    threading.Thread(target=run_worker, args=(mode,), daemon=True).start()
    return jsonify({"status": "started"})


@app.get("/api/status")
def api_status():
    def read(path):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return ""
    with state_lock:
        running = state["running"]
        error = state["error"]
        report_ready = state["report_ready"]
        mode = state["mode"]
    return jsonify({"running": running, "error": error, "report_ready": report_ready, "mode": mode, "attack": read(ATTACK_LOG), "detection": read(DETECTION_LOG)})


@app.get("/report")
def report():
    with state_lock:
        if not state["report_ready"]:
            return "No completed operation is available to report yet.", 409
        mode = state["mode"] or "operation"
    def read_log(path):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read() or "No events recorded."
        except FileNotFoundError:
            return "No events recorded."
    report_template = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Mini Cyber Range report</title>
<style>
body{font:14px/1.5 Arial,sans-serif;color:#202522;margin:32px auto;max-width:900px;padding:0 24px}h1{font-size:22px;margin-bottom:4px}h2{font-size:16px;border-bottom:1px solid #dfe3de;padding-bottom:6px;margin-top:24px}.meta{color:#68716b;font-size:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f8f6;border:1px solid #dfe3de;padding:12px;font:11px/1.5 monospace}.no-print{margin:12px 0;padding:8px 12px}@media print{body{margin:0 auto;padding:0 8mm}.no-print{display:none}pre{break-inside:avoid}}
</style></head><body><button class="no-print" onclick="window.print()">Print / Save as PDF</button>
<h1>Mini Cyber Range — Operation Report</h1>
<div class="meta">Generated: {{ timestamp }} · Run type: {{ mode }} · Times use the Kali system timezone.</div>
<h2>Simulator output</h2><pre>{{ attack }}</pre>
<h2>Detector output</h2><pre>{{ detection }}</pre>
</body></html>"""
    return render_template_string(
        report_template,
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        mode=mode,
        attack=read_log(ATTACK_LOG),
        detection=read_log(DETECTION_LOG),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
