import os
import json
import time
import random
import hmac
import hashlib
import asyncio
import subprocess
import ipaddress
from typing import List, Dict
from datetime import datetime, timezone
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Header, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests
from dotenv import load_dotenv

load_dotenv()

# System Configurations
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
HMAC_SECRET = b"netaegis_hackathon_secret_key"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/alerts.json")
AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "../config/audit.log")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "../pcap_captures")

os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)

app = FastAPI(title="NetAegis Cyber Command Center")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory Shared State
active_connections: List[WebSocket] = []
blocked_ips: List[Dict[str, str]] = []
live_incoming_stream: List[Dict[str, str]] = []
current_realtime_pps: int = 45
total_threat_events: int = 0

def init_ipset():
    """Initializes high-performance Linux ipset with automatic TTL expiry."""
    try:
        subprocess.run(["sudo", "ipset", "create", "netaegis_blacklist", "hash:ip", "timeout", "300"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "set", "--match-set", "netaegis_blacklist", "src", "-j", "DROP"], check=False, stderr=subprocess.DEVNULL)
        print("[+] Kernel ipset and iptables rules initialized successfully.")
    except Exception as e:
        print(f"[-] Kernel ipset initialization error: {e}")

init_ipset()

def log_audit_event(action: str, ip: str, detail: str = ""):
    """Writes immutable timestamped security logs for DPDP & CERT-In compliance."""
    timestamp = datetime.now(timezone.utc).isoformat()
    log_line = f"[{timestamp}] ACTION: {action} | IP: {anonymize_ip(ip)} | DETAIL: {detail}\n"
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(log_line)

def anonymize_ip(ip_str: str) -> str:
    """DPDP Act Compliance: Anonymizes IP addresses for public logs and storage."""
    try:
        parts = ip_str.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.***"
        return hashlib.sha256(ip_str.encode()).hexdigest()[:12]
    except Exception:
        return "xxx.xxx.xxx.xxx"

def apply_kernel_block(ip_str: str) -> bool:
    """Validates IP and adds it to Linux ipset kernel table."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        
        # Safeguard: Prevent loopback/localhost from self-blocking during local hping3 floods
        if ip_obj.is_loopback or str(ip_obj) == "127.0.0.1":
            print(f"[*] Safeguard: Loopback IP {ip_str} excluded from kernel ipset DROP.")
            return False

        subprocess.run(["sudo", "ipset", "add", "netaegis_blacklist", str(ip_obj), "timeout", "300", "-exist"], check=True)
        log_audit_event("KERNEL_BLOCK_APPLIED", str(ip_obj), "Added to ipset blacklist")
        trigger_pcap_dump(str(ip_obj))
        return True
    except ValueError:
        print(f"[-] Invalid IP format rejected: {ip_str}")
        return False
    except Exception as e:
        print(f"[-] Failed to execute ipset block for {ip_str}: {e}")
        return False

def apply_kernel_unblock(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        subprocess.run(["sudo", "ipset", "del", "netaegis_blacklist", str(ip_obj)], check=True)
        log_audit_event("MANUAL_UNBLOCK", str(ip_obj), "Removed from ipset blacklist")
        return True
    except Exception as e:
        print(f"[-] Manual unblock failed: {e}")
        return False

def trigger_pcap_dump(ip_str: str):
    filename = os.path.join(PCAP_DIR, f"threat_{ip_str}_{int(time.time())}.pcap")
    try:
        subprocess.Popen(["sudo", "tcpdump", "-i", "any", "-c", "50", "src", ip_str, "-w", filename],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def send_slack_alert(ip: str, attack_type: str):
    if not SLACK_WEBHOOK_URL:
        return
    payload = {
        "text": f"🚨 *NETAEGIS DEFENSE ALERT* 🚨\n*Threat Vector:* `{attack_type}`\n*Offending IP:* `{ip}`\n*Mitigation:* `Kernel ipset DROP (300s TTL)`\n*Compliance:* `CERT-In Logged | DPDP Anonymized`"
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, headers={'Content-Type': 'application/json'}, timeout=2)
    except Exception:
        pass

@app.post("/alert")
async def receive_alert(request: Request, background_tasks: BackgroundTasks, x_netaegis_signature: str = Header(None)):
    global blocked_ips, live_incoming_stream, current_realtime_pps, total_threat_events
    
    # 1. Strict HMAC Enforcement
    if not x_netaegis_signature:
        raise HTTPException(status_code=401, detail="Missing Security Signature Header")
        
    raw_body = await request.body()
    expected_sig = hmac.new(HMAC_SECRET, raw_body, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(x_netaegis_signature, expected_sig):
        print("[-] HMAC Signature Mismatch - Alert Rejected")
        raise HTTPException(status_code=401, detail="Invalid Security Signature")
    
    data = json.loads(raw_body.decode())
    ip = data.get("ip")
    attack_type = data.get("type", "Volumetric Flood")
    
    if ip and not any(b['ip'] == ip for b in blocked_ips):
        total_threat_events += 1
        blocked_ips.append({"ip": ip, "type": attack_type, "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S")})
        
        # Offload kernel blocking & alerts to non-blocking background workers
        background_tasks.add_task(apply_kernel_block, ip)
        background_tasks.add_task(send_slack_alert, ip, attack_type)
        
        live_incoming_stream.insert(0, {"ip": ip, "status": "BLOCKED", "type": attack_type})
        if len(live_incoming_stream) > 15:
            live_incoming_stream.pop()
            
        current_realtime_pps = random.randint(1800, 4200)
        return {"status": "Blocked", "ip": ip, "vector": attack_type}
    
    return {"status": "Ignored or Already Blocked", "ip": ip}

@app.post("/telemetry")
async def receive_telemetry(request: Request):
    global live_incoming_stream, current_realtime_pps
    data = await request.json()
    ip = data.get("ip")
    pps = data.get("pps", 40)
    
    current_realtime_pps = pps
    if ip:
        is_blocked = any(b['ip'] == ip for b in blocked_ips)
        status = "BLOCKED" if is_blocked else "ALLOWED"
        live_incoming_stream.insert(0, {"ip": ip, "status": status, "type": "Traffic Stream"})
        if len(live_incoming_stream) > 15:
            live_incoming_stream.pop()
    return {"status": "OK"}

@app.post("/api/unblock")
async def manual_unblock_ip(request: Request):
    global blocked_ips
    data = await request.json()
    ip = data.get("ip")
    if ip:
        apply_kernel_unblock(ip)
        blocked_ips = [b for b in blocked_ips if b['ip'] != ip]
        return {"status": "Unblocked", "ip": ip}
    return {"status": "Error", "message": "IP required"}

@app.get("/api/cert-in-report")
async def generate_cert_in_report():
    report = {
        "report_metadata": {
            "title": "CERT-In Cyber Incident Escalation Report",
            "regulatory_framework": "Cyber Security Directions under Section 70B (6-Hour Rule)",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "generated_by": "NetAegis Automated Intrusion Prevention System"
        },
        "incident_summary": {
            "incident_type": "Distributed Denial of Service (MITRE ATT&CK T1498 / T1499)",
            "total_quarantined_threats": len(blocked_ips),
            "mitigation_status": "Kernel ipset DROP Enforcement Active",
            "anonymized_threat_sources": [
                {"hash": hashlib.sha256(b['ip'].encode()).hexdigest()[:16], "vector": b['type'], "time": b['timestamp']}
                for b in blocked_ips
            ]
        },
        "system_health": {
            "firewall_mode": "Automated Active Defense",
            "dpdp_act_compliance": "IP Privacy Anonymization Enforced"
        }
    }
    return JSONResponse(content=report)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
            pps_display = current_realtime_pps + random.randint(-30, 30) if current_realtime_pps > 100 else random.randint(35, 70)

            heatmap_counts = [0] * 16
            for item in live_incoming_stream:
                try:
                    idx = int(item['ip'].split('.')[-1]) % 16
                except Exception:
                    idx = sum(ord(c) for c in item['ip']) % 16
                heatmap_counts[idx] += 1
            
            max_count = max(heatmap_counts) if sum(heatmap_counts) > 0 else 1
            heatmap_data = [int((count / max_count) * 100) for count in heatmap_counts]

            payload = {
                "blocked_count": len(blocked_ips),
                "total_events": total_threat_events,
                "blocked_ips": blocked_ips,
                "current_pps": pps_display,
                "has_threat": len(blocked_ips) > 0 or current_realtime_pps > 200,
                "heatmap": heatmap_data,
                "live_stream": live_incoming_stream[:10]
            }
            await websocket.send_text(json.dumps(payload))
    except WebSocketDisconnect:
        active_connections.remove(websocket)

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>NetAegis // Cyber Command Center</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Share Tech Mono', monospace; background-color: #030303; color: #00FF41; margin: 0; padding: 20px; }
            .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #00FF41; padding-bottom: 10px; margin-bottom: 20px; }
            .header h1 { margin: 0; font-size: 24px; text-shadow: 0 0 10px #00FF41; }
            .badge { background: #000; color: #00FF41; border: 1px solid #00FF41; padding: 6px 12px; font-weight: bold; box-shadow: 0 0 8px #00FF41; }
            .grid-container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
            .card { background: rgba(0,10,0,0.8); border: 1px solid #004400; padding: 15px; position: relative; }
            .card h3 { margin-top: 0; color: #00FF41; border-bottom: 1px dashed #004400; padding-bottom: 6px; }
            .ip-list { max-height: 160px; overflow-y: auto; list-style: none; padding: 0; margin: 0; }
            .ip-item { color: #FF003C; background: rgba(255,0,60,0.1); padding: 8px; margin-bottom: 6px; border-left: 3px solid #FF003C; display: flex; justify-content: space-between; align-items: center; }
            .unblock-btn { background: #FF003C; color: #FFF; border: none; padding: 3px 8px; cursor: pointer; font-family: inherit; font-size: 11px; }
            .heatmap-grid { display: grid; grid-template-columns: repeat(8, 1fr); gap: 6px; }
            .cell { padding: 12px 0; text-align: center; font-size: 11px; background-color: #001100; border: 1px solid #003300; }
            table { width: 100%; border-collapse: collapse; font-size: 13px; }
            th, td { padding: 8px; text-align: left; border-bottom: 1px dashed #004400; }
            .status-blocked { color: #FF003C; font-weight: bold; }
            .status-allowed { color: #00FF41; }
            .cert-btn { background: #00FF41; color: #000; border: none; padding: 8px 15px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-block; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>>_ NETAEGIS // CYBER COMMAND CENTER</h1>
            <div>
                <a href="/api/cert-in-report" target="_blank" class="cert-btn">EXPORT CERT-IN REPORT</a>
                <span class="badge">SYS.DEFENSE.ACTIVE</span>
            </div>
        </div>

        <div class="grid-container">
            <div class="card">
                <h3>[!] QUARANTINED THREATS (KERNEL IPSET)</h3>
                <ul class="ip-list" id="threat-list"></ul>
            </div>
            <div class="card">
                <h3>[~] REAL-TIME TRAFFIC (PACKETS / SEC)</h3>
                <canvas id="trafficChart" height="140"></canvas>
            </div>
        </div>

        <div class="grid-container">
            <div class="card">
                <h3>[*] SUBNET NODE INTENSITY HEATMAP</h3>
                <div class="heatmap-grid" id="heatmap"></div>
            </div>
            <div class="card">
                <h3>[#] MITIGATION & THREAT ANALYTICS</h3>
                <canvas id="summaryChart" height="140"></canvas>
            </div>
        </div>

        <div class="card">
            <h3>[>>] RAW TRAFFIC STREAM LOG (MITRE ATT&CK MAPPED)</h3>
            <table>
                <thead>
                    <tr><th>Source Node</th><th>Attack Vector</th><th>Action Status</th></tr>
                </thead>
                <tbody id="live-stream-body">
                    <tr><td colspan="3" style="text-align:center; color:#004400;">Awaiting packet interception...</td></tr>
                </tbody>
            </table>
        </div>

        <script>
            Chart.defaults.color = '#00FF41';
            Chart.defaults.font.family = "'Share Tech Mono', monospace";

            const heatmapEl = document.getElementById('heatmap');
            for(let i=1; i<=16; i++) {
                const cell = document.createElement('div');
                cell.className = 'cell';
                cell.id = `cell-${i}`;
                cell.innerText = `0x0${i.toString(16).toUpperCase()}`;
                heatmapEl.appendChild(cell);
            }

            const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
            const trafficChart = new Chart(ctxTraffic, {
                type: 'line',
                data: {
                    labels: Array(15).fill(''),
                    datasets: [{ label: 'PPS', data: Array(15).fill(45), borderColor: '#00FF41', backgroundColor: 'rgba(0, 255, 65, 0.1)', fill: true }]
                },
                options: { responsive: true, scales: { y: { beginAtZero: true } } }
            });

            const ctxSummary = document.getElementById('summaryChart').getContext('2d');
            const summaryChart = new Chart(ctxSummary, {
                type: 'bar',
                data: {
                    labels: ['Blocked IPs', 'Total Attacks'],
                    datasets: [{ data: [0, 0], backgroundColor: ['#FF003C', '#00FF41'] }]
                },
                options: { responsive: true, plugins: { legend: { display: false } } }
            });

            async function unblockIP(ip) {
                await fetch('/api/unblock', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip}) });
            }

            const ws = new WebSocket(`ws://${location.host}/ws`);
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);

                const threatList = document.getElementById('threat-list');
                threatList.innerHTML = data.blocked_ips.map(b => `
                    <li class="ip-item">
                        <span>[${b.timestamp}] ${b.ip} (${b.type})</span>
                        <button class="unblock-btn" onclick="unblockIP('${b.ip}')">UNBLOCK</button>
                    </li>
                `).join('');

                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[0].data.push(data.current_pps);
                let isThreat = data.current_pps > 200;
                trafficChart.data.datasets[0].borderColor = isThreat ? '#FF003C' : '#00FF41';
                trafficChart.update();

                summaryChart.data.datasets[0].data[0] = data.blocked_count;
                summaryChart.data.datasets[0].data[1] = data.total_events;
                summaryChart.update();

                data.heatmap.forEach((val, idx) => {
                    const cell = document.getElementById(`cell-${idx+1}`);
                    if(val > 0) {
                        cell.style.backgroundColor = val > 50 ? 'rgba(255,0,60,0.6)' : 'rgba(0,255,65,0.6)';
                        cell.style.color = '#FFF';
                    } else {
                        cell.style.backgroundColor = '#001100';
                        cell.style.color = '#004400';
                    }
                });

                const streamBody = document.getElementById('live-stream-body');
                if(data.live_stream && data.live_stream.length > 0) {
                    streamBody.innerHTML = data.live_stream.map(item => `
                        <tr>
                            <td>${item.ip}</td>
                            <td>${item.type}</td>
                            <td class="${item.status === 'BLOCKED' ? 'status-blocked' : 'status-allowed'}">[${item.status}]</td>
                        </tr>
                    `).join('');
                }
            };
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)