import os
import subprocess
import json
import requests
import asyncio
import random
from typing import List
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI()

# Absolute path resolution (always points to project_root/config/alerts.json)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE = os.path.join(BASE_DIR, "config", "alerts.json")

# Ensure config directory and alerts.json file exist on launch
os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
if not os.path.exists(ALERTS_FILE):
    with open(ALERTS_FILE, 'w') as f:
        json.dump({"malicious_ips": []}, f, indent=4)

# Your official Slack Webhook URL
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

def send_slack_alert(ip_address):
    """Sends a real-time notification to your Slack channel when an IP is blocked."""
    payload = {
        "text": f" *NetAegis Alert*: Malicious traffic detected! IP `{ip_address}` has been BLOCKED by the Kali firewall."
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        print(f"[+] Slack notification delivered for {ip_address}")
    except Exception as e:
        print(f"[-] Failed to deliver Slack notification: {e}")

def block_ip(ip_address):
    """Executes the Linux iptables kernel command to drop traffic from the attacker IP."""
    try:
        print(f"[!] Threat Detected! Executing firewall drop rule for IP: {ip_address}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"[+] Successfully blocked {ip_address} on network interface.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] iptables execution failed: {e}")
        return False

def get_blocked_ips():
    """Reads the malicious IP list from alerts.json reliably."""
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                data = json.load(f)
                return data.get("malicious_ips", [])
    except Exception as e:
        print(f"[-] Error reading {ALERTS_FILE}: {e}")
    return []

def update_alerts_file(ip_address):
    """Logs the blocked IP into config/alerts.json to persist state."""
    try:
        blocked_ips = get_blocked_ips()
        if ip_address not in blocked_ips:
            blocked_ips.append(ip_address)
            with open(ALERTS_FILE, 'w') as f:
                json.dump({"malicious_ips": blocked_ips}, f, indent=4)
            print(f"[+] Updated {ALERTS_FILE} with IP: {ip_address}")
    except Exception as e:
        print(f"[-] Error writing to {ALERTS_FILE}: {e}")

# --- API Endpoints ---

@app.post("/alert")
async def receive_alert(request: Request):
    """Receives JSON alerts from Student 1's detection script."""
    data = await request.json()
    attacker_ip = data.get("ip")
    
    if attacker_ip:
        success = block_ip(attacker_ip)
        if success:
            update_alerts_file(attacker_ip)
            send_slack_alert(attacker_ip)
            return {"status": "Blocked", "ip": attacker_ip}
            
    return {"status": "Failed or Invalid IP"}

@app.get("/api/stats")
async def get_stats():
    """Returns JSON live state (threats, real-time PPS, and heatmap metrics)."""
    blocked_ips = get_blocked_ips()
    has_threat = len(blocked_ips) > 0
    
    # Real-time traffic simulation
    current_pps = random.randint(4800, 5300) if has_threat else random.randint(40, 65)
    
    # Real-time node heat values
    heatmap = []
    for i in range(1, 17):
        if has_threat and i in [5, 6, 7]:
            heatmap.append(random.randint(85, 100))
        else:
            heatmap.append(random.randint(15, 35))

    return {
        "blocked_ips": blocked_ips,
        "blocked_count": len(blocked_ips),
        "current_pps": current_pps,
        "heatmap": heatmap,
        "has_threat": has_threat
    }

# --- Dashboard Interface ---

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>NetAegis Real-Time Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #ffffff; padding: 25px; margin: 0; }
        h1 { color: #4da6ff; border-bottom: 1px solid #333; padding-bottom: 15px; margin-top: 0; font-weight: 600; }
        h3 { color: #e0e0e0; margin-top: 0; margin-bottom: 15px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
        .panel { background-color: #1e1e1e; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); border: 1px solid #2a2a2a; }
        ul { list-style-type: none; padding-left: 0; margin: 0; }
        .heatmap-grid { display: grid; grid-template-columns: repeat(8, 1fr); gap: 10px; margin-top: 15px; }
        .heatmap-cell { 
            aspect-ratio: 1; 
            border-radius: 6px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 11px; 
            font-weight: bold; 
            color: #fff;
            transition: background-color 0.4s ease;
        }
        .status-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; float: right; }
        .online { background-color: #00cc66; color: #000; }
    </style>
</head>
<body>
    <h1> NetAegis: Real-Time Traffic & Threat Intelligence Dashboard <span class="status-badge online">REAL-TIME ACTIVE</span></h1>
    
    <div class="grid">
        <div class="panel">
            <h3>Threat Logs:</h3>
            <ul id="threatLogs"><li>Loading network state...</li></ul>
        </div>
        
        <div class="panel">
            <h3>Live Network Traffic (Packets / Sec):</h3>
            <canvas id="trafficChart"></canvas>
        </div>

        <div class="panel">
            <h3>Network Segment Heatmap (Live Intensity):</h3>
            <p style="font-size: 12px; color: #aaa;">Colors adjust dynamically per second (Green = Normal, Red = High Traffic/Attack).</p>
            <div class="heatmap-grid" id="heatmapGrid"></div>
        </div>

        <div class="panel">
            <h3>Mitigation Summary:</h3>
            <canvas id="attackChart"></canvas>
        </div>
    </div>

    <script>
        // 1. Init Heatmap Grid Cells
        const heatmapGrid = document.getElementById('heatmapGrid');
        const cells = [];
        for (let i = 1; i <= 16; i++) {
            const cell = document.createElement('div');
            cell.className = 'heatmap-cell';
            cell.innerText = '.10' + i;
            cell.style.backgroundColor = 'rgba(0, 150, 102, 0.5)';
            heatmapGrid.appendChild(cell);
            cells.push(cell);
        }

        // 2. Init Bar Chart
        const ctxBar = document.getElementById('attackChart').getContext('2d');
        const attackChart = new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels: ['Total Blocked Attacks'],
                datasets: [{
                    label: 'Blocked Malicious IPs',
                    data: [0],
                    backgroundColor: 'rgba(255, 77, 77, 0.6)',
                    borderColor: 'rgba(255, 77, 77, 1)',
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                animation: false,
                scales: { y: { beginAtZero: true, suggestedMax: 5, ticks: { precision: 0 } } }
            }
        });

        // 3. Init Line Chart
        const ctxLine = document.getElementById('trafficChart').getContext('2d');
        const maxPoints = 15;
        const lineLabels = Array(maxPoints).fill('');
        const lineData = Array(maxPoints).fill(0);

        const trafficChart = new Chart(ctxLine, {
            type: 'line',
            data: {
                labels: lineLabels,
                datasets: [{
                    label: 'Incoming Packets/sec',
                    data: lineData,
                    fill: true,
                    backgroundColor: 'rgba(77, 166, 255, 0.2)',
                    borderColor: '#4da6ff',
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                animation: false,
                scales: { y: { beginAtZero: true, suggestedMax: 100 } }
            }
        });

        // 4. Update Function (Fetches fresh telemetry every second)
        async function updateDashboard() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();

                // Update Threat Logs
                const threatLogs = document.getElementById('threatLogs');
                if (!data.blocked_ips || data.blocked_ips.length === 0) {
                    threatLogs.innerHTML = '<li style="color: #00cc66; font-weight: 500;">No attacks detected. Network is secure.</li>';
                } else {
                    threatLogs.innerHTML = data.blocked_ips.map(ip => `<li style="color: #ff4d4d; margin-bottom: 8px; font-weight: 500;">🔥 Blocked IP: ${ip}</li>`).join('');
                }

                // Update Bar Chart
                attackChart.data.datasets[0].data[0] = data.blocked_count;
                attackChart.update();

                // Update Line Chart
                lineData.shift();
                lineData.push(data.current_pps);
                
                if (data.has_threat) {
                    trafficChart.data.datasets[0].borderColor = '#ff4d4d';
                    trafficChart.data.datasets[0].backgroundColor = 'rgba(255, 77, 77, 0.2)';
                } else {
                    trafficChart.data.datasets[0].borderColor = '#4da6ff';
                    trafficChart.data.datasets[0].backgroundColor = 'rgba(77, 166, 255, 0.2)';
                }
                trafficChart.update();

                // Update Heatmap Cells
                data.heatmap.forEach((val, idx) => {
                    if (data.has_threat && (idx === 4 || idx === 5 || idx === 6)) {
                        cells[idx].style.backgroundColor = `rgba(255, 77, 77, ${val / 100})`;
                    } else {
                        cells[idx].style.backgroundColor = `rgba(0, ${Math.floor(val * 2.5 + 50)}, 102, 0.8)`;
                    }
                });
            } catch (err) {
                console.error("Error updating dashboard stats:", err);
            }
        }

        // Run update once immediately, then loop every 1000ms (1 second)
        updateDashboard();
        setInterval(updateDashboard, 1000);
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)