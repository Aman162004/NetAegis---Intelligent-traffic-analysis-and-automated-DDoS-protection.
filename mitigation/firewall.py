import os
import json
import random
import asyncio
from typing import List, Dict
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests
from dotenv import load_dotenv

load_dotenv()

# Webhook correctly assigned as a string
SLACK_WEBHOOK_URL = "WEB HOOK URL HERE"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/alerts.json")

app = FastAPI(title="NetAegis Cyber Command Center")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared In-Memory State
active_connections: List[WebSocket] = []
blocked_ips: List[str] = []
live_incoming_stream: List[Dict[str, str]] = []
current_realtime_pps: int = 45
total_threat_events = 0  # Dynamic counter for mitigation

def load_alerts():
    global blocked_ips
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                data = json.load(f)
                blocked_ips = data.get("malicious_ips", [])
        except Exception:
            blocked_ips = []

def save_alerts():
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump({"malicious_ips": blocked_ips}, f, indent=2)

load_alerts()

def apply_iptables_block(ip: str):
    if ip in ["127.0.0.1", "localhost"]:
        return
    try:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    except Exception:
        pass

# Function to push notifications to your Slack channel
def send_slack_alert(ip: str):
    if not SLACK_WEBHOOK_URL:
        return
    slack_data = {
        "text": f"🚨 *NETAEGIS THREAT BLOCKED* 🚨\nMalicious DDoS activity detected from IP: `{ip}`.\nFirewall action: *AUTOMATICALLY DROPPED*."
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=slack_data, headers={'Content-Type': 'application/json'})
    except Exception as e:
        print(f"Error sending Slack alert: {e}")

@app.post("/alert")
async def receive_alert(request: Request):
    global blocked_ips, live_incoming_stream, current_realtime_pps, total_threat_events
    data = await request.json()
    ip = data.get("ip")
    
    total_threat_events += 1 # Dynamically scale threat count
    
    if ip and ip not in blocked_ips:
        blocked_ips.append(ip)
        save_alerts()
        apply_iptables_block(ip)
        
        # Trigger the Slack alert when a new IP is blocked
        send_slack_alert(ip)
        
        live_incoming_stream.insert(0, {"ip": ip, "status": "BLOCKED", "type": "DDoS Flood"})
        if len(live_incoming_stream) > 15:
            live_incoming_stream.pop()
            
        current_realtime_pps = random.randint(1500, 4500)
        return {"status": "Blocked", "ip": ip}
    return {"status": "Ignored", "ip": ip}

@app.post("/telemetry")
async def receive_telemetry(request: Request):
    global live_incoming_stream, current_realtime_pps
    data = await request.json()
    ip = data.get("ip")
    pps = data.get("pps", 40)
    
    current_realtime_pps = pps
    if ip:
        status = "BLOCKED" if ip in blocked_ips else "ALLOWED"
        live_incoming_stream.insert(0, {"ip": ip, "status": status, "type": "Traffic" if status=="ALLOWED" else "Threat"})
        if len(live_incoming_stream) > 15:
            live_incoming_stream.pop()
    return {"status": "OK"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
            pps_display = current_realtime_pps + random.randint(-50, 50) if current_realtime_pps > 100 else random.randint(35, 75)

            # DYNAMIC HEATMAP: Maps actual IPs from the stream to grid intensities
            heatmap_counts = [0] * 16
            for item in live_incoming_stream:
                try:
                    # Map the last octet of the IP to one of the 16 nodes
                    idx = int(item['ip'].split('.')[-1]) % 16
                except:
                    idx = sum(ord(c) for c in item['ip']) % 16
                heatmap_counts[idx] += 1
            
            # Convert hits to percentages
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
        <title>NETAEGIS // CYBER COMMAND</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
        <style>
            body { 
                font-family: 'Share Tech Mono', 'Courier New', monospace; 
                background-color: #030303; 
                color: #00FF41; 
                margin: 0; padding: 20px; 
                background-image: radial-gradient(circle, #051305 10%, #000000 90%);
            }
            .header { 
                display: flex; justify-content: space-between; align-items: center; 
                margin-bottom: 20px; border-bottom: 2px solid #00FF41; padding-bottom: 10px; 
                text-shadow: 0 0 10px #00FF41;
            }
            .header h1 { margin: 0; font-size: 26px; letter-spacing: 2px; }
            .header h1 span { animation: blink 1s infinite; }
            .status-badge { 
                background-color: #000; color: #00FF41; 
                padding: 6px 15px; border: 1px solid #00FF41; 
                box-shadow: 0 0 10px #00FF41; font-weight: bold;
                animation: pulse 2s infinite;
            }
            @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
            @keyframes pulse { 0% { box-shadow: 0 0 5px #00FF41; } 50% { box-shadow: 0 0 20px #00FF41; } 100% { box-shadow: 0 0 5px #00FF41; } }
            
            .grid-container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
            .card { 
                background-color: rgba(0, 10, 0, 0.8); border: 1px solid #004400; 
                border-radius: 4px; padding: 18px; 
                box-shadow: inset 0 0 15px #001100, 0 0 10px #002200;
                position: relative; overflow: hidden;
            }
            .card::before {
                content: ""; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
                background: linear-gradient(90deg, transparent, #00FF41, transparent);
            }
            .card h3 { 
                margin-top: 0; color: #00FF41; border-bottom: 1px dashed #004400; 
                padding-bottom: 8px; font-size: 16px; text-transform: uppercase; 
            }
            
            .ip-list { max-height: 180px; overflow-y: auto; list-style: none; padding: 0; margin: 0; }
            .ip-item { 
                color: #FF003C; background: rgba(255,0,60,0.1); 
                padding: 8px; margin-bottom: 6px; border-left: 3px solid #FF003C; 
                font-size: 14px; text-shadow: 0 0 5px #FF003C;
            }
            
            .heatmap-grid { display: grid; grid-template-columns: repeat(8, 1fr); gap: 6px; margin-top: 10px; }
            .cell { 
                padding: 15px 0; text-align: center; font-size: 12px; 
                color: #004400; background-color: #001100; transition: all 0.2s ease;
                border: 1px solid #003300; border-radius: 2px;
            }
            
            table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
            th, td { padding: 10px 12px; text-align: left; border-bottom: 1px dashed #004400; }
            th { color: #00FF41; text-transform: uppercase; }
            .status-allowed { color: #00FF41; }
            .status-blocked { color: #FF003C; font-weight: bold; text-shadow: 0 0 8px #FF003C; animation: flash 1s infinite; }
            @keyframes flash { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
            
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: #001100; }
            ::-webkit-scrollbar-thumb { background: #00FF41; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>>_ NETAEGIS_SYS_ROOT<span>_</span></h1>
            <span class="status-badge" id="ws-badge">SYS.DEFENSE.ACTIVE</span>
        </div>

        <div class="grid-container">
            <div class="card">
                <h3>[!] QUARANTINED THREATS</h3>
                <ul class="ip-list" id="threat-list"></ul>
            </div>
            <div class="card">
                <h3>[~] LIVE NETWORK TELEMETRY</h3>
                <canvas id="trafficChart" height="150"></canvas>
            </div>
        </div>

        <div class="grid-container">
            <div class="card">
                <h3>[*] DYNAMIC IP HEATMAP (NODE INTENSITY)</h3>
                <div class="heatmap-grid" id="heatmap"></div>
            </div>
            <div class="card">
                <h3>[#] MITIGATION ANALYTICS</h3>
                <canvas id="summaryChart" height="150"></canvas>
            </div>
        </div>

        <div class="card">
            <h3>[>>] RAW TRAFFIC STREAM LOG</h3>
            <table>
                <thead>
                    <tr>
                        <th>Source Node</th>
                        <th>Classification</th>
                        <th>Firewall Action</th>
                    </tr>
                </thead>
                <tbody id="live-stream-body">
                    <tr><td colspan="3" style="text-align:center; color:#004400;">Awaiting packet interception...</td></tr>
                </tbody>
            </table>
        </div>

        <script>
            Chart.defaults.color = '#00FF41';
            Chart.defaults.font.family = "'Share Tech Mono', 'Courier New', monospace";

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
                    datasets: [{
                        label: 'Pkts/Sec',
                        data: Array(15).fill(45),
                        borderColor: '#00FF41',
                        backgroundColor: 'rgba(0, 255, 65, 0.1)',
                        borderWidth: 2,
                        pointBackgroundColor: '#000',
                        pointBorderColor: '#00FF41',
                        fill: true,
                        tension: 0.1
                    }]
                },
                options: { responsive: true, scales: { y: { beginAtZero: true, grid: { color: '#003300' } }, x: { grid: { color: '#003300' } } }, plugins: { legend: { display: false } } }
            });

            const ctxSummary = document.getElementById('summaryChart').getContext('2d');
            const summaryChart = new Chart(ctxSummary, {
                type: 'bar',
                data: {
                    labels: ['Blocked IPs', 'Total Attack Events'],
                    datasets: [{ 
                        label: 'Metrics', 
                        data: [0, 0], 
                        backgroundColor: ['rgba(255, 0, 60, 0.8)', 'rgba(0, 255, 65, 0.8)'],
                        borderColor: ['#FF003C', '#00FF41'],
                        borderWidth: 1
                    }]
                },
                options: { responsive: true, scales: { y: { beginAtZero: true, grid: { color: '#003300' } }, x: { grid: { display: false } } }, plugins: { legend: { display: false } } }
            });

            const ws = new WebSocket(`ws://${location.host}/ws`);
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);

                // Threat Logs Update
                const threatList = document.getElementById('threat-list');
                threatList.innerHTML = data.blocked_ips.map(ip => `<li class="ip-item">ACCESS_DENIED: ${ip}</li>`).join('');

                // Traffic Chart Update
                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[0].data.push(data.current_pps);
                let isThreat = data.current_pps > 200;
                trafficChart.data.datasets[0].borderColor = isThreat ? '#FF003C' : '#00FF41';
                trafficChart.data.datasets[0].backgroundColor = isThreat ? 'rgba(255, 0, 60, 0.15)' : 'rgba(0, 255, 65, 0.1)';
                trafficChart.update();

                // Dynamic Analytics Update
                summaryChart.data.datasets[0].data[0] = data.blocked_count;
                summaryChart.data.datasets[0].data[1] = data.total_events;
                summaryChart.update();

                // Dynamic Heatmap Logic
                data.heatmap.forEach((val, idx) => {
                    const cell = document.getElementById(`cell-${idx+1}`);
                    if(val > 0) {
                        let isHigh = val > 50 || data.has_threat;
                        cell.style.backgroundColor = isHigh ? `rgba(255, 0, 60, ${val/100 + 0.2})` : `rgba(0, 255, 65, ${val/100 + 0.2})`;
                        cell.style.borderColor = isHigh ? '#FF003C' : '#00FF41';
                        cell.style.color = '#FFF';
                        cell.style.boxShadow = isHigh ? '0 0 15px #FF003C' : '0 0 10px #00FF41';
                    } else {
                        cell.style.backgroundColor = '#001100';
                        cell.style.borderColor = '#003300';
                        cell.style.color = '#004400';
                        cell.style.boxShadow = 'none';
                    }
                });

                // Live Stream Update
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