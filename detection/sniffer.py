import os
import time
import math
import hmac
import hashlib
import json
import requests
from collections import defaultdict
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP, ICMP

load_dotenv()

MITIGATION_API_URL = os.getenv("MITIGATION_API_URL", "http://127.0.0.1:5000/alert")
TELEMETRY_URL = "http://127.0.0.1:5000/telemetry"
HMAC_SECRET = b"netaegis_hackathon_secret_key"

TIME_WINDOW = 3  

# Persistent session to prevent socket exhaustion
session = requests.Session()

# Adaptive EWMA Baseline Counters
ewma_pps = 40.0
ewma_var = 10.0
ALPHA = 0.2

# Multi-Vector Traffic Counters
ip_packet_counts = defaultdict(int)
syn_counts = defaultdict(int)
ack_counts = defaultdict(int)
udp_counts = defaultdict(int)
icmp_counts = defaultdict(int)
slowloris_conns = defaultdict(list)

window_start_time = time.time()

def dispatch_authenticated_alert(attacker_ip: str, attack_type: str):
    """Generates HMAC-SHA256 signature and dispatches alert to Firewall engine."""
    payload_dict = {"ip": attacker_ip, "type": attack_type}
    raw_payload = json.dumps(payload_dict, separators=(',', ':')).encode('utf-8')
    
    signature = hmac.new(HMAC_SECRET, raw_payload, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-NetAegis-Signature": signature
    }
    
    try:
        print(f"[🚨 ANOMALY DETECTED] Vector: {attack_type} | IP: {attacker_ip}")
        # Short timeout to remain non-blocking during flood conditions
        session.post(MITIGATION_API_URL, data=raw_payload, headers=headers, timeout=1.0)
    except Exception:
        pass  # Suppress connection pool errors when local HTTP queue is saturated

def send_telemetry(ip: str, count: int):
    """Sends real-time traffic statistics to dashboard WebSocket engine."""
    try:
        session.post(TELEMETRY_URL, json={"ip": ip, "pps": int(count / TIME_WINDOW)}, timeout=0.5)
    except Exception:
        pass

def evaluate_adaptive_baseline(current_pps: float, src_ip: str) -> bool:
    """EWMA Adaptive Baseline Calculation (mu + 3 * sigma)."""
    global ewma_pps, ewma_var
    std_dev = math.sqrt(ewma_var)
    dynamic_threshold = ewma_pps + (3 * std_dev)
    
    if current_pps > dynamic_threshold and current_pps > 60:
        return True
    
    diff = current_pps - ewma_pps
    ewma_pps += ALPHA * diff
    ewma_var += ALPHA * (diff**2 - ewma_var)
    return False

def process_packet(packet):
    global window_start_time, ip_packet_counts, syn_counts, ack_counts, udp_counts, icmp_counts, slowloris_conns
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_packet_counts[src_ip] += 1

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == "S":
                syn_counts[src_ip] += 1
            elif flags == "A":
                ack_counts[src_ip] += 1
            # Slowloris L7 Detection
            elif flags == "PA" and b"GET" in bytes(packet[TCP].payload):  
                slowloris_conns[src_ip].append(time.time())

        elif packet.haslayer(UDP):
            udp_counts[src_ip] += 1
        elif packet.haslayer(ICMP):
            icmp_counts[src_ip] += 1

    current_time = time.time()
    
    # Process aggregation window
    if current_time - window_start_time >= TIME_WINDOW:
        alert_count = 0
        for ip, count in list(ip_packet_counts.items()):
            pps = count / TIME_WINDOW
            send_telemetry(ip, count)

            # Cap alerts per window to 10 to keep local HTTP queue clear during testing
            if syn_counts[ip] >= 1 and alert_count < 10:  
                dispatch_authenticated_alert(ip, "TCP SYN Flood (Spoofed Source Vector)")
                alert_count += 1
            elif evaluate_adaptive_baseline(pps, ip) and alert_count < 10:
                dispatch_authenticated_alert(ip, "Volumetric Flood (EWMA Anomaly)")
                alert_count += 1
            elif udp_counts[ip] > 40 and alert_count < 10:
                dispatch_authenticated_alert(ip, "UDP Amplification Flood")
                alert_count += 1
            elif icmp_counts[ip] > 20 and alert_count < 10:
                dispatch_authenticated_alert(ip, "ICMP Ping Flood")
                alert_count += 1
            elif len(slowloris_conns[ip]) > 20 and alert_count < 10:
                dispatch_authenticated_alert(ip, "Slowloris L7 Exhaustion")
                alert_count += 1

        # Clear state after evaluation
        ip_packet_counts.clear()
        syn_counts.clear()
        ack_counts.clear()
        udp_counts.clear()
        icmp_counts.clear()
        slowloris_conns.clear()
        window_start_time = current_time

def start_sniffer():
    print("==========================================================")
    print("🛡️ NetAegis Multi-Vector Sniffer (EWMA + Slowloris Active)")
    print("==========================================================")
    # Listens on loopback interface for local hping3 simulation
    sniff(prn=process_packet, store=False, filter="ip", iface="lo")

if __name__ == "__main__":
    start_sniffer()