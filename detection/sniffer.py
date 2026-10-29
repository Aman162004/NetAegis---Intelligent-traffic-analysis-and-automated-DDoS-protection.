import os
import time
import requests
from collections import defaultdict
from dotenv import load_dotenv
from scapy.all import sniff, IP

load_dotenv()

MITIGATION_API_URL = os.getenv("MITIGATION_API_URL", "http://127.0.0.1:5000/alert")
TELEMETRY_URL = "http://127.0.0.1:5000/telemetry"

TIME_WINDOW = 3        # 3-second evaluation window
THRESHOLD_PPS = 50     # Packets threshold per window

ip_packet_counts = defaultdict(int)
window_start_time = time.time()

def dispatch_alert(attacker_ip, count):
    payload = {"ip": attacker_ip, "pps": int(count / TIME_WINDOW)}
    try:
        print(f"[🚨 ANOMALY DETECTED] High traffic volume from IP: {attacker_ip} ({count} pkts/3s)")
        requests.post(MITIGATION_API_URL, json=payload, timeout=2)
    except Exception as e:
        print(f"[-] Alert dispatch failed: {e}")

def send_telemetry(ip, count):
    try:
        requests.post(TELEMETRY_URL, json={"ip": ip, "pps": int(count / TIME_WINDOW)}, timeout=1)
    except Exception:
        pass

def process_packet(packet):
    global window_start_time, ip_packet_counts
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_packet_counts[src_ip] += 1

    current_time = time.time()
    if current_time - window_start_time >= TIME_WINDOW:
        for ip, count in list(ip_packet_counts.items()):
            send_telemetry(ip, count)
            if count >= THRESHOLD_PPS:
                dispatch_alert(ip, count)
                
        ip_packet_counts.clear()
        window_start_time = current_time

def start_sniffer():
    print("==========================================================")
    print("🛡️ NetAegis Student 1: Real-Time Dynamic Traffic Detector")
    print("==========================================================")
    sniff(prn=process_packet, store=False, filter="ip")

if __name__ == "__main__":
    start_sniffer()