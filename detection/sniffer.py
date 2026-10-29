import os
import time
import requests
from collections import defaultdict
from dotenv import load_dotenv
from scapy.all import sniff, IP

load_dotenv()

MITIGATION_API_URL = os.getenv(
    "MITIGATION_API_URL",
    "http://localhost:5000/alert"
)

TIME_WINDOW = 5
THRESHOLD_PPS = 100

ip_packet_counts = defaultdict(int)
window_start_time = time.time()


def dispatch_alert(attacker_ip):
    payload = {"ip": attacker_ip}
    headers = {"Content-Type": "application/json"}

    try:
        print(
            f"[ANOMALY DETECTED] High traffic volume "
            f"from IP: {attacker_ip}"
        )
        response = requests.post(
            MITIGATION_API_URL,
            json=payload,
            headers=headers,
            timeout=3
        )
        if response.status_code == 200:
            print(
                f"[+] Successfully notified mitigation "
                f"engine for IP: {attacker_ip}"
            )
        else:
            print(f"[-] Mitigation API returned: {response.status_code}")
    except Exception as e:
        print(f"[-] Failed to dispatch alert: {e}")


def process_packet(packet):
    global window_start_time, ip_packet_counts

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip != "127.0.0.1":
            ip_packet_counts[src_ip] += 1

    current_time = time.time()
    if current_time - window_start_time >= TIME_WINDOW:
        for ip, count in list(ip_packet_counts.items()):
            if count >= THRESHOLD_PPS:
                print(
                    f"[!] Threat Triggered: IP {ip} sent "
                    f"{count} packets in {TIME_WINDOW}s"
                )
                dispatch_alert(ip)

        ip_packet_counts.clear()
        window_start_time = current_time


if __name__ == "__main__":
    sniff(prn=process_packet, store=False, filter="ip")
