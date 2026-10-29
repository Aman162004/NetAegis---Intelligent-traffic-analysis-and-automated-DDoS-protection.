#!/usr/bin/env bash

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=========================================================="
echo "🛡️  NETAEGIS: AUTOMATED INTRUSION PREVENTION SYSTEM"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: NetAegis requires root privileges."
  echo "    Please run using: sudo ./start_netaegis.sh"
  exit 1
fi

PYTHON_BIN="$PROJECT_DIR/venv/bin/python"
mkdir -p "$PROJECT_DIR/config" "$PROJECT_DIR/pcap_captures"

cleanup() {
    echo ""
    echo "[!] Shutting down NetAegis background services..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[+] NetAegis system safely stopped."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

echo "[+] Starting Firewall Engine & Dashboard (Port 5000)..."
$PYTHON_BIN mitigation/firewall.py &
FIREWALL_PID=$!

sleep 3

echo "[+] Starting Multi-Vector Sniffer Engine..."
$PYTHON_BIN detection/sniffer.py &
SNIFFER_PID=$!

echo "=========================================================="
echo "🚀 SYSTEM ACTIVE AND PROTECTING LOCALHOST"
echo "👉 Dashboard URL : http://127.0.0.1:5000"
echo "👉 CERT-In API  : http://127.0.0.1:5000/api/cert-in-report"
echo "=========================================================="
echo "Press Ctrl+C to stop all background processes."

wait
