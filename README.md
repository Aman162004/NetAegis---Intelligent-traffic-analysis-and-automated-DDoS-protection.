# NetAegis---Intelligent-traffic-analysis-and-automated-DDoS-protection.

# 1. Clone repository and navigate to root folder
git clone https://github.com/Cyber-Wizard-X/NetAegis---Intelligent-traffic-analysis-and-automated-DDoS-protection.git
cd NetAegis---Intelligent-traffic-analysis-and-automated-DDoS-protection.

# Create Python virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install fastapi uvicorn requests scapy

# Initialize persistent tracking directory and JSON state file
mkdir -p config
echo '{"malicious_ips": []}' > config/alerts.json

# 2. Terminal 1: Launch Mitigation Server & Dashboard UI (Requires Root Privileges)
sudo $(which python3) mitigation/firewall.py

# Terminal 2: Launch Network Sniffer / Threat Detection Engine
source venv/bin/activate
sudo $(which python3) detection/sniffer.py

# 3. Single IP Block Test
curl -X POST http://localhost:5000/alert \
     -H "Content-Type: application/json" \
     -d '{"ip": "10.0.0.99"}'

# Multiple Sequential IP Blocks Test (Loop)
for ip in 10.0.0.101 10.0.0.102 10.0.0.103 10.0.0.104; do
  curl -X POST http://localhost:5000/alert \
       -H "Content-Type: application/json" \
       -d "{\"ip\": \"$ip\"}"
  sleep 1
done

# Check persistent state storage
cat config/alerts.json

# Fetch programmatic statistics API response
curl http://localhost:5000/api/stats


# 4. View all active Linux iptables drop rules with packet counters
sudo iptables -L INPUT -v -n

# Search specifically for blocked IPs added by NetAegis
sudo iptables -L INPUT -v -n | grep DROP

# Flush/Clear all active iptables firewall rules
sudo iptables -F INPUT

# Reset persistent alert database
echo '{"malicious_ips": []}' > config/alerts.json