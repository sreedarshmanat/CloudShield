# CloudShield
# 🛡️ CloudShield HIDS (Host-Based Intrusion Detection System)

CloudShield is a lightweight, real-time Host-Based Intrusion Detection System designed to detect network layer anomalies, active man-in-the-middle attacks, and unauthorized network poisoning, while automatically executing defensive firewall mitigations and syncing real-time alerts to a centralized dashboard.

---

## 🚀 Key Features

1. **Multi-Vector Threat Detection:**
   - **ARP Spoofing / MitM:** Detects unsolicited ARP replies attempting to poison local routing tables.
   - **DNS Spoofing / Rebinding:** Analyzes DNS responses dynamically to catch malicious internal IP redirections.
   - **Evil Twin / Rogue AP:** Identifies unauthorized Wi-Fi beacons and rogue broadcast signatures.
2. **Automated Systems Actuator:**
   - Automatically drops attacker IPs bi-directionally using native OS firewalls (`iptables` on Linux, `netsh` on Windows, `pfctl` on macOS).
   - Non-blocking asynchronous design with a bounded queue and batch dispatcher.
3. **Real-Time Web Dashboard:**
   - Node.js/Express backend processing batch JSON alerts.
   - Instant visual indicators (Critical, High, Medium, Low severity states).

---

## 📂 Project Structure

```text
CloudShield/
├── sensor_integration.py     # Core packet sniffer & anomaly detection engine
├── actuator.py               # OS firewall integration & batch event dispatcher
├── server.js                 # Node.js backend dashboard server
├── arp_attacker.py           # Simulated ARP Spoofing attack tool
├── dns_attacker.py           # Simulated DNS Poisoning attack tool
├── eviltwin_attacker.py      # Simulated Evil Twin / Rogue AP attack tool
├── package.json              # Node dependencies configuration
└── README.md                 # Project documentation
# 🛡️ CloudShield HIDS (Host-Based Intrusion Detection System)

CloudShield is a lightweight, real-time Host-Based Intrusion Detection System designed to detect network layer anomalies, active man-in-the-middle attacks, and unauthorized network poisoning, while automatically executing defensive firewall mitigations and syncing real-time alerts to a centralized dashboard.

---

## 🚀 Key Features

1. **Multi-Vector Threat Detection:**
   - **ARP Spoofing / MitM:** Detects unsolicited ARP replies attempting to poison local routing tables.
   - **DNS Spoofing / Rebinding:** Analyzes DNS responses dynamically to catch malicious internal IP redirections.
   - **Evil Twin / Rogue AP:** Identifies unauthorized Wi-Fi beacons and rogue broadcast signatures.
2. **Automated Systems Actuator:**
   - Automatically drops attacker IPs bi-directionally using native OS firewalls (`iptables` on Linux, `netsh` on Windows, `pfctl` on macOS).
   - Non-blocking asynchronous design with a bounded queue and batch dispatcher.
3. **Real-Time Web Dashboard:**
   - Node.js/Express backend processing batch JSON alerts.
   - Instant visual indicators (Critical, High, Medium, Low severity states).

---

## 📂 Project Structure

```text
CloudShield/
├── sensor_integration.py     # Core packet sniffer & anomaly detection engine
├── actuator.py               # OS firewall integration & batch event dispatcher
├── server.js                 # Node.js backend dashboard server
├── arp_attacker.py           # Simulated ARP Spoofing attack tool
├── dns_attacker.py           # Simulated DNS Poisoning attack tool
├── eviltwin_attacker.py      # Simulated Evil Twin / Rogue AP attack tool
├── package.json              # Node dependencies configuration
└── README.md                 # Project documentation
⚙️ Setup & Installation
Prerequisites
Python 3 with Scapy (pip install scapy requests)

Node.js & npm

Root / Administrator privileges (required for packet sniffing and firewall rule manipulation)

1. Start the Dashboard Backend
Bash
sudo node server.js
2. Launch the Intrusion Detection Sensor
Bash
sudo python3 sensor_integration.py
3. Run Attack Simulations
ARP Spoofing Attack:

Bash
sudo python3 arp_attacker.py
DNS Spoofing Attack:

Bash
sudo python3 dns_attacker.py
Evil Twin Attack:

Bash
sudo python3 eviltwin_attacker.py
