# NIPS (Network Intrusion Prevention System)

A lightweight, asynchronous, and multithreaded Network Intrusion Prevention System written in Python. It sniffs network traffic in real-time, detects malicious behaviors (like SYN Floods, Port Scans, and UDP/ICMP floods), and automatically mitigates them by injecting `iptables` rules.

## 📋 Prerequisites

To run this NIPS, you need a Linux environment (e.g., Ubuntu, Debian, Kali) because it relies heavily on Linux's `iptables` for mitigation.

- Python 3.x
- Root (`sudo`) privileges
- `iptables` installed (usually pre-installed on most Linux distributions)

### Python Dependencies
Install the required packet manipulation library:
pip install scapy

---

## How to Test This on Your Own VM (Crucial Steps)

If you have just cloned or copied this repository to your Virtual Machine, it will likely fail unless you change the network interface. **Follow these steps before running:**

### 1. Find your network interface
Open your terminal and run:
ip a

Look for your main network interface name. It might be `eth0`, `enp0s3`, `ens33`, etc.

### 2. Update `config.py`
Open `config.py` and change the `INTERFACE` variable to match the interface you found in step 1.

INTERFACE = "your_interface_name_here" # e.g., "eth0"

### 3. Adjust Thresholds (Optional for testing)
If you want to trigger the defenses easily during testing, you can lower the thresholds in `config.py`. For example, setting `"PORT_SCAN": 5` will block an IP after scanning only 5 ports.

---

## How to Run

Because this script sniffs raw network packets and modifies firewall rules, it **must** be run as root.

sudo python3 main.py

To stop the NIPS, simply press `Ctrl+C`. The script will gracefully intercept the termination signal, save all logs to `nips_alerts.json`, and **flush the iptables rules** to restore your network to its normal state.

---

## How to Simulate Attacks (Testing)

To see the NIPS in action, leave it running on your VM and use another machine (or a secondary VM) to attack it.

**1. Port Scanning:**
Use `nmap` to scan the VM:
nmap -p 1-100 <VM_IP_ADDRESS>

*Expected Result:* The NIPS will detect the scan, log the event, and block the attacker's IP.

**2. Ping Flood (ICMP):**
Send a rapid stream of pings:
sudo ping -f <VM_IP_ADDRESS>

**3. SYN Flood (Requires hping3):**
Simulate a TCP SYN Flood attack:
sudo hping3 -S --flood -V -p 80 <VM_IP_ADDRESS>

*Expected Result:* The NIPS will track the massive influx of SYN packets and trigger the `iptables` drop rule for the attacker (or trigger the Global DDoS mitigation if the global threshold is crossed).

---

## Project Structure

- `main.py`: The entry point. Handles packet sniffing via Scapy and contains the core detection logic.
- `firewall.py`: Asynchronous worker that safely interacts with `iptables` without blocking the packet sniffer.
- `logger.py`: Background thread that periodically flushes attack statistics and logs to disk.
- `state.py`: Global thread-safe variables, locks, and shared queues.
- `config.py`: Thresholds and primary configuration settings.