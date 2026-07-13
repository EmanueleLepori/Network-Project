# Entry point, packet sniffing, and core mitigation logic
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
import subprocess
import time
import signal
import sys
import json
from datetime import datetime

import config
import state
from firewall import start_firewall_worker, update_stats_from_iptables
from logger import start_log_worker

def cleanup_and_exit(sig, frame):
    # Graceful shutdown handler triggered by Ctrl+C (SIGINT)
    print("\n\n[*] Closing the firewall...")
    
    with state.log_lock:
        if state.ongoing_attacks:
            # Do one final fetch of iptables stats before wiping the rules
            update_stats_from_iptables()
            try:
                with open(config.LOG_FILE, "w") as f:
                    json.dump(state.storico_log, f, indent=4)
            except Exception as e:
                print(f"[-] Error while saving into the log file: {e}")
                
    print("[*] Removing all rules inside iptables (Flush PREROUTING)...")
    # Flush (-F) the raw PREROUTING chain to restore normal network traffic
    subprocess.run(["iptables", "-t", "raw", "-F", "PREROUTING"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Network reset. Quitting")
    sys.exit(0)

def block_ip(ip, reason, stats, packet):
    # Process an individual attacker, extract forensics, and dispatch a block command
    if ip not in state.blocked_ips:
        print(f"\n\n[!] INTRUSION DETECTED: {reason}")
        print(f"[*] Attacker: {ip} - Injecting iptables rule (DROP) and enabling hardware tracking...")
        
        totale_vittima = stats["syn"] + stats["udp"] + stats["icmp"] + stats["ssh"]
        mac_src = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
        
        # Basic OS fingerprinting using default Time-To-Live (TTL) values
        ttl, ip_id, ip_flags, os_guess = "Unknown", "Unknown", "Unknown", "Unknown"
        if packet.haslayer(IP):
            ttl = packet[IP].ttl
            ip_id = packet[IP].id
            ip_flags = str(packet[IP].flags)
            if isinstance(ttl, int):
                # Linux usually starts at 64, Windows at 128, Routers often at 255
                if ttl <= 64: os_guess = "Linux/Unix/macOS (TTL <= 64)"
                elif ttl <= 128: os_guess = "Windows (TTL <= 128)"
                else: os_guess = "Network Device / Other (TTL > 128)"
                
        # Note: JSON dictionary keys are kept in Italian to maintain compatibility 
        # with state.py and firewall.py which reference them directly
        info_attaccante = {
            "ip": ip,
            "mac_address": mac_src,
            "ttl_rilevato": ttl,
            "ip_id": ip_id,
            "ip_flags": ip_flags,
            "os_presunto": os_guess,
            "dettagli_protocollo": {}
        }
        
        # Extract deep packet inspection details based on the protocol
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            tcp_options = [f"{opt[0]}:{opt[1]}" if isinstance(opt, tuple) and