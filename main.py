# main.py
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
            tcp_options = [f"{opt[0]}:{opt[1]}" if isinstance(opt, tuple) and len(opt)>1 else str(opt) for opt in tcp_layer.options]
            info_attaccante["dettagli_protocollo"]["tcp"] = {
                "porta_sorgente": tcp_layer.sport,
                "tcp_flags": str(tcp_layer.flags),
                "window_size": tcp_layer.window,
                "opzioni_tcp": tcp_options
            }
        elif packet.haslayer(UDP):
            info_attaccante["dettagli_protocollo"]["udp"] = {
                "porta_sorgente": packet[UDP].sport,
                "lunghezza_payload_bytes": len(packet[Raw].load) if packet.haslayer(Raw) else 0
            }
        elif packet.haslayer(ICMP):
            info_attaccante["dettagli_protocollo"]["icmp"] = {
                "tipo_icmp": packet[ICMP].type,
                "codice_icmp": packet[ICMP].code,
                "payload_esadecimale": packet[Raw].load.hex() if packet.haslayer(Raw) else "No Payload"
            }
            
        info_attacco = {
            "attacco_individuato": reason,
            "pacchetti_intercettati_prima_del_blocco": totale_vittima,
            "pacchetti_distrutti_dal_firewall": 0 
        }
        
        nuovo_evento = {
            "tempo_dell_attacco": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "info_attaccante": info_attaccante,
            "info_attacco": info_attacco
        }
        
        # Safely log the attack and send the block instruction to the firewall thread
        with state.log_lock:
            state.ongoing_attacks[ip] = nuovo_evento
            state.storico_log.append(nuovo_evento)
        
        state.firewall_queue.put(("BLOCK_IP", ip))
        state.blocked_ips.add(ip)

def activate_ddos_mitigation():
    # Emergency global block triggered when the network is overwhelmed by a distributed attack
    if not state.ddos_mode_active:
        print("\n[!!!] DDoS Attack [!!!]")
        
        nuovo_evento = {
            "tempo_dell_attacco": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "info_attaccante": {
                "ip": "DISTRIBUTED (Multiple IPs)",
                "mac_address": "N/A",
                "ttl_rilevato": "Variable",
                "ip_id": "Variable",
                "ip_flags": "Variable",
                "os_presunto": "Distributed Botnet / Coordinated Mass Attack",
                "dettagli_protocollo": {
                    "tcp": {
                        "porta_sorgente": "Variable",
                        "tcp_flags": "S (SYN)",
                        "window_size": "Variable",
                        "opzioni_tcp": []
                    }
                }
            },
            "info_attacco": {
                "attacco_individuato": f"Global DDoS Emergency (SYN Flood - Detected > {state.global_syn_count} SYN/sec)",
                "pacchetti_intercettati_prima_del_blocco": state.global_syn_count,
                "pacchetti_distrutti_dal_firewall": 0
            }
        }
        
        with state.log_lock:
            state.ongoing_attacks["GLOBAL_DDoS"] = nuovo_evento
            state.storico_log.append(nuovo_evento)
            
        # Drops ALL SYN packets globally at the firewall level to save the server
        state.firewall_queue.put(("BLOCK_GLOBAL_SYN", None))
        state.ddos_mode_active = True

def analyze_packet(packet):
    # Callback function executed for every packet sniffed on the interface
    if IP in packet:
        src_ip = packet[IP].src
        
        # Whitelist local/loopback IPs to avoid self-blocking
        if src_ip in ["127.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.2.2"]:
            return
            
        # Ignore traffic from already blocked IPs (saves processing time)
        if src_ip in state.blocked_ips:
            return 

        # Increment specific protocol counters for rate limiting
        if TCP in packet:
            if packet[TCP].flags == "S":
                dst_port = packet[TCP].dport
                state.tracker[src_ip]["scanned_ports"].add(dst_port)
                state.global_syn_count += 1
                
                if dst_port == 22:
                    state.tracker[src_ip]["ssh"] += 1
                else:
                    state.tracker[src_ip]["syn"] += 1  

        elif UDP in packet:
            state.tracker[src_ip]["udp"] += 1
        # Check specifically for ICMP echo requests (type 8, standard pings)
        elif ICMP in packet and packet[ICMP].type == 8:
            state.tracker[src_ip]["icmp"] += 1

        # Evaluate if the total global SYN packets exceed the threshold (indicates DDoS)
        if state.global_syn_count > config.THRESHOLDS["GLOBAL_SYN_FLOOD"]:
            activate_ddos_mitigation()
            
        # Evaluate individual IP behavior against thresholds
        stats = state.tracker[src_ip]
        if len(stats["scanned_ports"]) > config.THRESHOLDS["PORT_SCAN"]: 
            block_ip(src_ip, f"Port Scanning ({len(stats['scanned_ports'])} ports)", stats, packet)
        elif stats["syn"] > 150:
            block_ip(src_ip, "TCP SYN Flood Attack (Big Attack)", stats, packet)
        elif stats["ssh"] > config.THRESHOLDS["SSH_BRUTE"]:
            block_ip(src_ip, "SSH Brute Force Attack", stats, packet)
        elif stats["syn"] > config.THRESHOLDS["SYN_FLOOD"]:
            block_ip(src_ip, "TCP SYN Flood Attack(Port Specific)", stats, packet)
        elif stats["udp"] > config.THRESHOLDS["UDP_FLOOD"]:
            block_ip(src_ip, "UDP Flood Attack", stats, packet)
        elif stats["icmp"] > config.THRESHOLDS["ICMP_FLOOD"]:
            block_ip(src_ip, "ICMP Ping Flood Attack", stats, packet)

        # Clear tracking data once the rolling time window expires to reset rate limits
        current_time = time.time()
        if current_time - state.start_time >= config.WINDOW:
            state.tracker.clear()
            state.global_syn_count = 0
            state.start_time = current_time

if __name__ == "__main__":
    # Bind Ctrl+C to the cleanup function
    signal.signal(signal.SIGINT, cleanup_and_exit)
    
    # Initialize background worker threads
    start_log_worker()
    start_firewall_worker()
    
    print(f"[*] NIPS started at {config.INTERFACE}")
    print("[*] Press Ctrl+C to stop the NIPS, forcing the saving of the log and restoring the iptables.")

    # Begin sniffing traffic on the specified interface without storing packets in RAM (store=0)
    sniff(iface=config.INTERFACE, filter="ip", prn=analyze_packet, store=0)