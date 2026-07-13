# Manages iptables rules and runs the asynchronous firewall worker
import subprocess
import threading
import state

def update_stats_from_iptables():
    try:
        # Query iptables for raw PREROUTING table statistics
        # -v: verbose (shows packet counts), -n: numeric output (no DNS resolution), -x: exact values
        result = subprocess.run(["iptables", "-t", "raw", "-L", "PREROUTING", "-v", "-n", "-x"], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        for line in lines:
            # Check if the rule is actively dropping packets
            if "DROP" in line:
                parts = line.split() 
                # Ensure the line has enough columns to extract packet count and source IP safely
                if len(parts) >= 9:
                    pkts_droppati = int(parts[0])
                    src_ip = parts[7]
                    
                    # Acquire thread lock to safely update the shared state dictionary and prevent race conditions
                    with state.log_lock:
                        # "0.0.0.0/0" indicates a global rule (e.g., a global SYN flood block)
                        if src_ip == "0.0.0.0/0":
                            if "GLOBAL_DDoS" in state.ongoing_attacks:
                                state.ongoing_attacks["GLOBAL_DDoS"]["info_attacco"]["pacchetti_distrutti_dal_firewall"] = pkts_droppati
                        # Otherwise, update the dropped packet count for the specific attacking IP
                        elif src_ip in state.ongoing_attacks:
                            state.ongoing_attacks[src_ip]["info_attacco"]["pacchetti_distrutti_dal_firewall"] = pkts_droppati

    except Exception as e:
        print(f"[-] Error while querying iptables: {e}")

def firewall_worker():
    # Run an infinite loop to continuously consume tasks from the queue
    while True:
        action, target = state.firewall_queue.get()
        
        # Insert (-I) a rule at the top of the raw PREROUTING chain to drop all traffic from the target IP
        if action == "BLOCK_IP":
            subprocess.run(["iptables", "-t", "raw", "-I", "PREROUTING", "-s", target, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        # Insert a rule to drop all incoming TCP SYN packets globally
        elif action == "BLOCK_GLOBAL_SYN":
            subprocess.run(["iptables", "-t", "raw", "-I", "PREROUTING", "-p", "tcp", "--syn", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        # Signal to the queue that the current task has been fully processed
        state.firewall_queue.task_done()

def start_firewall_worker():
    # Start the worker in a daemon thread so it runs in the background and closes when the main program exits
    threading.Thread(target=firewall_worker, daemon=True).start()