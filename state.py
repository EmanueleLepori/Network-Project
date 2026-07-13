# Global variables and shared state accessed across multiple threads
import time
import threading
import queue
from collections import defaultdict

# Reentrant lock to prevent race conditions when multiple threads read/write to shared dictionaries or logs
log_lock = threading.RLock()

# Thread-safe queue used to asynchronously pass tasks (like "BLOCK_IP") to the firewall worker thread
firewall_queue = queue.Queue()

# A set used for O(1) fast lookups to quickly check if an IP has already been blocked
blocked_ips = set()

# List acting as a chronological history of all triggered alerts and logged events
storico_log = []

# Dictionary tracking currently active attacks, mapping attacker IPs to their live statistics
ongoing_attacks = {} 

# Timestamp marking the start of the current monitoring window (used for rate calculations)
start_time = time.time()

# Accumulator tracking the total number of incoming SYN packets across all source IPs
global_syn_count = 0 

# Boolean flag that triggers restrictive defensive measures when a global attack is detected
ddos_mode_active = False 

def create_ip_record():
    # Returns a fresh baseline dictionary to track traffic types and scanned ports for a single IP
    return {"icmp": 0, "syn": 0, "udp": 0, "ssh": 0, "scanned_ports": set()}

# A dictionary that automatically initializes a new record using create_ip_record() 
# the first time an unknown IP is accessed, avoiding manual initialization and KeyErrors
tracker = defaultdict(create_ip_record)