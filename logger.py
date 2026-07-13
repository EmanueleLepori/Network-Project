# Handles persistent logging of attack events and periodic statistics updates
import json
import os
import time
import threading
import config
import state
from firewall import update_stats_from_iptables

def init_logs():
    # Check if a log file already exists to preserve attack history across program restarts
    if os.path.exists(config.LOG_FILE):
        try:
            with open(config.LOG_FILE, "r") as f:
                # Load previously saved alerts into the shared log history array
                state.storico_log = json.load(f)
        except json.JSONDecodeError:
            # If the file is corrupt, empty, or unreadable, ignore the error and start fresh
            pass 

def log_updater_worker():
    # Infinite loop that periodically flushes data to disk and updates firewall stats
    while True:
        # Wait 5 seconds between each logging cycle to avoid heavy I/O operations
        time.sleep(5)

        # Acquire the lock just long enough to safely check if there are any active attacks
        with state.log_lock:
            has_attacks = len(state.ongoing_attacks) > 0
            
        if has_attacks:
            # Fetch the latest dropped packet counts from iptables for currently active attacks
            update_stats_from_iptables()
            
            try:
                # Acquire the lock again before writing to disk to ensure no other thread 
                # modifies the log array while we are in the middle of dumping it
                with state.log_lock:
                    with open(config.LOG_FILE, "w") as f:
                        # Write the entire historical log to the JSON file with human-readable indentation
                        json.dump(state.storico_log, f, indent=4)
            except Exception as e:
                print(f"[-] Error while writing the log file: {e}")
                
def start_log_worker():
    # Prime the historical logs from disk, then start the background worker as a daemon thread
    init_logs()
    threading.Thread(target=log_updater_worker, daemon=True).start()