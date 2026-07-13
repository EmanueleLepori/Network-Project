# Main configuration settings for the Network Intrusion Prevention System (NIPS)

# The network interface that the NIPS will monitor for traffic
INTERFACE = "ens33"

# The time window (in seconds) used to calculate traffic rates and evaluate thresholds
WINDOW = 1.0 

# File path where intrusion alerts and attack logs will be saved
LOG_FILE = "nips_alerts.json"

# Maximum allowed events per time WINDOW before triggering a defensive action (e.g., blocking an IP)
THRESHOLDS = {
    "GLOBAL_SYN_FLOOD": 150, # Total SYN packets allowed from all sources combined
    "PORT_SCAN": 15,         # Max distinct ports a single IP can probe
    "SSH_BRUTE": 10,         # Max connection attempts to the SSH port (typically 22) from a single IP
    "SYN_FLOOD": 60,         # Max SYN packets allowed from a single specific IP
    "UDP_FLOOD": 100,        # Max UDP packets allowed from a single specific IP
    "ICMP_FLOOD": 50         # Max ICMP (ping) packets allowed from a single specific IP
}