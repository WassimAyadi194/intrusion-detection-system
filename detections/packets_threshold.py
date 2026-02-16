from constants import *
from logs.logger import write_log
import time

ip_counter = {}

class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'

def detect(pkt):
    src = pkt["IP"].src
    dst = pkt["IP"].dst
    now = time.time()

    # Initialize or update entry
    if src not in ip_counter:
        ip_counter[src] = [1, now]
    else:
        ip_counter[src][0] += 1
        ip_counter[src][1] = now

    # Detection rule
    if ip_counter[src][0] == PACKETS_THRESHOLD:
        alert = f"{Colors.RED}ALERT: Repeated packets from {src}{Colors.RESET}"
        print(alert)
        write_log(alert)

    # Cleanup old entries
    for ip in list(ip_counter.keys()):
        if now - ip_counter[ip][1] > COUNTER_WINDOW:
            del ip_counter[ip]
            print(f"{Colors.YELLOW}{ip} deleted for inactivity{Colors.RESET}")

    # Safety limit
    if len(ip_counter) > MAX_HOSTS:
        ip_counter.clear()
        print(f"{Colors.BLUE}IP COUNTER REACHED LIMIT. REINITIALIZATION SUCCESSFUL{Colors.RESET}")