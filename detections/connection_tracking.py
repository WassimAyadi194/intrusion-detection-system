import time
from constants import CONNECTION_WINDOW, MAX_CONNECTIONS
from logs.logger import write_log
from scapy.all import *

connections = {}

class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'

def track_connection(pkt):
    if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
        return

    src = pkt["IP"].src
    dst = pkt["IP"].dst
    dport = pkt["TCP"].dport
    now = time.time()

    key = (src, dst, dport)

    if key not in connections:
        connections[key] = {
            "packets": 1,
            "first_seen": now,
            "last_seen": now
        }
        alert = f"{Colors.GREEN}New connection: {src} -> {dst} : {dport} {Colors.RESET}"
        #write_log(alert)
        print(alert)

    else:
        connections[key]["packets"] += 1
        connections[key]["last_seen"] = now


    for key in list(connections.keys()):
        if now - connections[key]["last_seen"] > CONNECTION_WINDOW:
            del connections[key]
            print(f"{Colors.YELLOW}Connection tracker of {key} deleted for inactivity{Colors.RESET}")
    
    if len(connections) > MAX_CONNECTIONS:
        connections.clear()
        alert = f"{Colors.YELLOW}CONNECTIONS TABLE EXCEEDED LIMIT. REINITIALIZATION SUCCESSFUL{Colors.RESET}"
        print(alert)
        #write_log(alert)