import time 
vertical_scan = {} 
horizontal_scan = {}

VERTICAL_SCAN_WINDOW = 60
PORT_THRESHOLD = 5

HORIZONTAL_SCAN_WINDOW = 60
HOST_THRESHOLD = 10
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'

def detect_port_scan(pkt):
    if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
        return

    src = pkt["IP"].src
    dst = pkt["IP"].dst
    dport = pkt["TCP"].dport
    flags = pkt["TCP"].flags
    now = time.time()

    #DEBUG 
    #print(f"[DEBUG] SRC:{src}, DST:{dst}, DPORT:{dport}, FLAGS:{flags}")

    # Vertical scan tracking 
    vkey = (src, dst)
    if vkey not in vertical_scan:
        vertical_scan[vkey] = {"ports": set(), "time": now}

    vertical_scan[vkey]["ports"].add(dport)
    vertical_scan[vkey]["time"] = now 

    #DEBUG
    #print(f"VERTICAL COUNT OF KEY {vkey}:{len(vertical_scan[vkey]['ports'])}")

    if len(vertical_scan[vkey]["ports"]) >= PORT_THRESHOLD:
        alert = f"{Colors.RED}\nVERTICAL PORT SCAN detected: {src} → {dst}\n{Colors.RESET}"
        print(alert)
        
        del vertical_scan[vkey]
        print(f"{Colors.YELLOW}VERTICAL SCAN KEY DELETED{Colors.RESET}")

    # Horizontal scan tracking
    hkey = (src, dport)
    if hkey not in horizontal_scan:
        horizontal_scan[hkey] = {"hosts": set(), "time": now}

    horizontal_scan[hkey]["hosts"].add(dst)
    #horizontal_scan[hkey]["time"] = now

    #DEBUG 
    #print(f"HORIZONTAL COUNT OF KEY {hkey}:{len(horizontal_scan[hkey]['hosts'])}")

    if len(horizontal_scan[hkey]["hosts"]) >= HOST_THRESHOLD:
        alert = f"{Colors.RED}\nHORIZONTAL PORT SCAN detected: {src} on port {dport}\n{Colors.RESET}"
        print(alert)
        
        del horizontal_scan[hkey]
        print(f"{Colors.YELLOW}HORIZONTAL SCAN KEY DELETED{Colors.RESET}")

    cleanup(now)

def cleanup(now):
    for k in list(vertical_scan.keys()):
        if now - vertical_scan[k]["time"] > VERTICAL_SCAN_WINDOW:
            del vertical_scan[k]
            alert = f"{Colors.YELLOW}Deleted {k} entry in VERTICAL_SCAN for inactivity{Colors.RESET}"
            print(alert)

    for k in list(horizontal_scan.keys()):
        if now - horizontal_scan[k]["time"] > HORIZONTAL_SCAN_WINDOW:
            del horizontal_scan[k]
            alert = f"{Colors.YELLOW}Deleted {k} entry in HORIZONTAL_SCAN for inactivity{Colors.RESET}"
            print(alert)