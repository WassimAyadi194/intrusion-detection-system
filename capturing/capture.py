from scapy.all import *
from detections.packets_threshold import detect
from detections.connection_tracking import track_connection
from detections.port_scan import detect_port_scan
from constants import CAPTURE_TIMEOUT, CAPTURE_FILTER
from logs.logger import write_log
from capturing.interface_utils import *

def check_connectivity():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False


def handler(pkt):
    if not pkt.haslayer("IP"):
        print("Invalid packet.")
        return
    
    #print(pkt.summary())

    #src = pkt["IP"].src
    #dst = pkt["IP"].dst
    #print(src, "→", dst)
    detect(pkt)
    track_connection(pkt)
    detect_port_scan(pkt)

def start_capture(inf, local_ip):
    banner(inf,CAPTURE_FILTER)
    print("Starting capture...")
    try:
        while True:
            sniff(
                timeout=CAPTURE_TIMEOUT,
                prn=handler,
                iface=inf,
                store=False
            )

            if not check_connectivity():
                alert = "Network connectivity lost."
                #write_log(alert)
                raise RuntimeError(alert)

    #OS restricts direct access to network hardware by default for security reasons
    except PermissionError:
        alert = "Packet capture requires administrator/root privileges."
        #write_log(alert)
        raise RuntimeError(alert)

    #Failures from the operating system (network drivers, etc.)
    except OSError as e:
        alert = f"Packet capture failed: {e}"
        #write_log(alert)
        raise RuntimeError(alert)

    # Invalid values are passed to the sniff function parameters (e.g., negative number in timeout, invalid filter name)
    except ValueError as e:
        alert = f"Invalid capture configuration: {e}"
        #write_log(alert)
        raise RuntimeError(alert)
    finally:
        alert = "Capture session ended."
        #write_log(alert)
        print(alert)

#show_interfaces()