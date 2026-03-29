from scapy.all import sniff
from constants import CAPTURE_TIMEOUT, CAPTURE_FILTER
from capturing.interface_utils import *
from engine.ids_engine import DetectionEngine
import socket


def check_connectivity():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

def start_capture(inf):
    """
    Starts live packet capture and feeds packets to the IDS engine.
    """
    engine = DetectionEngine()
    banner(inf, CAPTURE_FILTER)
    print("Starting capture...")

    def handler(pkt):
        if not pkt.haslayer("IP"):
            return

        alerts = engine.process_packet(pkt)
        if alerts:
            for alert in alerts:
                print(alert)

    try:
        while True:
            sniff(
                timeout=CAPTURE_TIMEOUT,
                prn=handler,
                iface=inf,
                store=False
            )

            if not check_connectivity():
                raise RuntimeError("Network connectivity lost.")

    except PermissionError:
        raise RuntimeError("Packet capture requires administrator/root privileges.")

    except OSError as e:
        raise RuntimeError(f"Packet capture failed: {e}")

    except ValueError as e:
        raise RuntimeError(f"Invalid capture configuration: {e}")

    finally:
        print("Capture session ended.")
