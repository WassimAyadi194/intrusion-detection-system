#connection_tracking.py
import time

class ConnectionTracker:
    def __init__(self):
        self.connections = {}
        self.TIMEOUT = 60

    def analyze_packet(self, pkt):
        if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
            return None

        src   = pkt["IP"].src
        dst   = pkt["IP"].dst
        sport = pkt["TCP"].sport
        dport = pkt["TCP"].dport
        flags = pkt["TCP"].flags

        key = (src, dst, sport, dport)
        now = time.time()

        alerts = []

        if flags & 0x02:                        # SYN
            self.connections[key] = now
            alerts.append(f"Connection detected: {src} -> {dst}")

        elif (flags & 0x01) or (flags & 0x04):  # FIN or RST
            if key in self.connections:
                del self.connections[key]
                alerts.append(f"Connection terminated: {src} -> {dst}")

        self.cleanup(now)

        return alerts if alerts else None

    def cleanup(self, now):
        for key in list(self.connections.keys()):
            if now - self.connections[key] > self.TIMEOUT:
                del self.connections[key]