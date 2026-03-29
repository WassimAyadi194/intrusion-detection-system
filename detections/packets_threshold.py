import time

class PacketThresholdDetector:
    def __init__(self):
        self.packet_counts = {}
        self.WINDOW = 10
        self.THRESHOLD = 200

    def analyze_packet(self, pkt):
        '''if not pkt.haslayer("IP"):
            return None'''

        src = pkt["IP"].src
        now = time.time()
        #print(f"INTERFACE: {pkt.sniffed_on} // TCP FLAGS: {pkt["TCP"].flags}")
        alerts = []
        if src not in self.packet_counts:
            self.packet_counts[src] = {
                "count": 0,
                "start": now
            }

        entry = self.packet_counts[src]
        entry["count"] += 1

        if now - entry["start"] <= self.WINDOW:
            if entry["count"] >= self.THRESHOLD:
                alerts.append(f"PACKET FLOOD DETECTED from {src}")
                del self.packet_counts[src]
        else:
            self.packet_counts[src] = {
                "count": 1,
                "start": now
            }

        self.cleanup(now)

        return alerts if alerts else None

    def cleanup(self, now):
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]