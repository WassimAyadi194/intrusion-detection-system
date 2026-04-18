#packets_threshold.py
import time

class PacketThresholdDetector:
    def __init__(self):
        self.packet_counts = {}
        self.WINDOW = 10
        self.THRESHOLD = 1000

    def analyze_packet(self, pkt):
        if "IP" not in pkt:
            return None

        src = pkt["IP"].src
        now = time.time()

        alerts = []
        if src not in self.packet_counts:
            self.packet_counts[src] = {"count": 0, "start": now}

        entry = self.packet_counts[src]
        entry["count"] += 1

        if now - entry["start"] <= self.WINDOW:
            if entry["count"] >= self.THRESHOLD:
                alerts.append(f"PACKET FLOOD DETECTED from {src}")
                del self.packet_counts[src]
        else:
            self.packet_counts[src] = {"count": 1, "start": now}

        self.cleanup(now)

        return alerts if alerts else None

    def cleanup(self, now):
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]