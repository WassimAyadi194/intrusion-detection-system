# detections/packets_threshold.py
import time


class PacketThresholdDetector:
    def __init__(self):
        self.packet_counts = {}
        self.WINDOW = 10
        self.THRESHOLD = 3000
        self._last_cleanup: float = 0.0

    def analyze_packet(self, pkt) -> list[dict] | None:
        if "IP" not in pkt:
            return None

        src = pkt["IP"].src
        now = time.time()

        if src not in self.packet_counts:
            self.packet_counts[src] = {"count": 0, "start": now}

        entry = self.packet_counts[src]
        entry["count"] += 1

        alerts = []

        if now - entry["start"] <= self.WINDOW:
            if entry["count"] >= self.THRESHOLD:
                alerts.append({
                    "src":       src,
                    "type":      "packet_flood",
                    "metric":    None,
                    "severity":  "MEDIUM",
                    "message":   f"PACKET FLOOD DETECTED from {src}",
                    "timestamp": int(now),
                })
                del self.packet_counts[src]
        else:
            self.packet_counts[src] = {"count": 1, "start": now}

        # Throttled cleanup — only runs every WINDOW seconds
        if now - self._last_cleanup >= self.WINDOW:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for src in list(self.packet_counts.keys()):
            if now - self.packet_counts[src]["start"] > self.WINDOW:
                del self.packet_counts[src]