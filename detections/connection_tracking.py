# detections/connection_tracking.py
import time
import ipaddress

RECURRING_THRESHOLD = 10  # connections before a host is considered recurring


def _is_loopback(src: str) -> bool:
    try:
        return ipaddress.ip_address(src).is_loopback
    except ValueError:
        return False


class ConnectionTracker:
    def __init__(self, baseline_hosts: set[str] | None = None):
        self.connections: dict = {}
        self.TIMEOUT = 60
        self.baseline_hosts: set[str] = baseline_hosts or set()
        # In-memory per-session SYN counter per host (not persisted)
        self._syn_counts: dict[str, int] = {}

    def _classify_novelty(self, src: str) -> str:
        # Loopback is always internal — classifying it as 'new' or 'recurring'
        # produces misleading noise.  Use a dedicated label instead.
        if _is_loopback(src):
            return "loopback"
        count = self._syn_counts.get(src, 0)
        if count >= RECURRING_THRESHOLD:
            return "recurring"
        if src in self.baseline_hosts:
            return "known"
        return "new"

    def analyze_packet(self, pkt) -> list[dict] | None:
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

        if flags & 0x02:  # SYN
            # Increment counter before classification so first hit counts
            self._syn_counts[src] = self._syn_counts.get(src, 0) + 1
            novelty = self._classify_novelty(src)

            self.connections[key] = now
            alerts.append({
                "src":       src,
                "type":      "connection",
                "metric":    "new",
                "severity":  "INFO",
                "novelty":   novelty,
                "message":   f"Connection detected: {src} -> {dst} [{novelty}]",
                "timestamp": int(now),
            })

        elif (flags & 0x01) or (flags & 0x04):  # FIN or RST
            if key in self.connections:
                del self.connections[key]
                alerts.append({
                    "src":       src,
                    "type":      "connection",
                    "metric":    "terminated",
                    "severity":  "INFO",
                    "novelty":   None,   # termination events have no novelty classification
                    "message":   f"Connection terminated: {src} -> {dst}",
                    "timestamp": int(now),
                })

        self.cleanup(now)

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for key in list(self.connections.keys()):
            if now - self.connections[key] > self.TIMEOUT:
                del self.connections[key]