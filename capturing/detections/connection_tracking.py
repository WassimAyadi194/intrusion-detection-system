# detections/connection_tracking.py
import time
import ipaddress

# Module-level constants (neither is instance-specific)
RECURRING_THRESHOLD = 10   # SYN count before a host is classified as recurring
CONNECTION_TIMEOUT  = 60   # seconds before an idle tracked connection is expired
CLEANUP_INTERVAL    = 10   # seconds between connection-table cleanup passes


def _is_loopback(src: str) -> bool:
    try:
        return ipaddress.ip_address(src).is_loopback
    except ValueError:
        return False


class ConnectionTracker:
    def __init__(self, baseline_hosts: set[str] | None = None):
        self.connections: dict = {}
        self.baseline_hosts: set[str] = baseline_hosts or set()
        self._syn_counts: dict[str, int] = {}
        self._last_cleanup: float = 0.0

    def _classify_novelty(self, src: str) -> str:
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
                    "novelty":   None,
                    "message":   f"Connection terminated: {src} -> {dst}",
                    "timestamp": int(now),
                })

        # Throttled cleanup — only iterates the table every CLEANUP_INTERVAL seconds
        if now - self._last_cleanup >= CLEANUP_INTERVAL:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for key in list(self.connections.keys()):
            if now - self.connections[key] > CONNECTION_TIMEOUT:
                del self.connections[key]