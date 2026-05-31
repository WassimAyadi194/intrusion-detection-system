# detections/connection_tracking.py
import time
import ipaddress
from collections import deque

# Module-level constants (neither is instance-specific)
RECURRING_THRESHOLD = 10   # SYN count before a host is classified as recurring
CONNECTION_TIMEOUT  = 30   # seconds before a half-open connection is evicted as failed
CLEANUP_INTERVAL    = 10   # seconds between connection-table cleanup passes

# Sliding-window duration for SYN and failure counters.
# Counts older than this are discarded, preventing permanent penalisation of
# hosts that were noisy in the past but are now well-behaved.
COUNTER_WINDOW: float = 300.0   # 5 minutes


def _is_loopback(src: str) -> bool:
    try:
        return ipaddress.ip_address(src).is_loopback
    except ValueError:
        return False


class ConnectionTracker:
    def __init__(self, baseline_hosts: set[str] | None = None):
        self.connections: dict = {}
        self.baseline_hosts: set[str] = baseline_hosts or set()

        # Each entry is a deque of timestamps — one per SYN or failure event.
        # Using timestamped deques instead of plain counters gives us a sliding
        # window so that old activity naturally ages out (fixes the "never decays"
        # design issue).
        self._syn_times:    dict[str, deque] = {}
        self._failed_times: dict[str, deque] = {}

        self._last_cleanup: float = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_old(self, dq: deque, cutoff: float) -> None:
        """Remove timestamps older than *cutoff* from the left of *dq*."""
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _syn_count(self, src: str, now: float) -> int:
        """Return the number of SYNs from *src* within the sliding window."""
        dq = self._syn_times.get(src)
        if dq is None:
            return 0
        self._evict_old(dq, now - COUNTER_WINDOW)
        return len(dq)

    def _failed_count(self, src: str, now: float) -> int:
        """Return the number of failed connections from *src* within the window."""
        dq = self._failed_times.get(src)
        if dq is None:
            return 0
        self._evict_old(dq, now - COUNTER_WINDOW)
        return len(dq)

    def _classify_novelty(self, src: str, now: float) -> str:
        if _is_loopback(src):
            return "loopback"
        if src in self.baseline_hosts:
            return "known"
        count = self._syn_count(src, now)
        if count >= RECURRING_THRESHOLD:
            return "recurring"
        return "new"

    def _record_syn(self, src: str, now: float) -> None:
        if src not in self._syn_times:
            self._syn_times[src] = deque()
        self._syn_times[src].append(now)

    def _record_failure(self, src: str, now: float) -> None:
        """Record a failed-connection event for *src* at timestamp *now*."""
        if src not in self._failed_times:
            self._failed_times[src] = deque()
        self._failed_times[src].append(now)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_host_stats(self, src: str, now: float | None = None) -> dict:
        """
        Return novelty classification and failed-connection ratio for *src*.

        Both values are computed over the sliding COUNTER_WINDOW so that
        historical noise does not permanently penalise a host.

        Parameters
        ----------
        src : str
            Source IP address string.
        now : float | None
            Current epoch time.  Defaults to ``time.time()`` when omitted so
            callers that already hold a timestamp can pass it in to avoid a
            redundant syscall.

        Returns
        -------
        dict with keys:
            "novelty"                 – "new" | "known" | "recurring" | "loopback"
            "failed_connection_ratio" – float in [0.0, 1.0]

        If *src* has never been seen the safe defaults used by detectors that
        query this method before any SYN from that host are returned.
        """
        if now is None:
            now = time.time()

        total_syns = self._syn_count(src, now)
        if total_syns == 0:
            return {"novelty": "new", "failed_connection_ratio": 0.0}

        failed = self._failed_count(src, now)
        ratio  = failed / total_syns  # total_syns > 0 guaranteed above
        return {
            "novelty":                 self._classify_novelty(src, now),
            "failed_connection_ratio": ratio,
        }

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

        if flags & 0x02:  # SYN — open a tracked half-open connection
            self._record_syn(src, now)
            novelty = self._classify_novelty(src, now)

            self.connections[key] = now
            msg = f"Connection detected: {src} -> {dst} [{novelty}]"
            alerts.append({
                "src":       src,
                "type":      "connection",
                "metric":    "new",
                "severity":  "INFO",
                "novelty":   novelty,
                "message":   msg,
                "timestamp": int(now),
            })

        elif flags & 0x01:  # FIN — clean completion, do NOT count as failed
            if key in self.connections:
                del self.connections[key]
                msg = f"Connection terminated: {src} -> {dst}"
                alerts.append({
                    "src":       src,
                    "type":      "connection",
                    "metric":    "terminated",
                    "severity":  "INFO",
                    "novelty":   None,
                    "message":   msg,
                    "timestamp": int(now),
                })

        elif flags & 0x04:  # RST — failed / rejected connection
            if key in self.connections:
                del self.connections[key]
                self._record_failure(src, now)
                msg = f"Connection terminated: {src} -> {dst}"
                alerts.append({
                    "src":       src,
                    "type":      "connection",
                    "metric":    "terminated",
                    "severity":  "INFO",
                    "novelty":   None,
                    "message":   msg,
                    "timestamp": int(now),
                })

        # Throttled cleanup — only iterates the table every CLEANUP_INTERVAL seconds
        if now - self._last_cleanup >= CLEANUP_INTERVAL:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        """
        Evict half-open connections that have exceeded CONNECTION_TIMEOUT.
        Each evicted entry is counted as a failed connection for its source IP.
        Also prunes empty sliding-window deques to bound memory usage.
        """
        for key in list(self.connections.keys()):
            if now - self.connections[key] > CONNECTION_TIMEOUT:
                src = key[0]
                self._record_failure(src, now)
                del self.connections[key]

        # Prune deques whose entire window has aged out to keep memory bounded.
        cutoff = now - COUNTER_WINDOW
        for src in list(self._syn_times.keys()):
            self._evict_old(self._syn_times[src], cutoff)
            if not self._syn_times[src]:
                del self._syn_times[src]

        for src in list(self._failed_times.keys()):
            self._evict_old(self._failed_times[src], cutoff)
            if not self._failed_times[src]:
                del self._failed_times[src]