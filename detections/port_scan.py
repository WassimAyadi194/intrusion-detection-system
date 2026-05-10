# detections/port_scan.py
import time

from baseline.baseline_reader import get_all_baselines
from detections.connection_tracking import ConnectionTracker

CLEANUP_INTERVAL = 10  # seconds between scan-table cleanup passes

# Multiplier for the standard deviation term in the dynamic threshold formula.
_K: float = 2

# Absolute lower bounds — prevent thresholds from being unrealistically permissive
# for hosts whose mean + k*std is below a sensible minimum.
MIN_PORT_SCAN_LIMIT: int = 10
MIN_HOST_SCAN_LIMIT: int = 10

# How often (seconds) to refresh the baseline snapshot from the DB.
_BASELINE_REFRESH_INTERVAL: float = 120.0

# Ports that suppress the sensitivity penalty only (not the full dynamic baseline).
# Traffic to these ports is well-understood enough that we don't want the
# novelty / failure-rate multipliers tightening the threshold, but we still
# want the baseline mean+std to anchor the limit rather than falling back to
# the static HOST_THRESHOLD.
STATIC_THRESHOLD_PORTS: set[int] = {443}

# Multipliers applied to dynamic thresholds based on connection tracker signals.
# Set a value to 1.0 to disable that penalty.
SENSITIVITY_PENALTIES: dict[str, float] = {
    "novelty_new":        0.8,   # 20% stricter for hosts with no baseline history
    "high_failure_ratio": 0.8,   # 20% stricter for hosts with high RST/timeout rate
}

# Failed-connection ratio above which the high_failure_ratio penalty is applied.
HIGH_FAILURE_RATIO_THRESHOLD: float = 0.6

# Hard-tripwire constants.
HARD_TRIP_MIN_SYNS: int = 10    # minimum SYNs before hard tripwire can fire

# Cooldown (seconds) before the hard tripwire can fire again for the same source.
# Prevents alert storms when a scanner sustains a high RST rate across hundreds
# of packets — matches the cooldown pattern used in PacketThresholdDetector.
HARD_TRIP_COOLDOWN: float = 30.0


class PortScanDetector:
    def __init__(self, connection_tracker: ConnectionTracker):
        self.connection_tracker = connection_tracker
        self.vertical_scan = {}
        self.horizontal_scan = {}
        self.SCAN_WINDOW = 30
        # Static fallbacks used when a source IP is absent from the baseline.
        self.PORT_THRESHOLD = 8
        self.HOST_THRESHOLD = 10
        self._last_cleanup: float = 0.0
        self._baselines: dict[str, dict] = get_all_baselines()
        self._baselines_loaded_at: float = time.time()
        # Tracks the last hard-tripwire alert time per source IP.
        self._last_hard_trip_ts: dict[str, float] = {}

    def _refresh_baselines_if_stale(self, now: float) -> None:
        """Re-fetch baseline snapshot if the refresh interval has elapsed."""
        if now - self._baselines_loaded_at >= _BASELINE_REFRESH_INTERVAL:
            self._baselines = get_all_baselines()
            self._baselines_loaded_at = now

    def _penalty_multiplier(self, src: str, now: float) -> float:
        """
        Compute the combined sensitivity-penalty multiplier for *src*.

        Fetches host stats from the ConnectionTracker and applies
        SENSITIVITY_PENALTIES multiplicatively.  A value < 1.0 tightens
        (lowers) the dynamic threshold, making detection more aggressive.

        The novelty_new penalty is applied only when the host is both
        classified as "new" by the ConnectionTracker AND has no entry in the
        baseline DB.  A host that has a full baseline entry (mean, std) but
        happens not to be in baseline_hosts would otherwise be penalised on
        top of an already well-tuned dynamic threshold — a double-penalty that
        produces thresholds that are too aggressive.
        """
        stats = self.connection_tracker.get_host_stats(src, now)
        multiplier = 1.0

        # Only penalise truly unknown hosts — those with neither a baseline
        # DB entry nor enough observed traffic to be classified as recurring.
        if stats["novelty"] == "new" and self._baselines.get(src) is None:
            multiplier *= SENSITIVITY_PENALTIES["novelty_new"]

        if stats["failed_connection_ratio"] > HIGH_FAILURE_RATIO_THRESHOLD:
            multiplier *= SENSITIVITY_PENALTIES["high_failure_ratio"]

        return multiplier

    def _get_vertical_threshold(self, src: str, now: float) -> int:
        """
        Return the effective vertical (port) scan threshold for *src*.

            max(round((avg_unique_ports + K * std_unique_ports) * penalty), MIN_PORT_SCAN_LIMIT)

        Falls back to the static PORT_THRESHOLD when *src* has no baseline entry.
        """
        host = self._baselines.get(src)
        if host is None:
            return self.PORT_THRESHOLD

        mean    = host.get("avg_unique_ports", 0.0) or 0.0
        std     = host.get("std_unique_ports", 0.0) or 0.0
        dynamic = (mean + (_K * std)) * self._penalty_multiplier(src, now)
        return max(int(round(dynamic)), MIN_PORT_SCAN_LIMIT)

    def _get_horizontal_threshold(self, src: str, now: float, apply_penalty: bool = True) -> int:
        """
        Return the effective horizontal (destination) scan threshold for *src*.

            max(round((avg_unique_destinations + K * std_unique_destinations) * penalty), MIN_HOST_SCAN_LIMIT)

        Falls back to the static HOST_THRESHOLD when *src* has no baseline entry.

        Parameters
        ----------
        apply_penalty : bool
            When False the penalty multiplier is set to 1.0, leaving the
            dynamic baseline intact but removing sensitivity adjustments.
            Used for ports in STATIC_THRESHOLD_PORTS where we trust the
            baseline mean+std but don't want novelty/failure penalties.
        """
        host = self._baselines.get(src)
        if host is None:
            return self.HOST_THRESHOLD

        mean    = host.get("avg_unique_destinations", 0.0) or 0.0
        std     = host.get("std_unique_destinations", 0.0) or 0.0
        penalty = self._penalty_multiplier(src, now) if apply_penalty else 1.0
        dynamic = (mean + (_K * std)) * penalty
        return max(int(round(dynamic)), MIN_HOST_SCAN_LIMIT)

    def analyze_packet(self, pkt) -> list[dict] | None:
        if "IP" not in pkt or "TCP" not in pkt:
            return None

        flags = pkt["TCP"].flags

        # Only SYN packets
        if not flags & 0x02:
            return None

        src   = pkt["IP"].src
        dst   = pkt["IP"].dst
        dport = pkt["TCP"].dport
        now   = time.time()

        self._refresh_baselines_if_stale(now)

        # ---- Hard tripwire: high RST/timeout failure rate ----
        # The tripwire is gated by a per-source cooldown so that a sustained
        # scanner doesn't flood the alert pipeline with one HIGH alert per SYN.
        stats      = self.connection_tracker.get_host_stats(src, now)
        total_syns = self.connection_tracker._syn_count(src, now)
        failed_connection_ratio = stats["failed_connection_ratio"]

        if (
            total_syns >= HARD_TRIP_MIN_SYNS
            and failed_connection_ratio > 0.80
        ):
            last_trip = self._last_hard_trip_ts.get(src, 0.0)
            if now - last_trip >= HARD_TRIP_COOLDOWN:
                self._last_hard_trip_ts[src] = now
                return [{
                    "src":       src,
                    "type":      "port_scan",
                    "metric":    "hard_tripwire",
                    "severity":  "HIGH",
                    "message":   f"HIGH FAILURE RATE: {src}",
                    "timestamp": int(now),
                }]
            # Still within cooldown — suppress the duplicate but continue so
            # that the vertical/horizontal scan tables are still updated.

        alerts = []

        # ---- Vertical port scan ----
        vkey = (src, dst)

        if vkey not in self.vertical_scan:
            self.vertical_scan[vkey] = {"ports": set(), "time": now}

        self.vertical_scan[vkey]["ports"].add(dport)

        if (
            len(self.vertical_scan[vkey]["ports"]) >= self._get_vertical_threshold(src, now)
            and now - self.vertical_scan[vkey]["time"] <= self.SCAN_WINDOW
        ):
            alerts.append({
                "src":       src,
                "type":      "port_scan",
                "metric":    "vertical",
                "severity":  "HIGH",
                "message":   f"VERTICAL SCAN: {src} → {dst}",
                "timestamp": int(now),
            })
            # Reset the port set after alerting so that continued scanning
            # beyond the threshold generates follow-up alerts once another
            # threshold-worth of unique ports is seen.  This is intentional:
            # a brief burst is caught once; a persistent scanner is caught
            # repeatedly.  The hard tripwire (above) handles the sustained case
            # via failure-rate rather than port-count alone.
            del self.vertical_scan[vkey]

        # ---- Horizontal port scan ----
        hkey = (src, dport)

        if hkey not in self.horizontal_scan:
            self.horizontal_scan[hkey] = {"hosts": set(), "time": now}

        self.horizontal_scan[hkey]["hosts"].add(dst)

        # For ports in STATIC_THRESHOLD_PORTS we still use the dynamic baseline
        # mean+std, but suppress the sensitivity penalty.  This preserves the
        # per-host calibration while avoiding over-alerting on well-understood
        # high-volume ports like 443.
        apply_penalty = dport not in STATIC_THRESHOLD_PORTS
        h_thresh = self._get_horizontal_threshold(src, now, apply_penalty=apply_penalty)

        if (
            len(self.horizontal_scan[hkey]["hosts"]) >= h_thresh
            and now - self.horizontal_scan[hkey]["time"] <= self.SCAN_WINDOW
        ):
            alerts.append({
                "src":       src,
                "type":      "port_scan",
                "metric":    "horizontal",
                "severity":  "HIGH",
                "message":   f"HORIZONTAL SCAN: {src} on port {dport}",
                "timestamp": int(now),
            })
            del self.horizontal_scan[hkey]

        # Throttled cleanup
        if now - self._last_cleanup >= CLEANUP_INTERVAL:
            self.cleanup(now)
            self._last_cleanup = now

        return alerts if alerts else None

    def cleanup(self, now: float) -> None:
        for k in list(self.vertical_scan.keys()):
            if now - self.vertical_scan[k]["time"] > self.SCAN_WINDOW:
                del self.vertical_scan[k]

        for k in list(self.horizontal_scan.keys()):
            if now - self.horizontal_scan[k]["time"] > self.SCAN_WINDOW:
                del self.horizontal_scan[k]

        # Evict stale hard-tripwire cooldown entries to prevent unbounded growth.
        for src in list(self._last_hard_trip_ts.keys()):
            if now - self._last_hard_trip_ts[src] > HARD_TRIP_COOLDOWN:
                del self._last_hard_trip_ts[src]