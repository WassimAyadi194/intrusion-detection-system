# detections/alert_gate.py
import threading
import time
import ipaddress

# Default cooldown in seconds before the same (src, type, metric) key can fire again.
DEFAULT_COOLDOWN = 15
# HIGH alerts get a shorter cooldown.
HIGH_COOLDOWN = 5
# INFO alerts (non malicious) get an even shorter cooldown
INFO_COOLDOWN = 0
# CRITICAL alerts bypass cooldown entirely — they always emit.
CRITICAL_SEVERITY = "CRITICAL"
HIGH_SEVERITY = "HIGH"

# Loopback sources are rate-limited much more aggressively so they don't
# drown out external-traffic alerts.  Values are in seconds.
LOOPBACK_COOLDOWN_INFO     = 60   # connection tracking events from 127.x / ::1
LOOPBACK_COOLDOWN_DEFAULT  = 120  # everything else from loopback


def _is_loopback(src: str) -> bool:
    """Return True if src is a loopback address (IPv4 or IPv6)."""
    try:
        return ipaddress.ip_address(src).is_loopback
    except ValueError:
        return False


class AlertGate:
    """
    Centralised suppression layer that sits between detectors and output.

    Every raw alert must pass through `process()` before being printed or
    persisted. The gate deduplicates by (src, type, metric) key and
    enforces per-severity cooldowns:

        CRITICAL  → always allowed (no cooldown)
        HIGH      → 5 s cooldown
        everything else → 15 s cooldown

    Thread-safe via a single reentrant lock.
    """

    def __init__(
        self,
        default_cooldown: int = DEFAULT_COOLDOWN,
        high_cooldown: int = HIGH_COOLDOWN,
        info_cooldown: int = INFO_COOLDOWN,
    ):
        self._default_cooldown = default_cooldown
        self._high_cooldown = high_cooldown
        self._info_cooldown = info_cooldown
        # Maps dedup_key -> last_allowed_timestamp
        self._last_seen: dict[tuple, float] = {}
        self._lock = threading.RLock()
    #Public API
    def process(self, alert: dict) -> dict | None:
        """
        Return the alert dict if it should be emitted right now, else None.

        CRITICAL alerts always pass through (even from loopback).
        Loopback sources get a much longer cooldown to prevent flooding.
        All others are suppressed if the same (src, type, metric) key fired
        within the cooldown window.
        """
        severity = (alert.get("severity") or "").upper()

        if severity == CRITICAL_SEVERITY:
            return alert

        key = self._dedup_key(alert)
        now = time.time()
        src = alert.get("src", "")

        # Loopback suppression — overrides normal severity cooldowns.
        if _is_loopback(src):
            if severity in ("INFO", "LOW"):
                cooldown = LOOPBACK_COOLDOWN_INFO
            else:
                cooldown = LOOPBACK_COOLDOWN_DEFAULT
        elif severity == HIGH_SEVERITY:
            cooldown = self._high_cooldown
        elif severity in ("INFO", "LOW"):
            cooldown = self._info_cooldown
        else:
            cooldown = self._default_cooldown

        with self._lock:
            last = self._last_seen.get(key, 0.0)
            if now - last >= cooldown:
                self._last_seen[key] = now
                return alert
            return None

    @staticmethod
    def _dedup_key(alert: dict) -> tuple:
        return (
            alert.get("src", ""),
            alert.get("type", ""),
            alert.get("metric") or "",
        )