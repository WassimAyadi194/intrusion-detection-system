import collections
import threading
import time
import ipaddress

from logs.ids_logger import get_logger

log = get_logger(__name__)

DEFAULT_COOLDOWN   = 15
HIGH_COOLDOWN      = 5
INFO_COOLDOWN      = 30
CRITICAL_SEVERITY  = "CRITICAL"
HIGH_SEVERITY      = "HIGH"
LOOPBACK_COOLDOWN_INFO    = 60
LOOPBACK_COOLDOWN_DEFAULT = 120
_ALERT_HISTORY_TTL = 120
 
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
 
 
def _is_loopback(src: str) -> bool:
    try:
        return ipaddress.ip_address(src).is_loopback
    except ValueError:
        return False
 
 
class AlertGate:
 
    def __init__(
        self,
        default_cooldown: int = DEFAULT_COOLDOWN,
        high_cooldown: int = HIGH_COOLDOWN,
        info_cooldown: int = INFO_COOLDOWN,
    ):
        self._default_cooldown = default_cooldown
        self._high_cooldown    = high_cooldown
        self._info_cooldown    = info_cooldown
        self._last_seen: dict[tuple, float] = {}
        self._lock = threading.RLock()
        self._allowed_ts: collections.deque[tuple[float, str]] = collections.deque()
 

        # Per-host alert history used by worst_severity_since().
        # Dict is created lazily (setdefault) so cold-start cost is zero.
        self._host_alerts: dict[str, collections.deque[tuple[float, str]]] = {}

 
    def process(self, alert: dict) -> dict | None:
        severity = (alert.get("severity") or "").upper()
        src      = alert.get("src", "")
 
        if severity == CRITICAL_SEVERITY:
            with self._lock:
                now = time.time()
                self._allowed_ts.append((now, severity))

                self._host_alerts.setdefault(src, collections.deque()).append(
                    (now, severity)
                )
                
            time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))
            print(f"{time_str} [{severity}] {alert.get('message', '')}")
            return alert
 
        key = self._dedup_key(alert)
        now = time.time()
 
        if _is_loopback(src):
            cooldown = LOOPBACK_COOLDOWN_INFO if severity in ("INFO", "LOW") else LOOPBACK_COOLDOWN_DEFAULT
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
                self._allowed_ts.append((now, severity))
                
                self._host_alerts.setdefault(src, collections.deque()).append(
                    (now, severity)
                )
            
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))
                print(f"{time_str} [{severity}] {alert.get('message', '')}")
                return alert
                
            return None
 
    def count_since(self, since: float, exclude_severities: set[str] | tuple[str, ...] = ("INFO",)) -> int:
        cutoff_prune = time.time() - _ALERT_HISTORY_TTL
        with self._lock:
            while self._allowed_ts and self._allowed_ts[0][0] < cutoff_prune:
                self._allowed_ts.popleft()
            return sum(1 for ts, sev in self._allowed_ts if ts >= since and sev not in exclude_severities)
 
    def worst_severity_since(self, src: str, since: float) -> str:
        cutoff_prune = time.time() - _ALERT_HISTORY_TTL
        worst_rank   = 0
        worst_label  = "NONE"
 
        with self._lock:
            dq = self._host_alerts.get(src)
            if dq is None:
                return "NONE"
 
            # Lazy prune from the left — same pattern as count_since()
            while dq and dq[0][0] < cutoff_prune:
                dq.popleft()
 
            for ts, sev in dq:
                if ts < since:
                    continue
                rank = _SEVERITY_RANK.get(sev.upper(), 0)
                if rank > worst_rank:
                    worst_rank  = rank
                    worst_label = sev.upper()
 
        return worst_label

    def count_host_since(self, src: str, since: float) -> int:
        """Count how many alerts were allowed for *src* since *since*."""
        cutoff_prune = time.time() - _ALERT_HISTORY_TTL
        with self._lock:
            dq = self._host_alerts.get(src)
            if dq is None:
                return 0
            while dq and dq[0][0] < cutoff_prune:
                dq.popleft()
            return sum(1 for ts, _sev in dq if ts >= since)

    @staticmethod
    def _dedup_key(alert: dict) -> tuple:
        return (
            alert.get("src", ""),
            alert.get("type", ""),
            alert.get("metric") or "",
        )