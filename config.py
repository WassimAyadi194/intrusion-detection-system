# config.py
"""
Central configuration for the IDS.

All modules import constants from here. To change a value, edit it once
and every module that imports it picks up the change automatically.
"""
import json
import pathlib

_SETTINGS_PATH = pathlib.Path("ids_settings.json")

# ── Database ──────────────────────────────────────────────────────────────────
DB_NAME = "ids.db"

# ── DB retry (shared by ids_engine, anomaly_detector, data_collector) ─────────
DB_MAX_RETRIES = 2      # retries after the initial attempt (3 total)
DB_RETRY_DELAY = 0.2    # fixed backoff between attempts (seconds)

# ── Baseline EMA ──────────────────────────────────────────────────────────────
# Controls how much weight is given to newly-computed statistics when updating
# an existing baseline row.  Lower values = more memory / slower adaptation.
# Formula: updated = (1 - alpha) * old + alpha * new
BASELINE_EMA_ALPHA = 0.1

# ── Live-metrics retention ─────────────────────────────────────────────────────
# Rows older than this many hours are deleted once at application startup.
LIVE_METRICS_RETENTION_HOURS = 6

# ── Restart / stall config ────────────────────────────────────────────────────
_MAX_RESTARTS    = 3      # total restart attempts after first failure
_RESTART_BACKOFF = 0.5    # seconds between restart attempts
_STALL_TIMEOUT   = 30     # seconds with no packets before logging a warning
_STALL_CHECK_INTERVAL = 5 # how often the stall-monitor thread wakes up (seconds)

# ── Queue-depth monitoring and backpressure ───────────────────────────────────
_QUEUE_WARN_INTERVAL = 30   # seconds between periodic queue-depth checks
_QUEUE_WARN_DEPTH    = 500  # log a WARNING when either queue exceeds this
MAX_QUEUE_SIZE       = 2000 # packets — drop loopback/low-priority above this
QUEUE_SIZE_HARD_LIMIT = MAX_QUEUE_SIZE * 3
# ── Heartbeat ─────────────────────────────────────────────────────────────────
_HEARTBEAT_INTERVAL  = 30   # seconds between system-healthy log lines
# ── Window size ──────────────────────────────────────────────────────────────
# The rolling window (in seconds) over which we aggregate metrics for analysis.
WINDOW_SIZE = 20

# ── Batch config ─────────────────────────────────────────────────────────────
# Max packets to process in a single loop iteration.  This keeps memory usage
# bounded and prevents the collector thread from starving other parts of the
# application, at the cost of slightly longer collection periods when the
# volume is high.
COLLECTOR_BATCH_MAX = 500

# ── Packet-flood detector ─────────────────────────────────────────────────────
# Multiplier for the σ term in:  threshold = mean + PACKET_K * std
PACKET_K: float = 2.0
# Hard lower bound — prevents the threshold from being too permissive.
PACKET_MIN_GLOBAL_THRESHOLD: int = 1000
# Rolling window (seconds) over which per-source packet counts accumulate.
PACKET_WINDOW: int = 10
# Per-penalty multipliers (< 1.0 → stricter threshold).
PACKET_SENSITIVITY_PENALTIES: dict = {
    "novelty_new":        0.8,
    "high_failure_ratio": 0.8,
}
# Failed-connection ratio above which the high_failure_ratio penalty fires.
PACKET_HIGH_FAILURE_RATIO_THRESHOLD: float = 0.6

# ── Port-scan detector ────────────────────────────────────────────────────────
# Multiplier for the σ term in the vertical / horizontal threshold formula.
PORT_SCAN_K: float = 2.0
# Hard floors for vertical (per-destination) and horizontal (per-port) thresholds.
PORT_SCAN_MIN_PORT_SCAN_LIMIT: int = 10
PORT_SCAN_MIN_HOST_SCAN_LIMIT: int = 10
# Per-penalty multipliers (same semantics as packet detector).
PORT_SCAN_SENSITIVITY_PENALTIES: dict = {
    "novelty_new":        0.8,
    "high_failure_ratio": 0.8,
}
# Failed-connection ratio threshold for the port-scan high_failure_ratio penalty.
PORT_SCAN_HIGH_FAILURE_RATIO_THRESHOLD: float = 0.6
# Ports where the sensitivity penalty is suppressed (baseline mean+std is still used).
PORT_SCAN_STATIC_THRESHOLD_PORTS: set = {443}

# ── Anomaly detector ──────────────────────────────────────────────────────────
# Minimum effective standard deviation before Z-score division.
ANOMALY_STD_FLOOR: float = 1.0
# Minimum training samples before a baseline is considered reliable.
ANOMALY_MIN_BASELINE_SAMPLES: int = 10
# Per-metric absolute-delta guard — prevents trivially small absolute changes
# from firing even when the Z-score is large (e.g. 2 → 8 SYNs on a near-zero baseline).
ANOMALY_MIN_DELTAS: dict = {
    "syn_count":           20.0,
    "unique_ports":        10.0,
    "unique_destinations": 10.0,
    "packet_count":     1000.0,
}


# ── Settings persistence helpers ──────────────────────────────────────────────
def load_settings() -> dict:
    """Return persisted settings dict, or {} if the file does not exist."""
    if _SETTINGS_PATH.exists():
        try:
            return json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_settings(data: dict) -> None:
    """Atomically persist *data* to the settings JSON file."""
    _SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def apply_saved_settings() -> None:
    """
    Overwrite every tunable constant in this module with values from
    ids_settings.json (if present).  Call once at application startup,
    before any detector is instantiated.
    """
    import sys
    data = load_settings()
    if not data:
        return
    module = sys.modules[__name__]
    for key, value in data.items():
        if hasattr(module, key):
            # Coerce sets back from lists (JSON has no set type)
            existing = getattr(module, key)
            if isinstance(existing, set) and isinstance(value, list):
                value = set(value)
            setattr(module, key, value)