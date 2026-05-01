# config.py
"""
Central configuration for the IDS.

All modules import constants from here. To change a value, edit it once
and every module that imports it picks up the change automatically.
"""

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