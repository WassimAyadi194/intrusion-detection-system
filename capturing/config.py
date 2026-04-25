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
LIVE_METRICS_RETENTION_HOURS = 24