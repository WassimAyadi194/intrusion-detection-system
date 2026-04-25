# init_db.py
import sqlite3

from config import DB_NAME

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    # WAL mode is persistent — set once here so every subsequent connection
    # benefits without paying the PRAGMA round-trip on each open.
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    # Baseline Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            host_ip TEXT PRIMARY KEY,
            avg_syn REAL,
            std_syn REAL,
            avg_unique_ports REAL,
            std_unique_ports REAL,
            avg_unique_destinations REAL,
            std_unique_destinations REAL,
            avg_packet_count REAL,
            std_packet_count REAL,
            last_updated TIMESTAMP
        );
    """)

    # Live Metrics Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS live_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT,
            timestamp INTEGER,
            syn_count INTEGER,
            unique_ports INTEGER,
            unique_destinations INTEGER,
            packet_count INTEGER DEFAULT 0
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_live_host_time
        ON live_metrics(host_ip, timestamp);
    """)

    # Standalone timestamp index — used by the startup DELETE that prunes rows
    # older than LIVE_METRICS_RETENTION_HOURS.  A plain `WHERE timestamp < ?`
    # predicate cannot use the composite (host_ip, timestamp) index efficiently
    # because timestamp is not the leading column there.
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_live_timestamp
        ON live_metrics(timestamp);
    """)

    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT,
            metric TEXT,
            value REAL,
            baseline_avg REAL NULL,
            baseline_std REAL NULL,
            severity TEXT,
            timestamp INTEGER,
            description TEXT,
            novelty TEXT NULL
        );
    """)

    # Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            level     TEXT,
            module    TEXT,
            message   TEXT
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_level
        ON logs(level);
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp
        ON logs(timestamp);
    """)

    # novelty column (original guard, kept intact)
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN novelty TEXT;")
    except sqlite3.OperationalError:
        pass

    # packet_count column in live_metrics
    try:
        cursor.execute(
            "ALTER TABLE live_metrics ADD COLUMN packet_count INTEGER DEFAULT 0;"
        )
    except sqlite3.OperationalError:
        pass  # already exists

    # avg/std_packet_count columns in baseline
    for col in ("avg_packet_count REAL", "std_packet_count REAL"):
        try:
            cursor.execute(f"ALTER TABLE baseline ADD COLUMN {col};")
        except sqlite3.OperationalError:
            pass  # already exists

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    initialize_database()