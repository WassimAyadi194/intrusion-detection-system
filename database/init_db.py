# init_db.py
import sqlite3

DB_NAME = "ids.db"

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
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

    # ── Migration guards for pre-existing databases ──────────────────────────

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