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
            unique_destinations INTEGER
        );
    """)

    # Index for performance
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
            baseline_avg REAL,
            baseline_std REAL,
            severity TEXT,
            timestamp INTEGER,
            description TEXT
        );
    """)

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    initialize_database()