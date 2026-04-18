#baseline_trainer.py
import sqlite3
import math
from datetime import datetime, timezone

DB_NAME = "ids.db"
MIN_SAMPLES = 10

def compute_stddev(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def train_baseline(host_ip: str | None = None):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if host_ip:
        cursor.execute(
            "SELECT DISTINCT host_ip FROM live_metrics WHERE host_ip = ?",
            (host_ip,)
        )
    else:
        cursor.execute("SELECT DISTINCT host_ip FROM live_metrics")

    hosts = [row["host_ip"] for row in cursor.fetchall()]

    if not hosts:
        print("No data in live_metrics yet. Collect traffic first.")
        conn.close()
        return

    trained = 0
    skipped = 0

    for ip in hosts:
        cursor.execute("""
            SELECT syn_count, unique_ports, unique_destinations
            FROM live_metrics
            WHERE host_ip = ?
            ORDER BY timestamp ASC
        """, (ip,))
        rows = cursor.fetchall()

        if len(rows) < MIN_SAMPLES:
            print(f"[SKIP] {ip} — only {len(rows)} samples (need {MIN_SAMPLES})")
            skipped += 1
            continue

        syn_vals  = [r["syn_count"]          for r in rows]
        port_vals = [r["unique_ports"]        for r in rows]
        dest_vals = [r["unique_destinations"] for r in rows]

        def stats(vals):
            mean = sum(vals) / len(vals)
            std  = compute_stddev(vals, mean)
            return mean, std

        avg_syn,   std_syn   = stats(syn_vals)
        avg_ports, std_ports = stats(port_vals)
        avg_dests, std_dests = stats(dest_vals)

        cursor.execute("""
            INSERT INTO baseline (
                host_ip,
                avg_syn, std_syn,
                avg_unique_ports, std_unique_ports,
                avg_unique_destinations, std_unique_destinations,
                last_updated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_ip) DO UPDATE SET
                avg_syn                  = excluded.avg_syn,
                std_syn                  = excluded.std_syn,
                avg_unique_ports         = excluded.avg_unique_ports,
                std_unique_ports         = excluded.std_unique_ports,
                avg_unique_destinations  = excluded.avg_unique_destinations,
                std_unique_destinations  = excluded.std_unique_destinations,
                last_updated             = excluded.last_updated
        """, (
            ip,
            avg_syn, std_syn,
            avg_ports, std_ports,
            avg_dests, std_dests,
            datetime.now(timezone.utc).isoformat()
        ))

        print(
            f"[OK] {ip} — {len(rows)} samples | "
            f"syn={avg_syn:.1f}±{std_syn:.1f}  "
            f"ports={avg_ports:.1f}±{std_ports:.1f}  "
            f"dests={avg_dests:.1f}±{std_dests:.1f}"
        )
        trained += 1

    conn.commit()
    conn.close()
    print(f"\nBaseline training complete: {trained} trained, {skipped} skipped.")


if __name__ == "__main__":
    train_baseline()