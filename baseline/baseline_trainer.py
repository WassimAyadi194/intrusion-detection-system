# baseline/baseline_trainer.py
import sqlite3
import math
from datetime import datetime, timezone

from config import DB_NAME, BASELINE_EMA_ALPHA

# Minimum sample threshold
# We need at least this many windows of data before we are willing to compute
# statistics (avoids noise from a single window dominating the baseline).
MIN_SAMPLES = 10



# Helper: population standard deviation
def compute_stddev(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)



# Helper: Exponential Moving Average blend
def _ema(old: float, new: float, alpha: float = BASELINE_EMA_ALPHA) -> float:
    """
    Blend *new* into *old* using EMA:
        result = (1 - alpha) * old + alpha * new
    """
    return (1.0 - alpha) * old + alpha * new



def train_baseline(host_ip: str | None = None, only_existing: bool = False):

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Gather the set of hosts to train
    if host_ip:
        cursor.execute(
            "SELECT DISTINCT host_ip FROM live_metrics WHERE host_ip = ?",
            (host_ip,)
        )
    elif only_existing:
        cursor.execute(
            "SELECT DISTINCT host_ip FROM live_metrics WHERE host_ip IN (SELECT host_ip FROM baseline)"
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
        # Fetch raw live-metrics windows for this host
        cursor.execute("""
            SELECT syn_count, unique_ports, unique_destinations, packet_count
            FROM live_metrics
            WHERE host_ip = ?
            ORDER BY timestamp ASC
        """, (ip,))
        rows = cursor.fetchall()

        if len(rows) < MIN_SAMPLES:
            print(f"[SKIP] {ip} — only {len(rows)} samples (need {MIN_SAMPLES})")
            skipped += 1
            continue

        # ── Compute fresh statistics from the collected windows ───────────────
        syn_vals  = [r["syn_count"]          for r in rows]
        port_vals = [r["unique_ports"]        for r in rows]
        dest_vals = [r["unique_destinations"] for r in rows]
        pkt_vals  = [r["packet_count"] or 0  for r in rows]  # guard NULL from old rows

        def stats(vals: list[float]) -> tuple[float, float]:
            mean = sum(vals) / len(vals)
            std  = compute_stddev(vals, mean)
            return mean, std

        new_avg_syn,   new_std_syn   = stats(syn_vals)
        new_avg_ports, new_std_ports = stats(port_vals)
        new_avg_dests, new_std_dests = stats(dest_vals)
        new_avg_pkts,  new_std_pkts  = stats(pkt_vals)

        # ── Load any existing baseline row for this host ──────────────────────
        cursor.execute(
            "SELECT * FROM baseline WHERE host_ip = ?", (ip,)
        )
        existing = cursor.fetchone()

        if existing is not None:
            # ── EMA blend: nudge stored values toward newly-computed ones ─────
            # We apply the same alpha to both the mean and the std so that the
            # baseline's uncertainty estimate also adapts gradually.
            avg_syn   = _ema(existing["avg_syn"],                 new_avg_syn)
            std_syn   = _ema(existing["std_syn"],                 new_std_syn)
            avg_ports = _ema(existing["avg_unique_ports"],        new_avg_ports)
            std_ports = _ema(existing["std_unique_ports"],        new_std_ports)
            avg_dests = _ema(existing["avg_unique_destinations"], new_avg_dests)
            std_dests = _ema(existing["std_unique_destinations"], new_std_dests)

            # avg/std_packet_count may be NULL in older DB rows — default to 0
            avg_pkts  = _ema(existing["avg_packet_count"] or 0.0, new_avg_pkts)
            std_pkts  = _ema(existing["std_packet_count"] or 0.0, new_std_pkts)

            # Accumulate total observations across all training runs so that
            # the _MIN_BASELINE_SAMPLES guard in anomaly_detector.py reflects
            # the full history, not just the most-recent batch.
            sample_count = (existing["sample_count"] or 0) + len(rows)

            mode = "EMA"
        else:
            # Cold start: no prior record — use fresh values directly
            avg_syn,   std_syn   = new_avg_syn,   new_std_syn
            avg_ports, std_ports = new_avg_ports, new_std_ports
            avg_dests, std_dests = new_avg_dests, new_std_dests
            avg_pkts,  std_pkts  = new_avg_pkts,  new_std_pkts

            sample_count = len(rows)

            mode = "INIT"

        # Round for compact storage; precision beyond 3 d.p. is not meaningful
        # given the 10-second window granularity.
        avg_syn   = round(avg_syn,   3)
        std_syn   = round(std_syn,   3)
        avg_ports = round(avg_ports, 3)
        std_ports = round(std_ports, 3)
        avg_dests = round(avg_dests, 3)
        std_dests = round(std_dests, 3)
        avg_pkts  = round(avg_pkts,  3)
        std_pkts  = round(std_pkts,  3)

        # ── Persist (upsert) ──────────────────────────────────────────────────
        cursor.execute("""
            INSERT INTO baseline (
                host_ip,
                avg_syn, std_syn,
                avg_unique_ports, std_unique_ports,
                avg_unique_destinations, std_unique_destinations,
                avg_packet_count, std_packet_count,
                sample_count,
                last_updated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_ip) DO UPDATE SET
                avg_syn                  = excluded.avg_syn,
                std_syn                  = excluded.std_syn,
                avg_unique_ports         = excluded.avg_unique_ports,
                std_unique_ports         = excluded.std_unique_ports,
                avg_unique_destinations  = excluded.avg_unique_destinations,
                std_unique_destinations  = excluded.std_unique_destinations,
                avg_packet_count         = excluded.avg_packet_count,
                std_packet_count         = excluded.std_packet_count,
                sample_count             = excluded.sample_count,
                last_updated             = excluded.last_updated
        """, (
            ip,
            avg_syn,   std_syn,
            avg_ports, std_ports,
            avg_dests, std_dests,
            avg_pkts,  std_pkts,
            sample_count,
            datetime.now(timezone.utc).isoformat()
        ))

        print(
            f"[{mode}] {ip} — {len(rows)} new samples (total: {sample_count}) | "
            f"syn={avg_syn:.1f}±{std_syn:.1f}  "
            f"ports={avg_ports:.1f}±{std_ports:.1f}  "
            f"dests={avg_dests:.1f}±{std_dests:.1f}  "
            f"pkts={avg_pkts:.1f}±{std_pkts:.1f}"
        )
        trained += 1

    conn.commit()
    conn.close()
    print(f"\nBaseline training complete: {trained} trained, {skipped} skipped.")


if __name__ == "__main__":
    import sys
    only_existing = "--only-existing" in sys.argv
    train_baseline(only_existing=only_existing)