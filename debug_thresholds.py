"""
debug_thresholds.py
-------------------
Drop this in your project root and run:

    python debug_thresholds.py

It monkey-patches PacketThresholdDetector and AnomalyDetector so every threshold
calculation and every alert-fire decision is printed with the exact values involved.
No real packets are needed — it replays synthetic ones against your live baseline DB.

Adjust HOSTS_TO_PROBE to the IPs you want to trace.
"""

import time
import sqlite3
from unittest.mock import patch

# ── config ────────────────────────────────────────────────────────────────────
from config import DB_NAME

HOSTS_TO_PROBE = [
    "192.168.1.14",
    "31.13.69.35",
    "31.13.69.13",
    "41.226.49.147",
    "31.13.69.22",
    "127.0.0.1",
]

# Simulated per-host burst sizes to reproduce the tab-refresh scenario.
# Keys: host IP  →  (packet_burst, syn_count, unique_ports, unique_dests)
SIMULATED_BURST: dict[str, tuple[int, int, int, int]] = {
    "192.168.1.14":   (50,   8,  5,  3),
    "31.13.69.35":    (50,   6,  4,  2),
    "31.13.69.13":    (50,   6,  4,  2),
    "41.226.49.147":  (300, 20, 10,  5),
    "31.13.69.22":    (130, 15,  8,  4),
    "127.0.0.1":      (80,  12, 55,  6),
}

SEP = "─" * 72

# ── helpers ───────────────────────────────────────────────────────────────────

def fetch_baseline(host_ip: str) -> dict | None:
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM baseline WHERE host_ip = ?", (host_ip,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except sqlite3.Error as e:
        print(f"  [DB ERROR] {e}")
        return None


def fetch_packet_baseline(host_ip: str) -> dict | None:
    """baseline_reader.get_all_baselines() equivalent for a single host."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Adjust column names if your schema differs.
        cur.execute(
            "SELECT host_ip, avg_packet_count, std_packet_count FROM baseline WHERE host_ip = ?",
            (host_ip,),
        )
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except sqlite3.Error as e:
        print(f"  [DB ERROR] {e}")
        return None


# ── PacketThresholdDetector threshold trace ───────────────────────────────────

_K             = 5.0
_MIN_GLOBAL_THRESHOLD = 600
STATIC_FALLBACK       = 3000


def trace_packet_threshold(host_ip: str, burst_size: int) -> None:
    print(f"\n{'━'*72}")
    print(f"  PacketThresholdDetector  —  {host_ip}")
    print(SEP)

    row = fetch_packet_baseline(host_ip)

    if row is None:
        print(f"  baseline row : NOT FOUND  →  using static fallback = {STATIC_FALLBACK}")
        threshold = STATIC_FALLBACK
    else:
        mean = float(row.get("avg_packet_count") or 0.0)
        std  = float(row.get("std_packet_count") or 0.0)
        dynamic   = mean + (_K * std)
        threshold = max(int(dynamic), _MIN_GLOBAL_THRESHOLD)

        print(f"  avg_packet_count : {mean:.4f}")
        print(f"  std_packet_count  : {std:.4f}")
        print(f"  formula          : mean + (K={_K} × std)")
        print(f"                   = {mean:.4f} + ({_K} × {std:.4f})")
        print(f"                   = {dynamic:.4f}")
        print(f"  _MIN_GLOBAL      : {_MIN_GLOBAL_THRESHOLD}")
        print(f"  effective thresh : max({int(dynamic)}, {_MIN_GLOBAL_THRESHOLD}) = {threshold}")

    print(f"\n  simulated burst  : {burst_size} packets in 10s window")

    if burst_size >= threshold:
        print(f"  ⚠️  WOULD FIRE   : {burst_size} ≥ {threshold}  ← this is your false positive")
    else:
        print(f"  ✅  NO ALERT     : {burst_size} < {threshold}  (headroom: {threshold - burst_size})")

    # Sanity: what burst size would actually be needed to fire?
    print(f"\n  packets needed to fire alert : {threshold}")

    if row is not None and mean == 0.0 and std == 0.0:
        print(
            f"\n  ⚠️  WARNING: both mean and std are 0 — baseline may not have been "
            f"trained for this host yet. Effective threshold falls back to "
            f"_MIN_GLOBAL_THRESHOLD ({_MIN_GLOBAL_THRESHOLD})."
        )


# ── AnomalyDetector threshold trace ──────────────────────────────────────────

Z_THRESHOLD = 3.0
STD_FLOOR   = 1.0
# Must mirror anomaly_detector.py exactly.
_MIN_DELTAS = {
    "syn_count":           20, 
    "unique_ports":        10, 
    "unique_destinations":  8,   
    "packet_count":        40,
}
_MIN_BASELINE_SAMPLES = 30  # hosts with fewer samples are skipped entirely

ANOMALY_METRICS = [
    # (metric_key, baseline_mean_col, baseline_std_col)
    ("syn_count",           "avg_syn",                 "std_syn"),
    ("unique_ports",        "avg_unique_ports",        "std_unique_ports"),
    ("unique_destinations", "avg_unique_destinations", "std_unique_destinations"),
    ("packet_count",        "avg_packet_count",        "std_packet_count"),
]

SEVERITY_LEVELS = [
    (4.0, "CRITICAL"),
    (3.0, "HIGH"),
    (2.5, "MEDIUM"),
]


def _severity(z: float) -> str:
    for thresh, label in SEVERITY_LEVELS:
        if abs(z) >= thresh:
            return label
    return "LOW"


def trace_anomaly_detector(
    host_ip: str,
    syn_count: int,
    unique_ports: int,
    unique_dests: int,
    packet_count: int,
) -> None:
    print(f"\n{'━'*72}")
    print(f"  AnomalyDetector  —  {host_ip}")
    print(SEP)

    baseline = fetch_baseline(host_ip)
    if baseline is None:
        print(f"  baseline row : NOT FOUND  →  no anomaly alerts possible for this host")
        return

    # Mirror the _MIN_BASELINE_SAMPLES guard in anomaly_detector.py.
    sample_count = baseline.get("sample_count", None)
    if sample_count is None:
        print(f"  ⚠️  WARNING: 'sample_count' column missing from baseline table.")
        print(f"           Add it in baseline_trainer.py or the thin-baseline guard")
        print(f"           will silence ALL anomaly detection (defaults to 0 < 30).")
        print()
    elif sample_count < _MIN_BASELINE_SAMPLES:
        print(f"  sample_count : {sample_count}  <  _MIN_BASELINE_SAMPLES={_MIN_BASELINE_SAMPLES}")
        print(f"  ✅  SKIPPED  : baseline too thin — no alerts will fire for this host")
        return
    else:
        print(f"  sample_count : {sample_count}  ≥  _MIN_BASELINE_SAMPLES={_MIN_BASELINE_SAMPLES}  ✅")
    print()

    observed = {
        "syn_count":           syn_count,
        "unique_ports":        unique_ports,
        "unique_destinations": unique_dests,
        "packet_count":        packet_count,
    }

    for metric, mean_col, std_col in ANOMALY_METRICS:
        value = observed[metric]
        avg   = float(baseline.get(mean_col) or 0.0)
        std   = float(baseline.get(std_col)  or 0.0)
        eff_std   = max(std, STD_FLOOR)
        z         = (value - avg) / eff_std
        min_delta = _MIN_DELTAS.get(metric, 10)
        delta     = abs(value - avg)

        print(f"\n  metric           : {metric}")
        print(f"  observed value   : {value}")
        print(f"  baseline mean    : {avg:.4f}  (col: {mean_col})")
        print(f"  baseline std     : {std:.4f}  (col: {std_col})")
        print(f"  effective std    : max({std:.4f}, STD_FLOOR={STD_FLOOR}) = {eff_std:.4f}")
        print(f"  z-score          : ({value} - {avg:.4f}) / {eff_std:.4f} = {z:.4f}")
        print(f"  Z_THRESHOLD      : {Z_THRESHOLD}   →  |z| {abs(z):.4f} {'≥' if abs(z) >= Z_THRESHOLD else '<'} {Z_THRESHOLD}  {'PASS' if abs(z) >= Z_THRESHOLD else 'BLOCK (z too low)'}")
        print(f"  abs delta        : |{value} - {avg:.4f}| = {delta:.4f}")
        print(f"  min_delta        : {min_delta}            →  delta {delta:.4f} {'≥' if delta >= min_delta else '<'} {min_delta}  {'PASS' if delta >= min_delta else 'BLOCK (delta too small)'}")

        z_pass     = abs(z) >= Z_THRESHOLD
        delta_pass = delta >= min_delta

        if z_pass and delta_pass:
            sev = _severity(z)
            print(f"  ⚠️  WOULD FIRE   : severity={sev}")
        elif not z_pass:
            print(f"  ✅  NO ALERT     : z-score {abs(z):.2f} below threshold {Z_THRESHOLD}")
        else:
            print(f"  ✅  NO ALERT     : absolute delta {delta:.2f} below min_delta {min_delta}")

        # Show exactly what burst would trigger this metric
        trigger_z_val     = avg + Z_THRESHOLD * eff_std
        trigger_delta_val = avg + min_delta
        trigger_val       = max(trigger_z_val, trigger_delta_val)
        print(f"  min value to fire: max(z-trigger={trigger_z_val:.1f}, delta-trigger={trigger_delta_val:.1f}) = {trigger_val:.1f}")

        if avg == 0.0 and std == 0.0:
            print(
                f"  ⚠️  WARNING: mean and std both 0 — baseline may be untrained. "
                f"z = value / STD_FLOOR = {value} / {STD_FLOOR} = {z:.2f}"
            )


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + "═" * 72)
    print("  THRESHOLD DEBUG REPORT")
    print(f"  DB: {DB_NAME}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 72)

    for host in HOSTS_TO_PROBE:
        burst = SIMULATED_BURST.get(host, (50, 8, 5, 3))
        pkt_burst, syn, ports, dests = burst

        trace_packet_threshold(host, pkt_burst)
        trace_anomaly_detector(host, syn, ports, dests, pkt_burst)

    print("\n" + "═" * 72)
    print("  LEGEND")
    print(SEP)
    print("  ⚠️  WOULD FIRE  — the simulated burst crosses this detector's threshold")
    print("  ✅  NO ALERT    — the simulated burst is safely below threshold")
    print("  WARNING        — baseline data is missing / zero (untrained host)")
    print(
        "\n  'min value to fire' shows the EXACT observed value needed to trigger"
        "\n  an alert for each metric — compare against your real tab-refresh counts."
    )
    print("═" * 72 + "\n")


if __name__ == "__main__":
    main()