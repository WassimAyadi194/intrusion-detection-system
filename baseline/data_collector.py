# data_collector.py
import sqlite3
import time
import queue
import threading
from collections import defaultdict

from logs.ids_logger import get_logger
from config import DB_NAME, DB_MAX_RETRIES, DB_RETRY_DELAY, LIVE_METRICS_RETENTION_HOURS, WINDOW_SIZE, COLLECTOR_BATCH_MAX

log = get_logger(__name__)

def _make_host_entry() -> dict:
    return {
        "syn_count": 0,
        "unique_ports": set(),
        "unique_destinations": set(),
        "packet_count": 0,
    }


class LiveMetricsCollector:
    def __init__(self, packet_capture, engine):
        self.packet_capture = packet_capture
        self.engine         = engine
        self._stop_event    = threading.Event()
        self.host_data      = defaultdict(_make_host_entry)
        self.window_start   = time.time()

        # Snapshot of the most-recently completed 10-second window.
        self._last_window: dict[str, dict] = {}
 
        self._prune_old_metrics()

    def process_packet(self, pkt):
        if "IP" not in pkt or "TCP" not in pkt:
            return

        src   = pkt["IP"].src
        dst   = pkt["IP"].dst
        dport = pkt["TCP"].dport
        flags = pkt["TCP"].flags
        data  = self.host_data[src]

        data["packet_count"] += 1

        if flags & 0x02:  # SYN
            data["syn_count"] += 1

        data["unique_ports"].add(dport)
        data["unique_destinations"].add(dst)

    def flush_window(self):
        flush_start = time.monotonic()

        # Atomic swap: packets arriving during the DB write accumulate in the
        # new dict instead of being cleared after a potentially slow write.
        old_data = self.host_data
        self.host_data = defaultdict(_make_host_entry)

        conn   = self._db_connect()
        cursor = conn.cursor() if conn else None
        timestamp = int(time.time())

        snapshot = {
            host_ip: {
                "syn_count":           m["syn_count"],
                "unique_ports":        len(m["unique_ports"]),
                "unique_destinations": len(m["unique_destinations"]),
                "packet_count":        m["packet_count"],
            }
            for host_ip, m in old_data.items()
        }

        self._last_window = snapshot   # atomic reference replacement

        if cursor is not None:
            try:
                for host_ip, m in snapshot.items():
                    cursor.execute("""
                        INSERT INTO live_metrics
                            (host_ip, timestamp, syn_count, unique_ports,
                             unique_destinations, packet_count)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (host_ip, timestamp,
                          m["syn_count"], m["unique_ports"],
                          m["unique_destinations"], m["packet_count"]))
                conn.commit()
            except sqlite3.Error as exc:
                log.error(
                    "DB write failed — live_metrics not persisted for window "
                    "(n=%d hosts). Error: %s",
                    len(snapshot), exc,
                )
            finally:
                conn.close()

        for host_ip, m in snapshot.items():
            self.engine.process_anomaly(
                host_ip=host_ip,
                syn_count=m["syn_count"],
                unique_ports=m["unique_ports"],
                unique_destinations=m["unique_destinations"],
                packet_count=m["packet_count"],
            )

        flush_duration = time.monotonic() - flush_start
        if flush_duration > WINDOW_SIZE:
            log.warning(
                "flush_window() took %.2fs — exceeds WINDOW_SIZE (%ds); "
                "window timing is drifting",
                flush_duration, WINDOW_SIZE,
            )
        return flush_duration

    # ── Startup cleanup ───────────────────────────────────────────────────────
    def _prune_old_metrics(self) -> None:
        cutoff = int(time.time()) - LIVE_METRICS_RETENTION_HOURS * 3600
        conn = self._db_connect()
        if conn is None:
            log.warning("Startup cleanup skipped — could not open DB connection.")
            return
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM live_metrics WHERE timestamp < ?", (cutoff,)
            )
            deleted = cursor.rowcount
            conn.commit()
            if deleted:
                log.info(
                    "Startup cleanup: removed %d live_metrics rows older than %dh.",
                    deleted, LIVE_METRICS_RETENTION_HOURS,
                )
            else:
                log.debug("Startup cleanup: no stale live_metrics rows found.")
        except sqlite3.Error as exc:
            log.error("Startup cleanup failed: %s", exc)
        finally:
            conn.close()

    def _db_connect(self):
        last_exc: Exception | None = None
        for attempt in range(1 + DB_MAX_RETRIES):
            try:
                return sqlite3.connect(DB_NAME, timeout=5)
            except sqlite3.Error as exc:
                last_exc = exc
                if attempt < DB_MAX_RETRIES:
                    time.sleep(DB_RETRY_DELAY)

        log.error(
            "DB connect failed after %d attempts — live_metrics write skipped. "
            "Error: %s",
            1 + DB_MAX_RETRIES, last_exc,
        )
        return None

    def run(self):
        log.info("Live metrics collector started (window=%ds)", WINDOW_SIZE)
        while not self._stop_event.is_set():
            try:
                first = self.packet_capture.collector_queue.get(timeout=1)
            except queue.Empty:
                # No packets — check window boundary and loop.
                elapsed = time.time() - self.window_start
                if elapsed >= WINDOW_SIZE:
                    flush_duration = self.flush_window()
                    self.window_start = time.time() - flush_duration
                continue

            self.process_packet(first)
            drained = 1

            while drained < COLLECTOR_BATCH_MAX:
                try:
                    pkt = self.packet_capture.collector_queue.get_nowait()
                    self.process_packet(pkt)
                    drained += 1
                except queue.Empty:
                    break

            # ── Window flush ──────────────────────────────────────────────────
            elapsed = time.time() - self.window_start
            if elapsed >= WINDOW_SIZE:
                flush_duration = self.flush_window()
                self.window_start = time.time() - flush_duration

        log.info("Live metrics collector stopping.")

    def stop(self):
        self._stop_event.set()
        try:
            if self.host_data:
                self.flush_window()
        except Exception as exc:
            log.warning("Final flush failed on shutdown: %s", exc)