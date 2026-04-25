# ids_logger.py
"""
Centralised logging configuration for the IDS.

Usage in any module:
    from logs.ids_logger import get_logger
    log = get_logger(__name__)

Format:
    2024-01-15 12:34:56 [WARNING ] packet_capture     — engine_queue depth: 847 — processing lag

Log levels used across the system:
    INFO    — startup/shutdown, normal operational milestones
    WARNING — degraded conditions (stall, queue depth, flush overtime, cache miss)
    ERROR   — failures with data loss (DB write failed, alerts dropped)
    CRITICAL — unrecoverable failures (capture dead after all retries)

DB logging:
    INFO and above are written asynchronously to the `logs` table in ids.db.
    A background thread drains an internal queue and flushes in batches of up
    to _DB_BATCH_SIZE records, or every _DB_FLUSH_INTERVAL seconds — whichever
    comes first.  The hot packet path is never blocked by a DB write.
    DEBUG records are intentionally excluded from the DB to avoid queue bloat.
"""

import logging
import queue
import sqlite3
import sys
import threading
import time

from config import DB_NAME as _DB_NAME

_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)-20s — %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_DB_BATCH_SIZE     = 50     # flush when this many records are queued
_DB_FLUSH_INTERVAL = 5.0    # flush at least this often (seconds)
# Internal queue capacity: 2 000 records ≈ ~40 full batches.
# If the writer falls behind, new records are dropped rather than
# blocking the caller — the stdout handler always remains intact.
_DB_QUEUE_MAXSIZE  = 2_000

_configured = False

class _DBHandler(logging.Handler):
    _INSERT_SQL = """
        INSERT INTO logs (timestamp, level, module, message)
        VALUES (?, ?, ?, ?)
    """

    def __init__(self):
        super().__init__(level=logging.INFO)  # DEBUG is intentionally excluded
        self._queue: queue.Queue = queue.Queue(maxsize=_DB_QUEUE_MAXSIZE)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._writer_loop,
            daemon=True,
            name="LogDBWriter",
        )
        self._thread.start()

    def emit(self, record: logging.LogRecord) -> None:
        """
        Called by the logging framework on every matching log call.
        Puts a minimal tuple onto the queue; never blocks the caller.
        """
        try:
            # Pre-format the timestamp here so the writer thread doesn't need
            # to touch the LogRecord (avoids any thread-safety edge cases).
            ts = time.strftime(_DATE_FORMAT, time.localtime(record.created))
            short_name = record.name.split(".")[-1]
            self._queue.put_nowait((ts, record.levelname, short_name, record.getMessage()))
        except queue.Full:
            # Queue is saturated — drop silently rather than stalling the caller.
            # The record still reaches stdout via the StreamHandler.
            pass

    def close(self) -> None:
        """Flush remaining records then stop the background thread."""
        self._stop_event.set()
        self._thread.join(timeout=10)
        super().close()

    def _writer_loop(self) -> None:
        """
        Drain the queue in batches.  Wakes up when:
          (a) _DB_BATCH_SIZE records are ready, or
          (b) _DB_FLUSH_INTERVAL seconds have elapsed since the last flush.
        This keeps both latency and DB round-trips low.
        """
        batch: list[tuple] = []
        last_flush = time.monotonic()

        while not self._stop_event.is_set() or not self._queue.empty():
            # Block briefly waiting for the next record.
            try:
                record = self._queue.get(timeout=0.2)
                batch.append(record)
            except queue.Empty:
                pass

            now = time.monotonic()
            time_to_flush = (now - last_flush) >= _DB_FLUSH_INTERVAL
            size_to_flush  = len(batch) >= _DB_BATCH_SIZE

            if batch and (size_to_flush or time_to_flush):
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

        # Final drain after stop is requested.
        if batch:
            self._flush(batch)

    def _flush(self, batch: list[tuple]) -> None:
        """Write a batch of records to the DB. Errors are printed to stderr
        (we cannot use the logger here — that would cause infinite recursion)."""
        try:
            conn = sqlite3.connect(_DB_NAME, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executemany(self._INSERT_SQL, batch)
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            print(
                f"[LogDBWriter] DB flush failed — {len(batch)} log records lost. "
                f"Error: {exc}",
                file=sys.stderr,
            )

_db_handler: _DBHandler | None = None

def _configure() -> None:
    global _configured, _db_handler
    if _configured:
        return

    # ── stdout handler (all levels, always present) ──────────────────────────
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    # ── async DB handler (INFO and above only) ───────────────────────────────
    _db_handler = _DBHandler()

    root = logging.getLogger("ids")
    root.setLevel(logging.DEBUG)
    root.addHandler(stream_handler)
    root.addHandler(_db_handler)
    # Prevent log records from bubbling up to the root logger's default handler
    # (which would duplicate lines if basicConfig was called elsewhere).
    root.propagate = False

    _configured = True

def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'ids' namespace.

    Pass __name__ from the calling module so log lines show the module name.
    e.g. get_logger(__name__) in packet_capture.py → logger named 'ids.packet_capture'
    """
    _configure()
    short = name.split(".")[-1] if "." in name else name
    return logging.getLogger(f"ids.{short}")

def shutdown() -> None:
    """
    Flush and close the DB handler cleanly.
    Call this from main.py during graceful shutdown *before* the process exits,
    so in-flight log records are not lost.

        from logs.ids_logger import shutdown as shutdown_logger
        shutdown_logger()
    """
    if _db_handler is not None:
        _db_handler.close()