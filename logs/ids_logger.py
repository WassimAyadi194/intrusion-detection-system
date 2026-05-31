# ids_logger.py
"""
Centralised logging configuration for the IDS.

Usage in any module:
    from logs.ids_logger import get_logger
    log = get_logger(__name__)

Streaming logs to the UI:
    from logs.ids_logger import get_log_queue, release_log_queue

    q = get_log_queue()
    try:
        while running:
            ts, level, module, msg = q.get()
    finally:
        release_log_queue(q)

    # Each item is a (ts, level, module, message) tuple.
"""

import logging
import queue
import sqlite3
import sys
import threading
import time

from config import DB_NAME as _DB_NAME

_LOG_FORMAT        = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
_DATE_FORMAT       = "%Y-%m-%d %H:%M:%S"
_DB_BATCH_SIZE     = 50      # flush when this many records are queued
_DB_FLUSH_INTERVAL = 5.0     # flush at least this often (seconds)
_DB_QUEUE_MAXSIZE  = 2_000   # drop records rather than blocking caller
_UI_QUEUE_MAXSIZE  = 500     # per-subscriber cap; oldest record evicted on Full

_configured = False


# ---------------------------------------------------------------------------
# UIStreamHandler — fan-out, in-memory log streaming for the UI layer
# ---------------------------------------------------------------------------

class UIStreamHandler(logging.Handler):
    """
    Fans every log record out to a dynamic set of subscriber queues.

    Records are delivered as ``(ts, level, module, message)`` tuples.
    Delivery uses ``put_nowait``; a slow/full subscriber simply drops the
    record without stalling the logging thread.

    Prefer the module-level helpers ``subscribe_ui`` / ``unsubscribe_ui``
    or ``get_log_queue`` / ``release_log_queue`` over calling this directly.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self._lock: threading.Lock = threading.Lock()
        self._subscribers: dict[queue.Queue, None] = {}

    def subscribe(self, q: queue.Queue) -> None:
        """Register *q*. Calling more than once for the same queue is a no-op."""
        with self._lock:
            self._subscribers[q] = None

    def unsubscribe(self, q: queue.Queue) -> None:
        """Remove *q*. Safe to call even if *q* was never subscribed."""
        with self._lock:
            self._subscribers.pop(q, None)

    @property
    def subscriber_count(self) -> int:
        """Number of currently registered subscriber queues."""
        with self._lock:
            return len(self._subscribers)

    def emit(self, record: logging.LogRecord) -> None:
        ts = time.strftime(_DATE_FORMAT, time.localtime(record.created))
        short_name = record.name.split(".")[-1]
        payload = (ts, record.levelname, short_name, record.getMessage())

        with self._lock:
            targets = list(self._subscribers)

        for q in targets:
            try:
                q.put_nowait(payload)
            except queue.Full:
                # Evict oldest record to keep the queue current, then retry.
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except (queue.Empty, queue.Full):
                    pass


# ---------------------------------------------------------------------------
# _DBHandler — batched async SQLite writer
# ---------------------------------------------------------------------------

class _DBHandler(logging.Handler):
    _INSERT_SQL = """
        INSERT INTO logs (timestamp, level, module, message)
        VALUES (?, ?, ?, ?)
    """

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self._queue: queue.Queue = queue.Queue(maxsize=_DB_QUEUE_MAXSIZE)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._writer_loop,
            daemon=True,
            name="LogDBWriter",
        )
        self._thread.start()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ts = time.strftime(_DATE_FORMAT, time.localtime(record.created))
            short_name = record.name.split(".")[-1]
            self._queue.put_nowait((ts, record.levelname, short_name, record.getMessage()))
        except queue.Full:
            pass  # Drop silently; stdout handler always fires.

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
        """
        batch: list[tuple] = []
        last_flush = time.monotonic()

        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                record = self._queue.get(timeout=0.2)
                batch.append(record)
            except queue.Empty:
                pass

            now = time.monotonic()
            if batch and (len(batch) >= _DB_BATCH_SIZE or (now - last_flush) >= _DB_FLUSH_INTERVAL):
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

        if batch:
            self._flush(batch)

    def _flush(self, batch: list[tuple]) -> None:
        """Write a batch of records to the DB. Errors go to stderr."""
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


# ---------------------------------------------------------------------------
# Module-level singletons and public API
# ---------------------------------------------------------------------------

_db_handler: _DBHandler | None = None
_ui_handler: UIStreamHandler | None = None


def _configure() -> None:
    global _configured, _db_handler, _ui_handler
    if _configured:
        return

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    _db_handler = _DBHandler()
    _ui_handler = UIStreamHandler()

    root = logging.getLogger("ids")
    root.setLevel(logging.DEBUG)
    root.addHandler(stream_handler)
    root.addHandler(_db_handler)
    root.addHandler(_ui_handler)
    root.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'ids' namespace.

    Pass ``__name__`` from the calling module:
        log = get_logger(__name__)  # → 'ids.packet_capture'
    """
    _configure()
    short = name.split(".")[-1] if "." in name else name
    return logging.getLogger(f"ids.{short}")


def get_log_queue() -> queue.Queue:
    """
    Create and return a new per-consumer UI log queue (maxsize=_UI_QUEUE_MAXSIZE).

    Records are ``(ts, level, module, message)`` tuples.  Call
    ``release_log_queue`` when done to avoid a memory leak.
    """
    _configure()
    assert _ui_handler is not None
    q: queue.Queue = queue.Queue(maxsize=_UI_QUEUE_MAXSIZE)
    _ui_handler.subscribe(q)
    return q


def release_log_queue(q: queue.Queue) -> None:
    """Unsubscribe *q* and drain any buffered records."""
    if _ui_handler is not None:
        _ui_handler.unsubscribe(q)
    try:
        while True:
            q.get_nowait()
    except queue.Empty:
        pass


def subscribe_ui(q: queue.Queue) -> None:
    """Register *q* to receive ``(ts, level, module, message)`` log tuples."""
    _configure()
    assert _ui_handler is not None
    _ui_handler.subscribe(q)


def unsubscribe_ui(q: queue.Queue) -> None:
    """Remove *q* from the UI subscriber set. Safe to call at any time."""
    if _ui_handler is not None:
        _ui_handler.unsubscribe(q)


def shutdown() -> None:
    """
    Flush and close the DB handler cleanly.

    Call from ``main.py`` during graceful shutdown so in-flight records are
    not lost:
        from logs.ids_logger import shutdown as shutdown_logger
        shutdown_logger()
    """
    if _db_handler is not None:
        _db_handler.close()