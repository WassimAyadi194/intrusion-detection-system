"""
frontend/widgets/kpi/kpi_refresher.py

"""

from PySide6.QtCore import QObject, QTimer, Signal


class KpiRefresher(QObject):
    """
    Emits ``refreshed`` every ``interval_ms`` milliseconds with a dict
    containing the keys produced by ``DetectionEngine.kpi_snapshot()``:

        alerts_60s    : int
        active_hosts  : int
        engine_q      : int
        collector_q   : int
        capture_state : str
    """

    refreshed = Signal(dict)

    def __init__(self, engine, interval_ms: int = 1000, parent=None):
        super().__init__(parent)
        self._engine = engine

        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)

    def start(self) -> None:
        """Start the polling timer and emit one snapshot immediately."""
        self._poll()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def set_engine(self, engine) -> None:
        """Swap the engine reference (e.g. after a full IDS restart)."""
        self._engine = engine

    def _poll(self) -> None:
        if self._engine is None:
            return
        try:
            snapshot = self._engine.kpi_snapshot()
        except Exception:
            # Never let a backend error crash the UI timer loop.
            return
        self.refreshed.emit(snapshot)