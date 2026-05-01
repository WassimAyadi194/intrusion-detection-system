"""
frontend/widgets/hosts/host_refresher.py

"""

from PySide6.QtCore import QObject, QTimer, Signal
from logs.ids_logger import get_logger

log = get_logger(__name__)

class HostRefresher(QObject):
    """
    Emits ``refreshed`` every ``interval_ms`` milliseconds with the dict
    returned by ``DetectionEngine.host_metrics_snapshot()``.

    """

    # Emitted on every successful poll.  Payload: dict[str, dict]
    refreshed = Signal(dict)

    def __init__(self, engine, interval_ms: int = 1000, parent=None):
        super().__init__(parent)
        self._engine = engine

        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)

    def start(self) -> None:
        if self._timer.isActive():
            return
        self._poll()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def set_engine(self, engine) -> None:
        self._engine = engine


    def _poll(self) -> None:
        """Fetch a snapshot and emit it; silently drop on any error."""
        if self._engine is None:
            return
        try:
            snapshot: dict[str, dict] = self._engine.host_metrics_snapshot()
        except Exception as e:
            log.error(f"HostRefresher poll failed: {e}")
            return
        self.refreshed.emit(snapshot)
