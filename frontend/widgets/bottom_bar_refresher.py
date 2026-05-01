"""
frontend/widgets/bottom_bar_refresher.py

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QTimer, Signal

if TYPE_CHECKING:
    # Import only for type checking — avoids a hard runtime dependency on the
    # capturing package from within the frontend layer.
    from capturing.packet_capture import PacketCapture


class BottomBarRefresher(QObject):
    """
    Polls :class:`PacketCapture` state every second and emits a status dict.

    """

    signal: Signal = Signal(dict)

    def __init__(self, packet_capture: PacketCapture | None = None,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)

        self._packet_capture: PacketCapture | None = packet_capture

        self._timer = QTimer(self)
        self._timer.setInterval(1000)          # 1 000 ms — matches KPI pattern
        self._timer.timeout.connect(self._on_tick)

    def start(self) -> None:
        """Start periodic polling.  Safe to call multiple times."""
        if not self._timer.isActive():
            self._timer.start()

    def stop(self) -> None:
        """Stop periodic polling.  Safe to call even if not running."""
        self._timer.stop()

    def set_packet_capture(self, packet_capture: PacketCapture | None) -> None:
        """
        Swap the :class:`PacketCapture` instance at runtime.

        """
        self._packet_capture = packet_capture

    def _on_tick(self) -> None:
        """
        Read PacketCapture state and emit the status dict.

        """
        pc = self._packet_capture
        if pc is None:
            return

        # last_tick
        try:
            wall_time = pc.last_heartbeat_wall_time   # datetime | None
            last_tick: str = (
                wall_time.strftime("%H:%M:%S") if wall_time is not None else "—"
            )
        except AttributeError:
            last_tick = "—"

        # --- stall -------------------------------------------------------
        # stall_detected is a computed property; guard against AttributeError
        # for the same defensive reason as above.
        try:
            stall: bool = bool(pc.stall_detected)
        except AttributeError:
            stall = False

        self.signal.emit({"last_tick": last_tick, "stall": stall})