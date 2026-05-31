"""
Entry point for the IDS frontend.

Run from the project root:
    python -m frontend.app
"""
import sys
import signal
import queue
import threading
import importlib

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QShortcut, QKeySequence

from frontend.main_window import MainWindow
import frontend.styles as styles
import frontend.theme as theme
from PySide6.QtCore import qInstallMessageHandler, QtMsgType

def qt_message_handler(mode, context, message):
    if mode == QtMsgType.QtWarningMsg and "QFont::setPointSize" in message:
        return
    import sys
    print(message, file=sys.stderr)


def apply_styles(app):
    importlib.reload(theme)
    importlib.reload(styles)
    app.setStyleSheet("")
    app.setStyleSheet(styles.STYLESHEET)


from engine.launcher import start_ids as _start_ids, stop_ids as _stop_ids


def main():
    qInstallMessageHandler(qt_message_handler)
    app = QApplication(sys.argv)

    # Set application metadata AFTER QApplication is constructed.
    # Calling the static setters before QApplication(sys.argv) can cause
    # Qt's style / font subsystem to materialise a transient top-level
    # QWidget (visible as a tiny flickering window with title "HYBRID IDS")
    # before the application object exists to own it.
    app.setApplicationName("HYBRID IDS")
    app.setOrganizationName("IDS")

    

    # Load persisted tuning values before the engine (and its detectors) are
    # instantiated.  This overwrites the module-level defaults in config.py
    # with whatever the user last applied via the Settings panel.
    from config import apply_saved_settings
    apply_saved_settings()

    # Shared queue: DetectionEngine → AlertFeed (thread-safe)
    alert_queue: queue.Queue = queue.Queue()

    # Subscribe a UI log queue BEFORE starting the engine so we catch all startup logs.
    from logs.ids_logger import get_log_queue
    log_queue = get_log_queue()

    try:
        ids = _start_ids(alert_queue)
    except Exception as e:
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.critical(None, "Startup Error", str(e))
        sys.exit(1)

    window = MainWindow(alert_queue=alert_queue, log_queue=log_queue, engine=ids["engine"])
    window.show()
    apply_styles(app)

    # Ctrl+R → reload styles live
    shortcut = QShortcut(QKeySequence("Ctrl+R"), window)
    shortcut.activated.connect(lambda: apply_styles(app))

    # Make Ctrl+C in the terminal trigger a clean Qt shutdown.
    # Qt on Windows swallows SIGINT by default; this restores the expected
    # behaviour without touching any IDS internals.
    signal.signal(signal.SIGINT, lambda *_: app.quit())

    exit_code = app.exec()

    _stop_ids(ids)

    sys.exit(exit_code)

if __name__ == "__main__":
    main()