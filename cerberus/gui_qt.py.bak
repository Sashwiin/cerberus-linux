"""Cerberus native desktop GUI — PySide6 QtWebEngine window.

A standalone native Linux desktop window hosting the clinical Stitch UI
with zero external web browser dependencies. It runs as an ordinary user,
talking directly to an ephemeral in-process loopback supervisor for local
sandboxing or disposable QEMU VM execution.
"""

from __future__ import annotations

import os
import sys
import threading
from http.server import ThreadingHTTPServer

# Avoid Chromium zygote/namespace collisions on modern Linux kernels/containers
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox"

from PySide6.QtCore import QUrl
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMainWindow
from PySide6.QtWebEngineWidgets import QWebEngineView

from .web import DashboardState, make_handler


class CerberusMainWindow(QMainWindow):
    def __init__(self, port: int, state: DashboardState):
        super().__init__()
        self.port = port
        self.state = state

        self.setWindowTitle("Cerberus — Runtime Defense")
        self.resize(1320, 860)
        self.setMinimumSize(980, 640)

        self.view = QWebEngineView(self)
        self.setCentralWidget(self.view)

        # Load the local dashboard interface
        self.view.load(QUrl(f"http://127.0.0.1:{port}/"))

    def closeEvent(self, event):
        # Cleanly terminate any running disposable VM overlay on window close
        try:
            self.state.stop_vm()
        except Exception:
            pass
        event.accept()


def main() -> int:
    state = DashboardState()
    # Ephemeral loopback port (bound exclusively to 127.0.0.1, private to the user)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    port = httpd.server_address[1]

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Cerberus")

    win = CerberusMainWindow(port, state)
    win.show()

    ret = app.exec()
    try:
        httpd.shutdown()
        state.stop_vm()
    except Exception:
        pass
    return ret


if __name__ == "__main__":
    raise SystemExit(main())
