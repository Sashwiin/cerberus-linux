"""Cerberus native desktop app — the real web dashboard, in a native window.

Earlier builds of this file tried to reimplement the dashboard as hand-built
Qt widgets. That meant maintaining two UIs (and, in practice, drifting out of
sync with each other's colors, copy, and even features — the VM controls
existed in one and not the other). This version stops doing that: it *is*
the web dashboard (`static/index.html`, served by `cerberus.web`), rendered
in a `QWebEngineView` inside a plain native window. No browser tab, no
address bar, no "open a browser" step — just a window with an icon like any
other native app. One UI, one place it can drift out of date: nowhere.

Privilege is split exactly the way `packaging/AppRun` (the AppImage
launcher) already does it, for the same reason: Cerberus needs root for
mount/cgroup/seccomp, but a Qt/WebEngine window has no business running as
root. So only the sandbox SERVER (`cerberus.web`) is elevated, as a separate
subprocess, via `pkexec` (one graphical password prompt) or `sudo`; this
window stays an ordinary user process that just points its browser view at
127.0.0.1 once the server answers.

Needs PyQt5 *and* PyQtWebEngine — see NATIVE.md for the exact packages.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from shutil import which

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWebEngineWidgets import QWebEngineView

from . import __version__

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("CERBERUS_PORT", "8787"))
URL = f"http://127.0.0.1:{PORT}/"
STARTUP_TIMEOUT_S = 90

# Same palette the dashboard itself uses (static/index.html's :root block),
# just for the thin "starting up" screen shown before the real page loads.
CANVAS = "#f6f8fb"
INK = "#0f172a"
DIM = "#64748b"
CYAN = "#0284c7"


def _which(name: str) -> bool:
    return which(name) is not None


def _server_reachable() -> bool:
    try:
        urllib.request.urlopen(URL, timeout=1.5)
        return True
    except Exception:
        return False


def _start_server() -> subprocess.Popen | None:
    """Elevate the sandbox server if nothing is already answering on PORT.

    Returns the Popen handle if this call launched it (so the window can
    stop it again on close), or None if a server was already up -- in which
    case this window is just a second client of it, not its owner, and
    leaves it running when it closes.
    """
    if _server_reachable():
        return None

    pyexe = sys.executable or "python3"
    server_cmd = [pyexe, "-B", "-m", "cerberus.web",
                  "--host", "127.0.0.1", "--port", str(PORT)]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.dirname(HERE) + os.pathsep + env.get("PYTHONPATH", "")

    if os.geteuid() == 0:
        cmd = server_cmd
    elif _which("pkexec") and (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        cmd = ["pkexec", "env", f"PYTHONPATH={env['PYTHONPATH']}", *server_cmd]
    elif _which("sudo"):
        cmd = ["sudo", "-E", *server_cmd]
    else:
        raise RuntimeError("need root to start the sandbox server: no pkexec or sudo found")

    return subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


class CerberusWindow(QtWidgets.QMainWindow):
    def __init__(self, server_proc: subprocess.Popen | None):
        super().__init__()
        self._server_proc = server_proc
        self._started_at = time.time()
        self.setWindowTitle(f"Cerberus v{__version__}")
        self.resize(1440, 920)
        self.setMinimumSize(1000, 640)
        self.setStyleSheet(f"QMainWindow {{ background: {CANVAS}; }}")

        # Shown until the (possibly just-elevated) server answers, so the
        # window isn't just blank/frozen-looking during a pkexec prompt or a
        # slow server start.
        self.status = QtWidgets.QLabel(
            "Starting Cerberus…\n\n"
            "waiting for the privileged sandbox server "
            "(mount / cgroup / seccomp need root)\n"
            "approve the password prompt if one appears"
        )
        self.status.setAlignment(QtCore.Qt.AlignCenter)
        self.status.setWordWrap(True)
        self.status.setStyleSheet(
            f"color:{DIM}; font-size:12pt; font-weight:600; padding:60px; background:transparent;"
        )
        self.setCentralWidget(self.status)

        self.view: QWebEngineView | None = None
        self._poll = QtCore.QTimer(self)
        self._poll.timeout.connect(self._check_ready)
        self._poll.start(300)
        self._check_ready()  # in case it's already up (common: reusing a running server)

    def _check_ready(self) -> None:
        if self.view is not None:
            self._poll.stop()
            return
        # If we elevated the server ourselves and it already died (bad
        # password, no polkit agent, etc.), stop waiting and say so instead
        # of polling silently until STARTUP_TIMEOUT_S.
        if self._server_proc is not None and self._server_proc.poll() is not None:
            self._poll.stop()
            err = ""
            if self._server_proc.stderr is not None:
                err = self._server_proc.stderr.read().decode("utf-8", "replace").strip()
            self._show_error(
                "The sandbox server didn't start"
                + (f":\n{err[:400]}" if err else " (authorization cancelled?).")
            )
            return
        if _server_reachable():
            self._poll.stop()
            self.view = QWebEngineView()
            self.view.load(QtCore.QUrl(URL))
            self.setCentralWidget(self.view)
            return
        if time.time() - self._started_at > STARTUP_TIMEOUT_S:
            self._poll.stop()
            self._show_error(
                f"No response from {URL} after {STARTUP_TIMEOUT_S}s. "
                "Check that qemu/pkexec aren't stuck on a prompt, or run\n"
                "sudo python3 -m cerberus.web\nin a terminal to see the real error."
            )

    def _show_error(self, message: str) -> None:
        self.status.setStyleSheet(
            "color:#dc2626; font-size:11pt; font-weight:600; padding:60px; background:transparent;"
        )
        self.status.setText("Cerberus couldn't start\n\n" + message)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        proc = self._server_proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        event.accept()


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    server_proc = None
    try:
        server_proc = _start_server()
    except RuntimeError as exc:
        QtWidgets.QMessageBox.critical(None, "Cerberus", str(exc))
        return 1

    win = CerberusWindow(server_proc)
    win.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
