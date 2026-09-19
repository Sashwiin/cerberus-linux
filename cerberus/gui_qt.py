"""Cerberus native desktop GUI — PyQt5, no web anything.

This is the Qt sibling of `cerberus.gui` (the Tkinter app): same real
architecture, same privileged-helper subprocess protocol, same disposable-VM
path, just a different toolkit and two extra panels (Timeline & History,
Architecture & System) that the web dashboard also has. Every field in every
panel here is produced by an actual sandbox run or read live from
`cerberus.introspect` — nothing on this window is mocked.

Threading model, deliberately identical to the Tkinter app: worker threads
only ever touch a `queue.Queue`; a `QTimer` on the main (GUI) thread drains
that queue every 60ms and is the only code that touches widgets. That keeps
every Qt call on the GUI thread, which is Qt's one hard rule, without needing
cross-thread signals for every event kind.

Needs PyQt5 (`python3-pyqt5` on Debian/Ubuntu, `python3-qt5` on Fedora,
`pip install PyQt5` otherwise). See NATIVE.md.
"""

from __future__ import annotations

import base64
import html
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QTimer

from . import __version__, introspect

# ---- palette -----------------------------------------------------------
# Exactly the "Architectural Glassmorphism" palette the web dashboard uses
# (see the :root block in static/index.html) -- same tokens, same hex
# values, so the native window and the browser dashboard read as one
# product instead of two different apps that happen to share a backend.
# Qt style sheets can't do backdrop-filter blur or the page's grid-line
# background, so panels are flat near-white instead of frosted glass --
# everything else (colors, borders, radii) matches exactly.
BG = "#f6f8fb"          # --canvas
PANEL = "#ffffff"       # card / glass surface (flat, no blur, in Qt)
PANEL2 = "#eef2f6"      # --canvas2 -- header bar, inactive tabs, table heads
LINE = "#dde3ea"        # --line, flattened onto white
INK = "#0f172a"         # --ink
DIM = "#64748b"         # --dim
FAINT = "#94a3b8"       # --faint
INFO = "#0284c7"        # --cyan
OK = "#0d9159"          # --green
WARN = "#c2790c"        # --amber
BAD = "#dc2626"         # --red
ACCENT = "#6366f1"      # --violet
ACCENT_HOVER = "#4f46e5"
IDLE_GREY = "#cbd5e1"
MONO_FAMILY = '"JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace'
BODY_FAMILY = '"Inter", "Segoe UI", Ubuntu, "DejaVu Sans", sans-serif'
DISPLAY_FAMILY = '"Space Grotesk", "Inter", "DejaVu Sans", sans-serif'

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(os.path.dirname(HERE), "payloads")
INTERP_BY_EXT = {".py": "python3", ".sh": "bash", ".js": "node",
                  ".rb": "ruby", ".pl": "perl", ".lua": "lua"}
MAX_BYTES = 256 * 1024

APP_STYLESHEET = f"""
QMainWindow, QWidget {{ background: {BG}; color: {INK}; font-family: {BODY_FAMILY}; font-size: 10pt; }}
QTabWidget::pane {{ border: 0; background: {BG}; }}
QTabBar::tab {{ background: {PANEL2}; color: {DIM}; padding: 9px 18px; border: 1px solid {LINE};
                border-bottom: none; font-weight: 600; }}
QTabBar::tab:selected {{ background: {PANEL}; color: {INK}; border-bottom: 2px solid {ACCENT}; }}
QComboBox, QLineEdit {{ background: {PANEL}; color: {INK}; border: 1px solid {LINE};
                        border-radius: 6px; padding: 6px 8px; }}
QComboBox QAbstractItemView {{ background: {PANEL}; color: {INK}; selection-background-color: {ACCENT};
                               selection-color: white; }}
QPushButton {{ background: {PANEL}; color: {DIM}; border: 1px solid {LINE}; border-radius: 7px;
              padding: 9px; font-weight: 600; }}
QPushButton:hover {{ border-color: {ACCENT}; color: {INK}; }}
QPushButton:disabled {{ color: {FAINT}; }}
QPushButton#primary {{ background: {ACCENT}; color: white; border: none; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#danger {{ background: {BAD}; color: white; border: none; }}
QPushButton#danger:disabled {{ background: #fde8e8; color: {FAINT}; }}
QCheckBox {{ color: {INK}; }}
QTextEdit, QPlainTextEdit {{ background: {PANEL}; color: {INK}; border: 1px solid {LINE};
                             border-radius: 8px; font-family: {MONO_FAMILY}; font-size: 9pt; }}
QListWidget, QTableWidget {{ background: {PANEL}; color: {INK}; border: 1px solid {LINE};
                             border-radius: 8px; gridline-color: {LINE}; }}
QHeaderView::section {{ background: {PANEL2}; color: {FAINT}; border: none; border-bottom: 1px solid {LINE};
                        padding: 6px; font-weight: 600; }}
QListWidget::item {{ padding: 8px; border-bottom: 1px solid {LINE}; }}
QListWidget::item:selected {{ background: #eef2ff; color: {INK}; }}
QScrollArea {{ border: none; }}
QGroupBox {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 8px; margin-top: 10px;
            font-weight: 600; color: {INK}; padding-top: 14px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px; color: {DIM}; }}
QLabel[role="faint"] {{ color: {FAINT}; }}
QLabel[role="dim"] {{ color: {DIM}; }}
QScrollBar:vertical {{ background: {BG}; width: 10px; }}
QScrollBar::handle:vertical {{ background: {FAINT}; border-radius: 5px; min-height: 20px; }}
"""


def _find_python() -> str:
    return sys.executable or "python3"


def _which(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def _card(title: str, color: str = INK) -> tuple[QtWidgets.QFrame, QtWidgets.QLabel]:
    """A small bordered stat tile: big number label + caption. Returns
    (frame, number_label) so the caller can update the number later."""
    frame = QtWidgets.QFrame()
    frame.setStyleSheet(f"QFrame {{ background:{PANEL}; border:1px solid {LINE}; border-radius:8px; }}")
    lay = QtWidgets.QVBoxLayout(frame)
    lay.setContentsMargins(14, 10, 14, 10)
    num = QtWidgets.QLabel("0")
    num.setStyleSheet(f"color:{color}; font-family:{MONO_FAMILY}; font-size:22pt; font-weight:700; border:none;")
    lay.addWidget(num)
    cap = QtWidgets.QLabel(title)
    cap.setStyleSheet(f"color:{FAINT}; font-size:8pt; font-weight:700; border:none;")
    lay.addWidget(cap)
    return frame, num


class DropZone(QtWidgets.QFrame):
    """Click-to-browse and drag-and-drop target for a script file."""

    def __init__(self, on_file, parent=None):
        super().__init__(parent)
        self.on_file = on_file
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(120)
        self._normal()
        lay = QtWidgets.QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        icon = QtWidgets.QLabel("⬆")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet(f"color:{ACCENT}; font-size:22pt; border:none; background:transparent;")
        lay.addWidget(icon)
        main = QtWidgets.QLabel("Open a script…")
        main.setAlignment(Qt.AlignCenter)
        main.setStyleSheet(f"color:{INK}; font-weight:700; border:none; background:transparent;")
        lay.addWidget(main)
        sub = QtWidgets.QLabel(".py .sh .js .rb .pl .lua · max 256 KiB")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(f"color:{FAINT}; font-size:8pt; border:none; background:transparent;")
        lay.addWidget(sub)

    def _normal(self):
        self.setStyleSheet(f"QFrame {{ background:{PANEL}; border:2px solid {LINE}; border-radius:10px; }}")

    def _hover(self):
        self.setStyleSheet(f"QFrame {{ background:{PANEL}; border:2px solid {ACCENT}; border-radius:10px; }}")

    def enterEvent(self, event):
        self._hover()

    def leaveEvent(self, event):
        self._normal()

    def mousePressEvent(self, event):
        self.on_file(None)  # None -> caller opens a file picker

    def dragEnterEvent(self, event: QtGui.QDragEnterEvent):
        if event.mimeData().hasUrls():
            self._hover()
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self._normal()

    def dropEvent(self, event: QtGui.QDropEvent):
        self._normal()
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self.on_file(path)


def _draw_mark() -> QtGui.QPixmap:
    """The small circular Cerberus mark, drawn with QPainter (same spirit as
    the Tk canvas version: a ring, an arc, three dots)."""
    pm = QtGui.QPixmap(40, 40)
    pm.fill(Qt.transparent)
    p = QtGui.QPainter(pm)
    p.setRenderHint(QtGui.QPainter.Antialiasing)
    pen = QtGui.QPen(QtGui.QColor(ACCENT))
    pen.setWidth(2)
    p.setPen(pen)
    p.drawEllipse(4, 4, 32, 32)
    p.setBrush(QtGui.QColor(BAD))
    p.setPen(Qt.NoPen)
    for cx in (14, 20, 26):
        p.drawEllipse(QtCore.QPointF(cx, 16), 2.2, 2.2)
    p.end()
    return pm


class CerberusMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.q: queue.Queue = queue.Queue()
        self.running = False
        self.seen = self.allowed = self.watched = self.viol = 0
        self.first_violation_shown = False
        self._run_started_at = 0.0
        self._current_run_meta: dict = {}
        self.history: list[dict] = []
        self.tl_filter = "all"

        # disposable-VM state
        self._vm = None
        self._vm_port = 8799
        self.vm_image = "ubuntu"
        self._vm_phase = "off"  # off | booting | live

        self.setWindowTitle("Cerberus")
        self.resize(1180, 760)
        self.setMinimumSize(920, 600)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root_lay = QtWidgets.QVBoxLayout(central)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        root_lay.addWidget(self._build_header())

        self.tabs = QtWidgets.QTabWidget()
        root_lay.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_analyze_tab(), "Analyze")
        self.tabs.addTab(self._build_timeline_tab(), "Timeline && History")
        self.tabs.addTab(self._build_architecture_tab(), "Architecture && System")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        self._set_state("idle", "idle", "open a script to check it")
        self._refresh_badge()
        self._load_architecture()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._drain_queue)
        self._timer.start(60)

    # ------------------------------------------------------------- header

    def _build_header(self) -> QtWidgets.QWidget:
        h = QtWidgets.QWidget()
        h.setFixedHeight(64)
        h.setStyleSheet(f"background:{PANEL2}; border-bottom:1px solid {LINE};")
        lay = QtWidgets.QHBoxLayout(h)
        lay.setContentsMargins(18, 8, 18, 8)

        mark = QtWidgets.QLabel()
        mark.setPixmap(_draw_mark())
        lay.addWidget(mark)

        title_box = QtWidgets.QVBoxLayout()
        title_box.setSpacing(0)
        title = QtWidgets.QLabel("Cerberus")
        title.setStyleSheet(f"color:{INK}; font-family:{DISPLAY_FAMILY}; font-size:14pt; font-weight:700; background:transparent;")
        title_box.addWidget(title)
        sub = QtWidgets.QLabel(f"ephemeral sandbox · real-time syscall defense · v{__version__}")
        sub.setStyleSheet(f"color:{DIM}; font-size:9pt; background:transparent;")
        title_box.addWidget(sub)
        wrap = QtWidgets.QWidget()
        wrap.setLayout(title_box)
        lay.addWidget(wrap)

        lay.addStretch(1)

        # Persistent execution-mode badge -- always visible, tells you at a
        # glance where runs execute: local sandbox, or the disposable VM and
        # whether it's booting / live.
        self.badge = QtWidgets.QLabel("")
        self.badge.setStyleSheet(
            f"background:{PANEL}; color:{INK}; border:1px solid {LINE}; "
            "border-radius:8px; padding:6px 14px; font-weight:700;"
        )
        lay.addWidget(self.badge)
        return h

    def _refresh_badge(self) -> None:
        if not self.run_in_vm.isChecked():
            text, fg = "◈ LOCAL SANDBOX", INFO
        elif self._vm_phase == "live":
            text, fg = "▣ DISPOSABLE VM · LIVE", OK
        elif self._vm_phase == "booting":
            text, fg = "▣ DISPOSABLE VM · BOOTING…", WARN
        else:
            text, fg = "▣ DISPOSABLE VM · off (boots on run)", DIM
        self.badge.setText(text)
        self.badge.setStyleSheet(
            f"background:{PANEL}; color:{fg}; border:1px solid {fg}; "
            "border-radius:8px; padding:6px 14px; font-weight:700;"
        )

    # -------------------------------------------------------- analyze tab

    def _build_analyze_tab(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        outer = QtWidgets.QHBoxLayout(page)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(16)

        # ---- sidebar --------------------------------------------------
        side = QtWidgets.QWidget()
        side.setFixedWidth(300)
        sl = QtWidgets.QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)

        def caption(txt):
            lab = QtWidgets.QLabel(txt)
            lab.setStyleSheet(f"color:{FAINT}; font-size:8pt; font-weight:700; margin-top:10px;")
            sl.addWidget(lab)

        caption("CHECK A FILE")
        self.drop = DropZone(self._on_drop_file)
        sl.addWidget(self.drop)

        caption("POLICY PROFILE")
        self.policy = QtWidgets.QComboBox()
        self.policy.addItems(["strict", "loopback", "observe", "paranoid"])
        sl.addWidget(self.policy)

        caption("NETWORK")
        self.net = QtWidgets.QComboBox()
        self.net.addItems(["none", "host"])
        sl.addWidget(self.net)

        # disposable-VM toggle: run two boundaries deep, still in this window
        self.run_in_vm = QtWidgets.QCheckBox(" Run in disposable VM")
        self.run_in_vm.stateChanged.connect(lambda _=None: self._refresh_badge())
        sl.addWidget(self.run_in_vm)
        vm_note = QtWidgets.QLabel("kernel-escape isolation · needs qemu · slower boot")
        vm_note.setWordWrap(True)
        vm_note.setStyleSheet(f"color:{FAINT}; font-size:8pt; margin-bottom:6px;")
        sl.addWidget(vm_note)

        caption("OR TRY A BUNDLED SAMPLE")
        self.sample = QtWidgets.QComboBox()
        samples = [f for f in sorted(os.listdir(PAYLOAD_DIR))
                   if f.endswith(".py")] if os.path.isdir(PAYLOAD_DIR) else []
        self.sample.addItems(samples)
        sl.addWidget(self.sample)
        run_btn = QtWidgets.QPushButton("▶  Run sample")
        run_btn.clicked.connect(self.run_sample)
        sl.addWidget(run_btn)

        # legend
        leg = QtWidgets.QHBoxLayout()
        for col, txt in ((INFO, "allowed"), (WARN, "watched"), (BAD, "violation")):
            dot = QtWidgets.QLabel("●")
            dot.setStyleSheet(f"color:{col}; border:none;")
            leg.addWidget(dot)
            lab = QtWidgets.QLabel(txt)
            lab.setStyleSheet(f"color:{DIM}; font-size:8pt; border:none;")
            leg.addWidget(lab)
        leg.addStretch(1)
        leg_w = QtWidgets.QWidget()
        leg_w.setLayout(leg)
        leg_w.setStyleSheet("margin-top:14px;")
        sl.addWidget(leg_w)
        sl.addStretch(1)
        outer.addWidget(side)

        # ---- main area --------------------------------------------------
        main = QtWidgets.QVBoxLayout()
        outer.addLayout(main, 1)

        self.state_frame = QtWidgets.QFrame()
        self.state_frame.setStyleSheet(f"QFrame {{ background:{PANEL}; border:1px solid {LINE}; border-radius:10px; }}")
        sf_lay = QtWidgets.QHBoxLayout(self.state_frame)
        self.orb = QtWidgets.QLabel()
        self.orb.setFixedSize(40, 40)
        self._paint_orb(IDLE_GREY)
        sf_lay.addWidget(self.orb)
        tf = QtWidgets.QVBoxLayout()
        self.state_big = QtWidgets.QLabel("idle")
        self.state_big.setStyleSheet(f"color:{INK}; font-family:{DISPLAY_FAMILY}; font-size:16pt; font-weight:700; border:none;")
        tf.addWidget(self.state_big)
        self.state_sub = QtWidgets.QLabel("")
        self.state_sub.setStyleSheet(f"color:{DIM}; border:none;")
        tf.addWidget(self.state_sub)
        sf_lay.addLayout(tf)
        sf_lay.addStretch(1)
        main.addWidget(self.state_frame)

        # violation / error banner (hidden until needed)
        self.banner = QtWidgets.QFrame()
        self.banner.setStyleSheet(f"QFrame {{ background:#fef2f2; border:1px solid {BAD}; border-radius:10px; }}")
        b_lay = QtWidgets.QVBoxLayout(self.banner)
        self.banner_title = QtWidgets.QLabel("")
        self.banner_title.setStyleSheet(f"color:{BAD}; font-size:12pt; font-weight:700; border:none;")
        b_lay.addWidget(self.banner_title)
        self.banner_desc = QtWidgets.QLabel("")
        self.banner_desc.setWordWrap(True)
        self.banner_desc.setStyleSheet(f"color:{INK}; border:none;")
        b_lay.addWidget(self.banner_desc)
        self.banner_lat = QtWidgets.QLabel("")
        self.banner_lat.setStyleSheet(f"color:{INK}; font-family:{MONO_FAMILY}; font-size:20pt; font-weight:700; border:none;")
        b_lay.addWidget(self.banner_lat)
        self.banner.hide()
        main.addWidget(self.banner)

        # metrics
        metrics_row = QtWidgets.QHBoxLayout()
        self.metric_vars = {}
        for key, txt, col in (("seen", "syscalls seen", INK), ("allowed", "allowed", OK),
                              ("watched", "watched", WARN), ("viol", "violations", BAD)):
            frame, num = _card(txt, col)
            metrics_row.addWidget(frame)
            self.metric_vars[key] = num
        main.addLayout(metrics_row)

        # feed
        feed_frame = QtWidgets.QFrame()
        feed_frame.setStyleSheet(f"QFrame {{ background:{PANEL}; border:1px solid {LINE}; border-radius:10px; }}")
        ff_lay = QtWidgets.QVBoxLayout(feed_frame)
        top = QtWidgets.QHBoxLayout()
        feed_title = QtWidgets.QLabel("live syscall feed")
        feed_title.setStyleSheet(f"color:{DIM}; border:none;")
        top.addWidget(feed_title)
        top.addStretch(1)
        self.feed_meta = QtWidgets.QLabel("")
        self.feed_meta.setStyleSheet(f"color:{FAINT}; font-size:8pt; border:none;")
        top.addWidget(self.feed_meta)
        ff_lay.addLayout(top)
        self.feed = QtWidgets.QTextEdit()
        self.feed.setReadOnly(True)
        self.feed.setStyleSheet(f"border:none; background:transparent; font-family:{MONO_FAMILY}; font-size:9pt;")
        ff_lay.addWidget(self.feed)
        main.addWidget(feed_frame, 1)

        return page

    def _paint_orb(self, color: str) -> None:
        pm = QtGui.QPixmap(40, 40)
        pm.fill(Qt.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setBrush(QtGui.QColor(color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(2, 2, 36, 36)
        p.end()
        self.orb.setPixmap(pm)

    def _on_drop_file(self, path) -> None:
        if self.running:
            return
        if path is None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Choose a script to check", "",
                "Scripts (*.py *.sh *.js *.rb *.pl *.lua);;All files (*)")
            if not path:
                return
        self.run_path(path)

    # ------------------------------------------------------------- actions

    def run_sample(self) -> None:
        if self.running or not self.sample.currentText():
            return
        self.run_path(os.path.join(PAYLOAD_DIR, self.sample.currentText()))

    def run_path(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            self._show_error(f"cannot read file: {e}")
            return
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        if ext not in INTERP_BY_EXT:
            self._show_error(f"unsupported type '{ext or 'none'}'")
            return
        if len(data) > MAX_BYTES:
            self._show_error(f"file too large ({len(data)//1024} KiB > 256 KiB)")
            return
        if b"\x00" in data[:4096]:
            self._show_error("looks like a binary, not a script")
            return
        self._start_run(name, INTERP_BY_EXT[ext], data)

    def _start_run(self, name: str, interp: str, data: bytes) -> None:
        self._reset_run()
        self.running = True
        self._run_started_at = time.time()
        in_vm = bool(self.run_in_vm.isChecked())
        self._current_run_meta = {
            "filename": name, "bytes": len(data), "policy": self.policy.currentText(),
            "net": self.net.currentText(), "source": "sample" if data else "upload",
            "vm": in_vm,
        }
        where = "in disposable VM" if in_vm else "under monitor"
        self._set_state("running", "running", f"{name} — executing {where}")
        self.feed_meta.setText(f"{name} · {len(data)} bytes · uid 65534"
                               + (" · VM" if in_vm else ""))
        target = self._worker_vm if in_vm else self._worker
        threading.Thread(target=target, args=(name, interp, data), daemon=True).start()

    # ---- workers (background threads; touch ONLY self.q, never widgets) ----

    def _worker_vm(self, name: str, interp: str, data: bytes) -> None:
        """Run inside a disposable VM: boot it (once), then stream events over
        the forwarded port into the same native widgets. No browser involved."""
        from . import vm as vmmod
        from . import wsclient
        host, port = "127.0.0.1", self._vm_port

        def status(msg):
            self.q.put({"kind": "vm_status", "summary": msg})

        try:
            if self._vm is None or not self._vm.is_running():
                self.q.put({"kind": "vm_phase", "phase": "booting"})
                status("preparing disposable VM…")
                self._vm = vmmod.spawn_vm(port=port, image=self.vm_image, progress=status)
                self._start_console_reader(self._vm)
                status("waiting for the VM to finish booting…")
                if not wsclient.wait_up(host, port, timeout=240):
                    self.q.put({"kind": "vm_phase", "phase": "off"})
                    self.q.put({"kind": "error",
                                "summary": "VM booted but the dashboard never came "
                                           "up — see the vm console lines above"})
                    self.q.put({"kind": "run_end", "detail": {"verdict": "error"}})
                    return
                self.q.put({"kind": "vm_phase", "phase": "live"})
                status("VM up — sandbox runs two boundaries deep")
            else:
                self.q.put({"kind": "vm_phase", "phase": "live"})

            events = wsclient.WSEvents(host, port)
            events.connect()
            wsclient.upload(host, port, name, data,
                            policy=self.policy.currentText(), net=self.net.currentText())
            for ev in events:
                self.q.put(ev)
                if ev.get("kind") == "run_end":
                    break
            events.close()
        except Exception as exc:
            self.q.put({"kind": "error", "summary": f"VM run failed: {exc}"})
            self.q.put({"kind": "run_end", "detail": {"verdict": "error"}})

    def _start_console_reader(self, vm) -> None:
        def reader():
            try:
                for line in vm.proc.stdout:
                    line = line.rstrip("\n")
                    if line.strip():
                        self.q.put({"kind": "vm_console", "summary": line})
            except Exception:
                pass
        threading.Thread(target=reader, daemon=True).start()

    def _worker(self, name: str, interp: str, data: bytes) -> None:
        """Spawn the elevated helper and read its JSON event stream."""
        pybin = _find_python()
        helper = [pybin, "-B", "-m", "cerberus.helper", "--policy", self.policy.currentText(),
                  "--net", self.net.currentText(), "--name", name, "--interp", interp, "--b64"]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(HERE) + os.pathsep + env.get("PYTHONPATH", "")

        if os.geteuid() == 0:
            cmd = helper
        elif _which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            cmd = ["pkexec", "env", f"PYTHONPATH={env['PYTHONPATH']}", *helper]
        elif _which("sudo"):
            cmd = ["sudo", "-E", *helper]
        else:
            self.q.put({"kind": "error", "summary": "need root: no pkexec or sudo"})
            self.q.put({"kind": "result", "verdict": "error"})
            return

        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        except OSError as e:
            self.q.put({"kind": "error", "summary": f"failed to launch helper: {e}"})
            self.q.put({"kind": "result", "verdict": "error"})
            return

        proc.stdin.write(base64.b64encode(data))
        proc.stdin.close()
        for line in proc.stdout:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                pass
        err = proc.stderr.read().decode("utf-8", "replace")
        proc.wait()
        if proc.returncode != 0 and not self.first_violation_shown:
            self.q.put({"kind": "error",
                        "summary": f"helper exited {proc.returncode}: "
                                   f"{err.strip()[:200] or 'authorization cancelled?'}"})
            self.q.put({"kind": "result", "verdict": "error"})

    # ------------------------------------------------------ event pump (GUI thread)

    def _drain_queue(self) -> None:
        try:
            while True:
                ev = self.q.get_nowait()
                self._handle(ev)
        except queue.Empty:
            pass

    def _handle(self, ev: dict) -> None:
        kind = ev.get("kind")
        if kind == "syscall":
            self.seen += 1
            if ev.get("severity") == "suspicious":
                self.watched += 1
            else:
                self.allowed += 1
            self._metrics()
            self._append_feed(ev)
        elif kind == "violation":
            self.seen += 1
            self.viol += 1
            self._metrics()
            self._append_feed(ev)
            self._show_violation(ev)
            self._set_state("frozen", "FROZEN", "process group stopped mid-syscall")
        elif kind in ("lifecycle", "state"):
            self._append_feed(ev)
        elif kind == "run_start":
            pass
        elif kind == "vm_phase":
            self._vm_phase = ev.get("phase", "off")
            self._refresh_badge()
        elif kind == "vm_status":
            self.state_sub.setText(ev.get("summary", ""))
        elif kind == "vm_console":
            self._append_console(ev.get("summary", ""))
        elif kind == "error":
            self._show_error(ev.get("summary", "error"))
        elif kind in ("result", "run_end"):
            self._finish(ev)

    def _finish(self, ev: dict) -> None:
        self.running = False
        src = ev.get("detail") if ev.get("kind") == "run_end" else ev
        src = src or ev
        v = src.get("verdict")
        stats = src.get("stats") or {}
        if v == "contained":
            self._set_state("frozen", "CONTAINED", "payload stopped before it could act")
        elif v == "clean":
            self._set_state("clean", "CLEAN", "payload finished — no violations")
        else:
            self._set_state("error", "ERROR", ev.get("summary", "run failed"))
        meta = f"{stats.get('notifications', 0)} syscalls inspected"
        if stats.get("decide_us_p50") is not None:
            meta += f" · median decide {stats['decide_us_p50']}µs"
        in_vm = self.run_in_vm.isChecked()
        meta += " · in disposable VM" if in_vm else " · local sandbox"
        self.feed_meta.setText(meta)

        # Real run history -- same shape as the web dashboard's /api/history
        # records, so Timeline & History shows exactly what actually happened.
        m = self._current_run_meta
        entry = {
            "id": f"{int(self._run_started_at*1000) & 0xFFFFFFFF:x}",
            "ts": self._run_started_at,
            "filename": m.get("filename", "?"),
            "policy": m.get("policy", "?"),
            "net": m.get("net", "?"),
            "source": m.get("source", "?"),
            "bytes": m.get("bytes", 0),
            "verdict": v or "error",
            "exit_code": src.get("exit_code"),
            "frozen": bool(src.get("frozen")),
            "first_violation": src.get("first_violation"),
            "stats": stats,
            "duration_s": round(time.time() - self._run_started_at, 3),
        }
        self.history.append(entry)
        self._render_timeline()

    # ------------------------------------------------------------- painting

    def _set_state(self, cls: str, big: str, sub: str) -> None:
        colors = {"idle": IDLE_GREY, "running": INFO, "frozen": BAD, "clean": OK, "error": BAD}
        border = {"idle": LINE, "running": INFO, "frozen": BAD, "clean": OK, "error": BAD}
        self._paint_orb(colors.get(cls, IDLE_GREY))
        self.state_frame.setStyleSheet(
            f"QFrame {{ background:{PANEL}; border:1px solid {border.get(cls, LINE)}; border-radius:10px; }}")
        big_color = BAD if cls in ("frozen", "error") else (OK if cls == "clean" else INK)
        self.state_big.setStyleSheet(f"color:{big_color}; font-family:{DISPLAY_FAMILY}; font-size:16pt; font-weight:700; border:none;")
        self.state_big.setText(big)
        self.state_sub.setText(sub)

    def _metrics(self) -> None:
        self.metric_vars["seen"].setText(str(self.seen))
        self.metric_vars["allowed"].setText(str(self.allowed))
        self.metric_vars["watched"].setText(str(self.watched))
        self.metric_vars["viol"].setText(str(self.viol))

    def _append_feed(self, ev: dict) -> None:
        sev = ev.get("severity", "info")
        color = {"info": INFO, "suspicious": WARN, "violation": BAD}.get(sev, DIM)
        if ev.get("kind") in ("lifecycle", "state", "run_start", "run_end"):
            color = DIM
        ts = ""
        if ev.get("ts"):
            ts = datetime.fromtimestamp(ev["ts"]).strftime("%H:%M:%S.%f")[:-3]
        sc = ev.get("syscall") or "·"
        lat = f"  {ev['latency_us']:.0f}µs" if ev.get("latency_us") is not None else ""
        line = (
            f'<span style="color:{FAINT}">{html.escape(ts):<13}</span> '
            f'<span style="color:{color}">{html.escape(sc):<14}</span> '
            f'<span style="color:{INK}">{html.escape(ev.get("summary", ""))}</span>'
            f'<span style="color:{FAINT}">{html.escape(lat)}</span>'
        )
        self.feed.append(line)
        self._trim_feed(800)

    def _append_console(self, line: str) -> None:
        html_line = (f'<span style="color:{ACCENT}">vm</span> '
                     f'<span style="color:{DIM}">│ {html.escape(line)}</span>')
        self.feed.append(html_line)
        self._trim_feed(1200)

    def _trim_feed(self, cap: int) -> None:
        doc = self.feed.document()
        if doc.blockCount() > cap:
            cursor = QtGui.QTextCursor(doc.findBlockByNumber(0))
            cursor.select(QtGui.QTextCursor.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()
        sb = self.feed.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _show_violation(self, ev: dict) -> None:
        if self.first_violation_shown:
            return
        self.first_violation_shown = True
        self.banner.setStyleSheet(f"QFrame {{ background:#fef2f2; border:1px solid {BAD}; border-radius:10px; }}")
        self.banner_title.setStyleSheet(f"color:{BAD}; font-size:12pt; font-weight:700; border:none;")
        self.banner_title.setText(f"⛔ CONTAINED — {ev.get('rule','')}")
        frozen = (ev.get("detail") or {}).get("frozen", True)
        who = "detected & frozen in" if frozen else "detected & denied in"
        self.banner_desc.setText(f"{ev.get('summary','')}    ({who})")
        lat = ev.get("latency_us")
        self.banner_lat.setText(f"{lat:.0f} µs" if lat is not None else "—")
        self.banner.show()

    def _reset_run(self) -> None:
        self.seen = self.allowed = self.watched = self.viol = 0
        self.first_violation_shown = False
        self._metrics()
        self.banner.hide()
        self.feed.clear()
        self.feed_meta.setText("")

    def _show_error(self, msg: str) -> None:
        self.running = False
        self.banner.setStyleSheet(f"QFrame {{ background:#fffbeb; border:1px solid {WARN}; border-radius:10px; }}")
        self.banner_title.setStyleSheet(f"color:{WARN}; font-size:12pt; font-weight:700; border:none;")
        self.banner_title.setText("⚠ could not run")
        self.banner_desc.setText(msg)
        self.banner_lat.setText("")
        self.banner.show()
        self._set_state("idle", "idle", "ready")

    # ------------------------------------------------------- timeline tab

    def _build_timeline_tab(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(page)
        lay.setContentsMargins(20, 20, 20, 20)

        head = QtWidgets.QLabel("Spatial Runtime Timeline")
        head.setStyleSheet(f"color:{INK}; font-family:{DISPLAY_FAMILY}; font-size:18pt; font-weight:700;")
        lay.addWidget(head)
        desc = QtWidgets.QLabel(
            "Every run this window has executed, newest first. Nothing here is "
            "synthesised — the sandbox keeps no disk state, so this list lives "
            "only in this app's memory for as long as it stays open.")
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{DIM};")
        lay.addWidget(desc)

        filt_row = QtWidgets.QHBoxLayout()
        self._tl_buttons = {}
        for key, label in (("all", "All"), ("contained", "Contained"), ("clean", "Clean")):
            b = QtWidgets.QPushButton(label)
            b.setCheckable(True)
            b.setChecked(key == "all")
            b.clicked.connect(lambda _=None, k=key: self._set_tl_filter(k))
            filt_row.addWidget(b)
            self._tl_buttons[key] = b
        filt_row.addStretch(1)
        lay.addLayout(filt_row)

        splitter = QtWidgets.QSplitter(Qt.Vertical)
        self.tl_list = QtWidgets.QListWidget()
        self.tl_list.currentRowChanged.connect(self._on_tl_select)
        splitter.addWidget(self.tl_list)

        self.tl_detail = QtWidgets.QTextEdit()
        self.tl_detail.setReadOnly(True)
        self.tl_detail.setPlaceholderText("Select a run above to see its forensic detail.")
        splitter.addWidget(self.tl_detail)
        splitter.setSizes([300, 260])
        lay.addWidget(splitter, 1)
        return page

    def _set_tl_filter(self, key: str) -> None:
        self.tl_filter = key
        for k, b in self._tl_buttons.items():
            b.setChecked(k == key)
        self._render_timeline()

    def _render_timeline(self) -> None:
        self.tl_list.clear()
        self._tl_rows = [r for r in reversed(self.history)
                         if self.tl_filter == "all" or r["verdict"] == self.tl_filter]
        for run in self._tl_rows:
            vclass = run["verdict"]
            color = {"contained": BAD, "clean": OK}.get(vclass, WARN)
            when = datetime.fromtimestamp(run["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            item = QtWidgets.QListWidgetItem(
                f"● {run['filename']}   [{run['verdict'].upper()}]   "
                f"{run['policy']} · {run['net']} · {run['duration_s']}s · {when}")
            item.setForeground(QtGui.QColor(INK))
            item.setData(Qt.UserRole, run)
            self.tl_list.addItem(item)
            item.setForeground(QtGui.QColor(color) if vclass in ("contained",) else QtGui.QColor(INK))

    def _on_tl_select(self, row: int) -> None:
        if row < 0 or row >= len(getattr(self, "_tl_rows", [])):
            self.tl_detail.clear()
            return
        run = self._tl_rows[row]
        stats = run.get("stats") or {}
        lines = [
            f"<b>{html.escape(run['filename'])}</b> — run {run['id']}",
            f"verdict: <b style='color:{BAD if run['verdict']=='contained' else OK}'>{run['verdict']}</b>"
            f" &nbsp; exit_code: {run.get('exit_code')} &nbsp; frozen: {run.get('frozen')}",
            f"policy: {run['policy']} &nbsp; network: {run['net']} &nbsp; source: {run['source']} "
            f"&nbsp; bytes: {run['bytes']} &nbsp; duration: {run['duration_s']}s",
            f"syscalls seen: {stats.get('notifications')} &nbsp; allowed: {stats.get('allowed')} "
            f"&nbsp; watched: {stats.get('suspicious')} &nbsp; violations: {stats.get('violations')}",
            f"decide p50/p99: {stats.get('decide_us_p50')}µs / {stats.get('decide_us_p99')}µs",
        ]
        fv = run.get("first_violation")
        if fv:
            lines.append(
                f"<br><span style='color:{BAD}'><b>{html.escape(fv.get('rule',''))}</b></span> — "
                f"{html.escape(fv.get('summary',''))} (syscall <b>{html.escape(fv.get('syscall',''))}</b>, "
                f"{fv.get('response_us')}µs to respond)")
        top = stats.get("top_syscalls") or []
        if top:
            lines.append("<br>" + " &nbsp; ".join(f"<code>{n} ×{c}</code>" for n, c in top))
        self.tl_detail.setHtml("<br>".join(lines))

    # --------------------------------------------------- architecture tab

    def _build_architecture_tab(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(page)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QtWidgets.QWidget()
        self._arch_layout = QtWidgets.QVBoxLayout(inner)
        self._arch_layout.setContentsMargins(20, 20, 20, 20)
        self._arch_layout.setSpacing(14)
        scroll.setWidget(inner)
        outer.addWidget(scroll)
        return page

    def _on_tab_changed(self, idx: int) -> None:
        pass  # architecture is loaded once at startup; history renders on every finish

    def _load_architecture(self) -> None:
        """Populate the Architecture & System tab straight from
        `cerberus.introspect` -- same process, so no HTTP round trip is even
        needed; it can never show something different from what the running
        monitor enforces."""
        info = introspect.system_info()
        lay = self._arch_layout

        head = QtWidgets.QLabel("Runtime Subsystem & Syscall Topology")
        head.setStyleSheet(f"color:{INK}; font-family:{DISPLAY_FAMILY}; font-size:18pt; font-weight:700;")
        lay.addWidget(head)
        sub = QtWidgets.QLabel("Every figure below is read from the running policy "
                               "engine, not hand-typed — it can never drift from "
                               "what the monitor actually enforces.")
        sub.setWordWrap(True)
        sub.setStyleSheet(f"color:{DIM};")
        lay.addWidget(sub)

        # syscall tiers
        tiers_row = QtWidgets.QHBoxLayout()
        tiers = [
            ("Bypass-Deny", info["syscall_tiers"]["bypass_deny"], BAD),
            ("Escape-Class", info["syscall_tiers"]["escape"], "#c2410c"),
            ("Notify (Judged)", info["syscall_tiers"]["notify"], INFO),
            ("Baseline Allow", info["syscall_tiers"]["baseline_allow"], OK),
        ]
        for label, data, color in tiers:
            box = QtWidgets.QGroupBox(label)
            bl = QtWidgets.QVBoxLayout(box)
            count = QtWidgets.QLabel(str(data["count"]))
            count.setStyleSheet(f"color:{color}; font-family:{MONO_FAMILY}; font-size:24pt; font-weight:700; border:none;")
            bl.addWidget(count)
            desc = QtWidgets.QLabel(data["action"])
            desc.setWordWrap(True)
            desc.setStyleSheet(f"color:{DIM}; font-size:8pt; border:none;")
            bl.addWidget(desc)
            names = data.get("names") or data.get("sample") or []
            if names:
                chips = QtWidgets.QLabel(", ".join(names) + (" …" if len(names) < data["count"] else ""))
                chips.setWordWrap(True)
                chips.setStyleSheet(f"color:{INK}; font-family:{MONO_FAMILY}; font-size:8pt; border:none;")
                bl.addWidget(chips)
            tiers_row.addWidget(box)
        lay.addLayout(tiers_row)

        # isolation substrate
        iso_box = QtWidgets.QGroupBox("Isolation Substrate")
        iso_grid = QtWidgets.QGridLayout(iso_box)
        rows = [
            ("Interception", info["interception"]),
            ("Kernel minimum", info["kernel_min"]),
            ("Namespaces", ", ".join(info["namespaces"])),
            ("Storage root", info["storage_root"]),
            ("Cgroup response", info["cgroup"]["response"]),
            ("Runs as", info["run_as"]),
            ("Read-only binds", ", ".join(info["read_only_binds"])),
            ("Device nodes", ", ".join(info["device_nodes"])),
            ("Sensitive path patterns", f"{info['sensitive_patterns']} (always a violation, any prefix)"),
        ]
        for i, (k, v) in enumerate(rows):
            kl = QtWidgets.QLabel(k)
            kl.setStyleSheet(f"color:{FAINT}; font-size:8pt; font-weight:700; border:none;")
            vl = QtWidgets.QLabel(v)
            vl.setWordWrap(True)
            vl.setStyleSheet(f"color:{INK}; font-family:{MONO_FAMILY}; font-size:9pt; border:none;")
            iso_grid.addWidget(kl, i, 0)
            iso_grid.addWidget(vl, i, 1)
        lay.addWidget(iso_box)

        # policy profiles table
        prof_box = QtWidgets.QGroupBox("Policy Profiles")
        pv = QtWidgets.QVBoxLayout(prof_box)
        table = QtWidgets.QTableWidget()
        cols = ["Profile", "Network", "Loopback", "Exec", "Unlisted syscalls", "Max processes"]
        table.setColumnCount(len(cols))
        table.setHorizontalHeaderLabels(cols)
        table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        profiles = info["profiles"]
        table.setRowCount(len(profiles))
        for r, (name, p) in enumerate(profiles.items()):
            vals = [
                name,
                "allowed" if p["allow_network"] else "denied",
                "allowed" if p["allow_loopback"] else "denied",
                "allowed" if p["allow_exec"] else "denied",
                "allowed, logged" if p["default_allow_unlisted"] else "denied (strict allowlist)",
                str(p["max_processes"]),
            ]
            for c, val in enumerate(vals):
                item = QtWidgets.QTableWidgetItem(val)
                if c > 0 and "denied" in val:
                    item.setForeground(QtGui.QColor(FAINT))
                elif c > 0:
                    item.setForeground(QtGui.QColor(OK))
                table.setItem(r, c, item)
        table.setFixedHeight(36 * (len(profiles) + 1))
        pv.addWidget(table)
        lay.addWidget(prof_box)
        lay.addStretch(1)

    # ------------------------------------------------------------- close

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        vm = self._vm
        if vm is not None and vm.is_running():
            try:
                vm.stop()  # terminate QEMU and delete the disposable overlay
            except Exception:
                pass
        self._vm = None
        self._vm_phase = "off"
        event.accept()


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(APP_STYLESHEET)
    win = CerberusMainWindow()
    win.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
