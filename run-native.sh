#!/usr/bin/env bash
# Launch the native Cerberus desktop app: the real web dashboard, rendered
# in a native Qt window (QWebEngineView) -- no browser tab, no address bar.
#
# The window itself runs as your normal user. It elevates only the sandbox
# SERVER (cerberus.web) via pkexec (or sudo) as a separate subprocess, the
# same split packaging/AppRun (the AppImage launcher) already uses, then
# points its browser view at that server on 127.0.0.1.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# PyQt5 isn't in the stdlib; some distros split it into its own package, and
# the WebEngine (Chromium-based) view is its own package again.
if ! python3 -c 'import PyQt5.QtWidgets' 2>/dev/null; then
  echo "Cerberus needs PyQt5. Install it:"
  echo "  Debian/Ubuntu/Mint : sudo apt install python3-pyqt5"
  echo "  Fedora             : sudo dnf install python3-qt5"
  echo "  Arch               : sudo pacman -S python-pyqt5"
  echo "  otherwise          : pip install PyQt5"
  exit 1
fi
if ! python3 -c 'import PyQt5.QtWebEngineWidgets' 2>/dev/null; then
  echo "Cerberus needs PyQtWebEngine (the window renders the dashboard's own"
  echo "HTML/CSS, not a hand-built copy of it). Install it:"
  echo "  Debian/Ubuntu/Mint : sudo apt install python3-pyqt5.qtwebengine"
  echo "  Fedora             : sudo dnf install python3-qt5-webengine"
  echo "  Arch               : sudo pacman -S python-pyqtwebengine"
  echo "  otherwise          : pip install PyQtWebEngine"
  exit 1
fi

# pkexec (graphical) is used at run time to elevate the sandbox server; warn if absent.
if ! command -v pkexec >/dev/null 2>&1 && ! command -v sudo >/dev/null 2>&1; then
  echo "warning: neither pkexec nor sudo found; the sandbox server needs root." >&2
fi

cd "$HERE"
# Wipe stale compiled bytecode so an extract-over-old-copy can't run old code.
find "$HERE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
ver="$(python3 -c 'import cerberus; print(cerberus.__version__)' 2>/dev/null || echo '?')"
echo "Cerberus v$ver  —  running from $(pwd)"
exec python3 -B -m cerberus.gui_qt   # -B: don't write .pyc, never reuse stale ones
