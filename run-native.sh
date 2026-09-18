#!/usr/bin/env bash
# Launch the native Cerberus desktop app (Tkinter window, no browser).
#
# The GUI runs as your normal user; when you check a file it elevates ONLY the
# sandbox helper via pkexec (or sudo), so the window stays in your session.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

export QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox"

# Cerberus uses PySide6 for the modern clinical Stitch UI, falling back to Tkinter.
if ! python3 -c 'import PySide6' 2>/dev/null && ! python3 -c 'import tkinter' 2>/dev/null; then
  echo "Cerberus needs PySide6 or Tkinter. Install it:"
  echo "  pip install PySide6"
  echo "  or: sudo apt install python3-tk"
  exit 1
fi

# pkexec (graphical) is used at run time for the sandbox helper; warn if absent.
if ! command -v pkexec >/dev/null 2>&1 && ! command -v sudo >/dev/null 2>&1; then
  echo "warning: neither pkexec nor sudo found; the sandbox helper needs root." >&2
fi

cd "$HERE"
# Wipe stale compiled bytecode so an extract-over-old-copy can't run old code.
find "$HERE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
ver="$(python3 -c 'import cerberus; print(cerberus.__version__)' 2>/dev/null || echo '?')"
echo "Cerberus v$ver  —  running from $(pwd)"
exec python3 -B -m cerberus.gui   # -B: don't write .pyc, never reuse stale ones
