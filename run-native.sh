#!/usr/bin/env bash
# Launch the native Cerberus desktop app (Tkinter window, no browser).
#
# The GUI runs as your normal user; when you check a file it elevates ONLY the
# sandbox helper via pkexec (or sudo), so the window stays in your session.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# Tkinter ships with CPython but some distros split it into a package.
if ! python3 -c 'import tkinter' 2>/dev/null; then
  echo "Cerberus needs Tkinter (python3-tk). Install it:"
  echo "  Debian/Ubuntu/Mint : sudo apt install python3-tk"
  echo "  Fedora             : sudo dnf install python3-tkinter"
  echo "  Arch               : sudo pacman -S tk"
  exit 1
fi

# pkexec (graphical) is used at run time for the sandbox helper; warn if absent.
if ! command -v pkexec >/dev/null 2>&1 && ! command -v sudo >/dev/null 2>&1; then
  echo "warning: neither pkexec nor sudo found; the sandbox helper needs root." >&2
fi

cd "$HERE"
exec python3 -m cerberus.gui
