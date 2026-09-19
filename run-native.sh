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

# QtWebEngine's native-Wayland Qt platform plugin has long-standing
# compositing bugs on some driver/compositor combos: elements that need a
# GPU-composited layer (3D CSS transforms, backdrop-filter blur -- exactly
# what the dashboard's isometric cube and glass panels use) can render as
# blank/black instead of their real content, while everything else on the
# page looks fine. Running the same QtWebEngine through XWayland instead of
# native Wayland is the standard fix. So: if this looks like a Wayland
# session, default to the xcb (X11/XWayland) platform plugin. This is a
# platform-plugin switch, not a rendering-quality tradeoff like the GPU
# flags were -- it shouldn't cost you anything. Set CERBERUS_QPA=wayland to
# force native Wayland back on (e.g. to compare), or to any other Qt
# platform name to force that instead.
if [ -n "${WAYLAND_DISPLAY:-}" ] && [ "${CERBERUS_QPA:-xcb}" != "wayland" ]; then
  export QT_QPA_PLATFORM="${CERBERUS_QPA:-xcb}"
  echo "Wayland session detected — running the WebEngine view through XWayland (QT_QPA_PLATFORM=$QT_QPA_PLATFORM)."
  echo "(set CERBERUS_QPA=wayland to force native Wayland instead)"
fi

cd "$HERE"
# Wipe stale compiled bytecode so an extract-over-old-copy can't run old code.
find "$HERE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
ver="$(python3 -c 'import cerberus; print(cerberus.__version__)' 2>/dev/null || echo '?')"
echo "Cerberus v$ver  —  running from $(pwd)"

# QtWebEngine's embedded Chromium sometimes spams harmless GL warnings on
# Linux (gles2_cmd_decoder.cc, glCopyTexSubImage2D, "framebuffer incomplete")
# from its GPU compositor. Forcing software rendering to silence them turned
# out to be the wrong trade: the dashboard's isometric cube (3D CSS
# transforms) and glass-panel blur both rely on GPU compositing, so
# disabling it flattened the cube into a gray box and broke the blur
# surfaces. So: leave GPU compositing on (this is what actually worked), and
# just filter the known-noisy lines out of the terminal instead. Set
# CERBERUS_RAW_LOGS=1 to see everything unfiltered (useful if you're
# debugging a *real* WebEngine problem, since this filter is pattern-based
# and could in theory hide something relevant).
NOISE_PATTERN='gles2_cmd_decoder\.cc|GpuRasterization|GL_INVALID_FRAMEBUFFER_OPERATION|GL_INVALID_OPERATION.*glCopyTexSubImage2D|RENDER WARNING: texture bound to texture unit'

if [ "${CERBERUS_RAW_LOGS:-0}" = "1" ] || ! command -v grep >/dev/null 2>&1; then
  exec python3 -B -m cerberus.gui_qt   # -B: don't write .pyc, never reuse stale ones
else
  # Process substitution (bash-only, fine: the shebang is bash) -- filters
  # stderr through grep -v without touching stdout or the exit code.
  python3 -B -m cerberus.gui_qt 2> >(grep --line-buffered -Ev "$NOISE_PATTERN" >&2)
  exit $?
fi
