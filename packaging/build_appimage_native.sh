#!/usr/bin/env bash
# Build a NATIVE-GUI Cerberus AppImage (Tkinter window, no browser).
#
# Run this on the machine you'll ship from — a normal Fedora/Ubuntu/Arch desktop
# where Tkinter is installed (python3-tk / python3-tkinter / tk). It bundles the
# system CPython *and* Tcl/Tk so the resulting AppImage opens a real window with
# no toolkit installed on the target.
#
# Why it isn't prebuilt in this repo: it must copy the host's Tcl/Tk, so it can
# only be assembled where those libraries exist. The logic below finds them
# automatically.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$ROOT/..}"
APPDIR="$ROOT/Cerberus-native.AppDir"
PYBIN="$(command -v python3.11 || command -v python3)"
PYVER="$("$PYBIN" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
STDLIB="$("$PYBIN" -c 'import sysconfig;print(sysconfig.get_path("stdlib"))')"

echo "==> python $PYVER at $PYBIN"

# Preflight: Tkinter must import on this build host.
if ! "$PYBIN" -c 'import tkinter' 2>/dev/null; then
  echo "!! This host has no Tkinter. Install it and re-run:"
  echo "     Debian/Ubuntu: sudo apt install python3-tk"
  echo "     Fedora:        sudo dnf install python3-tkinter"
  echo "     Arch:          sudo pacman -S tk"
  exit 1
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" "$APPDIR/usr/share/cerberus" \
         "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

echo "==> bundling CPython + stdlib"
cp "$(readlink -f "$PYBIN")" "$APPDIR/usr/bin/python3"
cp -a "$STDLIB" "$APPDIR/usr/lib/python$PYVER"

# ---- Tcl/Tk: the piece that makes the native window work --------------------
echo "==> locating Tcl/Tk"
TKINFO="$("$PYBIN" - <<'PY'
import tkinter, _tkinter, os
r=tkinter.Tk(); r.withdraw()
print("TCL", r.tk.exprstring('$tcl_library'))
try:
    print("TK", r.tk.exprstring('$tk_library'))
except Exception:
    print("TK", "")
print("SO", _tkinter.__file__)
r.destroy()
PY
)"
TCL_LIB=$(echo "$TKINFO" | awk '/^TCL/{ $1=""; sub(/^ /,""); print }')
TK_LIB=$(echo  "$TKINFO" | awk '/^TK/{  $1=""; sub(/^ /,""); print }')
TK_SO=$(echo   "$TKINFO" | awk '/^SO/{  print $2 }')
echo "    tcl_library=$TCL_LIB"
echo "    tk_library=$TK_LIB"
echo "    _tkinter=$TK_SO"

# copy the tcl/tk script libraries
mkdir -p "$APPDIR/usr/share/tcltk"
[ -n "$TCL_LIB" ] && cp -a "$TCL_LIB" "$APPDIR/usr/share/tcltk/tcl" || true
[ -n "$TK_LIB" ]  && cp -a "$TK_LIB"  "$APPDIR/usr/share/tcltk/tk"  || true

# ensure _tkinter.so is present in lib-dynload (cp -a of stdlib already covers it,
# but copy explicitly if the interpreter reports it elsewhere)
DYN="$APPDIR/usr/lib/python$PYVER/lib-dynload"
mkdir -p "$DYN"
[ -f "$TK_SO" ] && cp -L "$TK_SO" "$DYN/" || true

# copy the shared libs Tk needs (libtcl, libtk, and their non-glibc deps)
copy_lib(){ local f; f=$(ldconfig -p 2>/dev/null | awk -v L="$1" '$1==L{print $NF; exit}') || true
  [ -n "${f:-}" ] && cp -L "$f" "$APPDIR/usr/lib/" 2>/dev/null && echo "    + $1" || true; }
for lib in libtcl8.6.so libtk8.6.so libtcl9.0.so libtk9.0.so \
           libz.so.1 libexpat.so.1 libffi.so.8 libffi.so.7 \
           libX11.so.6 libXext.so.6 libXft.so.2 libXss.so.1 libfontconfig.so.1 \
           libfreetype.so.6 libXrender.so.1 libbz2.so.1.0 libpng16.so.16; do
  copy_lib "$lib"
done
# also pull whatever _tkinter.so links to that we can resolve
if [ -f "$DYN/_tkinter"*.so ]; then
  for dep in $(ldd "$DYN"/_tkinter*.so 2>/dev/null | awk '/=>/{print $3}'); do
    case "$dep" in */libc.so*|*/libm.so*|*/ld-*) continue;; esac
    [ -f "$dep" ] && cp -Ln "$dep" "$APPDIR/usr/lib/" 2>/dev/null || true
  done
fi

echo "==> trimming stdlib (keeping tkinter!)"
( cd "$APPDIR/usr/lib/python$PYVER" && rm -rf test tests idlelib turtledemo \
    lib2to3 ensurepip config-*/libpython*.a __pycache__ 2>/dev/null || true )
find "$APPDIR/usr/lib/python$PYVER" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

echo "==> copying Cerberus source"
for d in cerberus static payloads; do cp -a "$SRC/$d" "$APPDIR/usr/share/cerberus/"; done
find "$APPDIR/usr/share/cerberus" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# icon (reuse the drawn PNG if present, else a solid placeholder)
if [ -f "$ROOT/cerberus.png" ]; then cp "$ROOT/cerberus.png" "$APPDIR/cerberus.png"
else "$PYBIN" "$ROOT/make_icon.py" 2>/dev/null && cp "$ROOT/cerberus.png" "$APPDIR/cerberus.png" || true; fi
[ -f "$APPDIR/cerberus.png" ] && { cp "$APPDIR/cerberus.png" "$APPDIR/.DirIcon"
  cp "$APPDIR/cerberus.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/cerberus.png"; }

cat > "$APPDIR/cerberus.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Cerberus
GenericName=Untrusted-code sandbox
Comment=Run untrusted code in an ephemeral sandbox with real-time syscall defense
Exec=AppRun
Icon=cerberus
Categories=Security;System;
Terminal=false
EOF
cp "$APPDIR/cerberus.desktop" "$APPDIR/usr/share/applications/cerberus.desktop"

# ---- AppRun: launch the native GUI as the user -----------------------------
cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
APPDIR="${APPDIR:-$HERE}"
PYVER="$(cd "$APPDIR/usr/lib" && ls -d python3.* | head -1)"
export PYTHONHOME="$APPDIR/usr"
export PYTHONPATH="$APPDIR/usr/share/cerberus"
export LD_LIBRARY_PATH="$APPDIR/usr/lib:${LD_LIBRARY_PATH:-}"
export TCL_LIBRARY="$APPDIR/usr/share/tcltk/tcl"
export TK_LIBRARY="$APPDIR/usr/share/tcltk/tk"
export PYTHONDONTWRITEBYTECODE=1
# The GUI runs as the user and elevates the sandbox helper itself.
exec "$APPDIR/usr/bin/python3" -m cerberus.gui "$@"
EOF
chmod +x "$APPDIR/AppRun"

echo "==> AppDir ready ($(du -sh "$APPDIR" | cut -f1))"
if [ -x "$ROOT/appimagetool" ]; then
  ARCH=x86_64 "$ROOT/appimagetool" --appimage-extract-and-run "$APPDIR" \
      "$ROOT/Cerberus-native-x86_64.AppImage" && \
      echo "==> built $ROOT/Cerberus-native-x86_64.AppImage"
else
  echo "appimagetool not found next to this script; AppDir is at $APPDIR"
  echo "get it: https://github.com/AppImage/appimagetool/releases  then re-run"
fi
