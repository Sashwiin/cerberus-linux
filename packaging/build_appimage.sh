#!/usr/bin/env bash
# Build Cerberus.AppImage — a portable, self-contained Linux app.
#
# Bundles a relocatable CPython plus the Cerberus source, and an AppRun that
# opens the dashboard in the user's browser while elevating ONLY the sandbox
# server via pkexec (Cerberus needs root for mount/cgroup/seccomp). The
# privilege split keeps the browser in the user's session and the server as
# root, which is what actually works on a real desktop.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$ROOT/../cerberus}"          # the Cerberus repo
APPDIR="$ROOT/Cerberus.AppDir"
PYBIN="$(command -v python3.11 || command -v python3)"
PYVER="$("$PYBIN" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
STDLIB="$("$PYBIN" -c 'import sysconfig;print(sysconfig.get_path("stdlib"))')"

echo "==> python: $PYBIN ($PYVER)   stdlib: $STDLIB"
echo "==> source: $SRC"

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" "$APPDIR/usr/share/cerberus" \
         "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# ---- 1. bundle the interpreter + stdlib -------------------------------------
echo "==> bundling CPython $PYVER"
cp "$(readlink -f "$PYBIN")" "$APPDIR/usr/bin/python3"
cp -a "$STDLIB" "$APPDIR/usr/lib/python$PYVER"

# small, non-glibc shared libs python needs (glibc/ld stay on the host)
for lib in libz.so.1 libexpat.so.1 libffi.so.8 libffi.so.7 libbz2.so.1.0 liblzma.so.5; do
  f=$(ldconfig -p 2>/dev/null | awk -v L="$lib" '$1==L{print $NF; exit}') || true
  [ -n "${f:-}" ] && cp -L "$f" "$APPDIR/usr/lib/" 2>/dev/null && echo "    + $lib" || true
done

# trim the stdlib: things a headless server never needs
echo "==> trimming stdlib"
( cd "$APPDIR/usr/lib/python$PYVER" && rm -rf \
    test tests idlelib turtledemo tkinter lib2to3 ensurepip \
    config-*/libpython*.a distutils/tests unittest/test \
    __pycache__ */__pycache__ */*/__pycache__ 2>/dev/null || true )
find "$APPDIR/usr/lib/python$PYVER" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# ---- 2. the Cerberus app ----------------------------------------------------
echo "==> copying Cerberus source"
for d in cerberus static payloads; do
  cp -a "$SRC/$d" "$APPDIR/usr/share/cerberus/"
done
cp "$SRC/README.md" "$SRC/DEMO.md" "$SRC/LICENSE" "$APPDIR/usr/share/cerberus/" 2>/dev/null || true
find "$APPDIR/usr/share/cerberus" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# ---- 3. icon ----------------------------------------------------------------
cat > "$ROOT/make_icon.py" <<'PY'
# Draw the Cerberus mark (a three-headed watchdog silhouette) as a 256px PNG,
# using only the stdlib (zlib) so the build needs no image libraries.
import struct, zlib, math
S=256
buf=bytearray(b'\x00'*(S*S*4))
def px(x,y,r,g,b,a=255):
    if 0<=x<S and 0<=y<S:
        i=(y*S+x)*4; buf[i:i+4]=bytes((r,g,b,a))
def disc(cx,cy,rad,col):
    for y in range(int(cy-rad),int(cy+rad+1)):
        for x in range(int(cx-rad),int(cx+rad+1)):
            if (x-cx)**2+(y-cy)**2<=rad*rad: px(x,y,*col)
# dark rounded background
bg=(17,23,34)
for y in range(S):
    for x in range(S):
        dx=min(x,S-1-x); dy=min(y,S-1-y)
        if dx+dy>18 or (dx>18 and dy>18): px(x,y,*bg)
# purple ring
ring=(124,92,255)
for a in range(0,360,1):
    r=112
    x=128+r*math.cos(math.radians(a)); y=128+r*math.sin(math.radians(a))
    disc(x,y,4,ring)
# three glowing red "heads"
red=(248,81,73)
disc(92,150,15,red); disc(128,132,17,red); disc(164,150,15,red)
# a muzzle arc under them
arc=(124,92,255)
for a in range(200,340):
    x=128+58*math.cos(math.radians(a)); y=170+40*math.sin(math.radians(a))
    disc(x,y,5,arc)
# encode PNG
raw=bytearray()
for y in range(S):
    raw.append(0); raw+=buf[y*S*4:(y+1)*S*4]
def chunk(t,d):
    c=struct.pack('>I',len(d))+t+d; return c+struct.pack('>I',zlib.crc32(t+d)&0xffffffff)
png=b'\x89PNG\r\n\x1a\n'
png+=chunk(b'IHDR',struct.pack('>IIBBBBB',S,S,8,6,0,0,0))
png+=chunk(b'IDAT',zlib.compress(bytes(raw),9))
png+=chunk(b'IEND',b'')
open('cerberus.png','wb').write(png)
print("icon written")
PY
( cd "$ROOT" && "$PYBIN" make_icon.py )
cp "$ROOT/cerberus.png" "$APPDIR/cerberus.png"
cp "$ROOT/cerberus.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/cerberus.png"
cp "$ROOT/cerberus.png" "$APPDIR/.DirIcon"

# ---- 4. desktop entry -------------------------------------------------------
cat > "$APPDIR/cerberus.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Cerberus
GenericName=Untrusted-code sandbox
Comment=Run untrusted code in an ephemeral sandbox with real-time syscall defense
Exec=AppRun
Icon=cerberus
Categories=Security;System;Development;
Terminal=false
Keywords=sandbox;seccomp;security;malware;
EOF
cp "$APPDIR/cerberus.desktop" "$APPDIR/usr/share/applications/cerberus.desktop"

# ---- 5. AppRun --------------------------------------------------------------
cp "$ROOT/AppRun" "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun"

echo "==> AppDir size: $(du -sh "$APPDIR" | cut -f1)"

# ---- 6. package -------------------------------------------------------------
echo "==> packaging with appimagetool"
export ARCH=x86_64
if "$ROOT/appimagetool" --appimage-extract-and-run "$APPDIR" "$ROOT/Cerberus-x86_64.AppImage" 2>&1; then
  echo "==> built: $ROOT/Cerberus-x86_64.AppImage"
else
  echo "!! appimagetool failed; the AppDir is still usable via ./Cerberus.AppDir/AppRun"
fi
