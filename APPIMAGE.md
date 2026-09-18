# Cerberus as a Linux app (AppImage)

`Cerberus-x86_64.AppImage` is a single, self-contained file. It bundles its own
Python runtime and the whole app — nothing to install. Copy it to any 64-bit
Linux machine and run it.

## Run it

```bash
chmod +x Cerberus-x86_64.AppImage
./Cerberus-x86_64.AppImage
```

Or double-click it in your file manager. A graphical password prompt appears
(Cerberus needs root for mount / cgroup / seccomp), then the dashboard opens in
your browser at `http://127.0.0.1:8787`. Drop a script on the page to check it.

To put it in your applications menu, drop the file into `~/Applications` and most
desktops pick it up; or install with
[`appimaged`](https://github.com/probonopd/go-appimage).

## How it stays correct about privileges

Cerberus needs root, but a double-clicked AppImage runs as **you**, and the
browser must open in **your** session. So the launcher splits the privilege:

- the sandbox **server** is elevated with `pkexec` (one password prompt), and
- the **browser** is opened as you.

They meet over `127.0.0.1`. Because an AppImage's mount is private to the user
who mounted it (a root process can't read it), the launcher first stages the
bundle to a world-readable temp dir and runs the elevated server from there.

## Requirements on the target machine

- 64-bit Linux, **kernel ≥ 5.14** (5.9+ works with slightly weaker teardown).
- **cgroup v2** — the default on Fedora and recent Ubuntu/Debian/Arch. Check
  with `stat -fc %T /sys/fs/cgroup` (want `cgroup2fs`).
- **FUSE 2** to mount the AppImage (`libfuse2` on Debian/Ubuntu). If it's
  missing, run without mounting:
  ```bash
  ./Cerberus-x86_64.AppImage --appimage-extract-and-run
  ```
- `pkexec` (polkit) for the graphical prompt, or `sudo` if you launch from a
  terminal. Without a desktop session, run `sudo ./Cerberus-x86_64.AppImage`.

## Options

```bash
CERBERUS_PORT=9000 ./Cerberus-x86_64.AppImage      # use a different port
sudo ./Cerberus-x86_64.AppImage                    # terminal, no pkexec prompt
./Cerberus-x86_64.AppImage --appimage-extract      # unpack to squashfs-root/
```

## Rebuilding it

The AppImage is produced by `build/build_appimage.sh`, which bundles the
system's CPython plus `cerberus/`, `static/`, and `payloads/`, writes an icon and
desktop entry, and packages everything with `appimagetool`. From a checkout with
`appimagetool` next to the script:

```bash
cd build && ./build_appimage.sh /path/to/cerberus
```

The launcher logic lives in `build/AppRun`.
