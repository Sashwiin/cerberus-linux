# Cerberus — native desktop app

A real application window built with **Tkinter** (native OS widgets). No browser,
no HTML, no local web server — the GUI talks to the sandbox engine through a
plain pipe to a privileged helper process.

## Run it now (on your Linux machine)

```bash
./run-native.sh
```

That's it. The window opens; click **Open a script…**, pick a file, and it runs
in the sandbox with the live syscall feed, metrics, and a containment banner
showing the detect-to-freeze latency. A `▶ Run sample` button runs the bundled
villains.

Tkinter ships with CPython but a few distros split it into a package:

| distro | install |
|---|---|
| Debian / Ubuntu / Mint | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Arch | `sudo pacman -S tk` |

## How privilege works

The window runs as **you**. When you check a file, only the sandbox **helper**
(`cerberus.helper`) is elevated — via `pkexec` (a graphical password prompt) or
`sudo` if you launched from a terminal. The helper does the mount / cgroup /
seccomp work as root and streams JSON events back to the window over its stdout.
Nothing about the UI runs as root, and nothing touches the network.

```
  Tkinter window (you) ──spawn pkexec──►  cerberus.helper (root)
        ▲                                        │ builds sandbox, runs monitor
        └──────── JSON events on stdout ─────────┘ freezes on violation
```


## Run inside a disposable VM — still in the native window

Tick **"Run in disposable VM"** in the window (needs `qemu-system-x86_64`). The
first VM run boots a throwaway VM in the background (~20–60s, downloads a small
image once), then every check runs *two boundaries deep* — Cerberus's sandbox
inside the VM — while the live feed, metrics and containment banner appear in the
**same native window**. No browser. The VM is torn down (and its disposable disk
deleted) when you close the window.

Under the hood the window becomes a native client of the sandbox server running
inside the VM, streaming syscall events back over one forwarded port.

## Package it as a single-file native app

To ship one self-contained file that opens the native window with **nothing**
installed on the target, build a native AppImage **on a machine that has Tkinter**
(the build must copy that machine's Tcl/Tk):

```bash
cd packaging
# put appimagetool next to the script (one-time):
#   curl -L -o appimagetool https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
#   chmod +x appimagetool
./build_appimage_native.sh ..
# → Cerberus-native-x86_64.AppImage
```

The script bundles CPython, the Tcl/Tk libraries and script directories, and the
Cerberus source, wiring `TCL_LIBRARY`/`TK_LIBRARY` so the window renders on a
target with no toolkit installed.

> Note: this native-GUI AppImage can only be *assembled* on a host that has
> Tkinter, because it copies that host's Tcl/Tk. The build box used to create
> this repo had no GUI libraries, so the prebuilt file isn't included — running
> the one command above on your desktop produces it.

## Requirements on the machine that runs it

- Linux, **kernel ≥ 5.14** (5.9+ works with slightly weaker teardown), **cgroup v2**.
- `python3-tk` (for `run-native.sh`) — or nothing, if you use the native AppImage.
- `pkexec` (polkit) for the graphical prompt, or run from a terminal with `sudo`.
