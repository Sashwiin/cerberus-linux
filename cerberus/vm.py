"""cerberus vm — run Cerberus inside a disposable QEMU/KVM virtual machine.

This is the boundary that makes Cerberus safe against a *kernel* escape. Even
after the in-process hardening, everything runs on the host kernel, so a kernel
exploit defeats the sandbox. Put the whole thing inside a throwaway VM and a
break-out only wrecks the VM, which is deleted the moment it exits.

What this does, in one command:

  1. fetches a small cloud image once (cached), never modified;
  2. makes a *copy-on-write overlay* so the run is disposable;
  3. builds a cloud-init seed (pure-Python ISO, no external tools) that carries
     the Cerberus source in and auto-starts the dashboard on boot;
  4. boots QEMU with an *isolated* network (no route to your LAN or the
     internet) except one forwarded port for the dashboard;
  5. on exit, deletes the overlay so nothing the guest did survives.

Dependencies on the host: qemu-system-x86_64 and qemu-img (package qemu-kvm /
qemu-system-x86 / qemu-utils). KVM (/dev/kvm) is used when present and the tool
falls back to slower TCG emulation otherwise. Nothing else -- the seed ISO is
written here in pure Python.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import textwrap
import time
import urllib.request
from pathlib import Path

from .iso9660 import write_iso

CACHE = Path(os.environ.get("CERBERUS_VM_CACHE",
                            os.path.expanduser("~/.cache/cerberus-vm")))

# Small, cloud-init-ready base images. These are the official upstream URLs; the
# file is downloaded once and never changed (runs use overlays).
IMAGES = {
    "ubuntu": {
        "url": "https://cloud-images.ubuntu.com/releases/24.04/release/"
               "ubuntu-24.04-server-cloudimg-amd64.img",
        "login": "ubuntu",
    },
    "debian": {
        "url": "https://cloud.debian.org/images/cloud/bookworm/latest/"
               "debian-12-genericcloud-amd64.qcow2",
        "login": "debian",
    },
    "fedora": {
        "url": "https://download.fedoraproject.org/pub/fedora/linux/releases/40/"
               "Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2",
        "login": "fedora",
    },
}


def _c(txt: str, color: str) -> str:
    if not sys.stderr.isatty():
        return txt
    codes = {"purple": "35", "red": "1;31", "green": "32", "dim": "2", "b": "1"}
    return f"\033[{codes.get(color, '0')}m{txt}\033[0m"


def log(msg: str) -> None:
    print(_c("[cerberus-vm]", "purple") + " " + msg, file=sys.stderr, flush=True)


def die(msg: str, code: int = 1):
    print(_c("[cerberus-vm] error:", "red") + " " + msg, file=sys.stderr)
    raise SystemExit(code)


def _have(prog: str) -> str | None:
    return shutil.which(prog)


def _check_deps() -> tuple[str, str]:
    qemu = _have("qemu-system-x86_64")
    qimg = _have("qemu-img")
    if not qemu or not qimg:
        die("QEMU is required. Install it:\n"
            "  Debian/Ubuntu : sudo apt install qemu-system-x86 qemu-utils\n"
            "  Fedora        : sudo dnf install @virtualization qemu-img\n"
            "  Arch          : sudo pacman -S qemu-full")
    return qemu, qimg


def _kvm_ok() -> bool:
    return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)


# --------------------------------------------------------------- source bundle


def _project_root() -> Path:
    # cerberus/vm.py -> project root is the parent of the package dir
    return Path(__file__).resolve().parent.parent


def _make_source_tar() -> bytes:
    root = _project_root()
    buf = io.BytesIO()
    import gzip
    # Deterministic gzip (mtime=0) so the same source always yields the same
    # seed bytes -- reproducible builds, and stable to test against.
    def _norm(ti):
        if "__pycache__" in ti.name:
            return None
        ti.mtime = 0  # stable across runs
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    gz = gzip.GzipFile(fileobj=buf, mode="wb", mtime=0)
    with tarfile.open(fileobj=gz, mode="w") as tar:
        for sub in ("cerberus", "static", "payloads"):
            p = root / sub
            if p.is_dir():
                tar.add(p, arcname=sub, filter=_norm)
    gz.close()
    return buf.getvalue()


# ------------------------------------------------------------------ cloud-init


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def build_seed(port: int) -> bytes:
    """Build a NoCloud seed ISO carrying the source and a boot-time launcher.

    The YAML is assembled with explicit indentation rather than textwrap.dedent:
    the embedded base64 tarball is the least-indented content, so dedent would
    take *it* as the baseline and strip every file body out from under its
    `content:` key -- producing malformed cloud-config that cloud-init silently
    skips (write_files/runcmd never run, dashboard never starts, browser gets an
    empty response). The whole document is validated by a YAML parser in tests.
    """
    tgz_b64 = base64.b64encode(_make_source_tar()).decode()
    b64_block = _indent("\n".join(tgz_b64[i:i + 76]
                                  for i in range(0, len(tgz_b64), 76)), 6)

    start_script = _indent(_START_SH.format(port=port), 6)
    wait_script = _indent(_WAIT_PY.format(port=port), 6)

    user_data = (
        "#cloud-config\n"
        "hostname: cerberus\n"
        "password: cerberus\n"
        "chpasswd:\n"
        "  expire: false\n"
        "ssh_pwauth: true\n"
        "write_files:\n"
        "  - path: /opt/cerberus.tgz.b64\n"
        "    permissions: '0600'\n"
        "    content: |\n"
        f"{b64_block}\n"
        "  - path: /usr/local/bin/cerberus-start\n"
        "    permissions: '0755'\n"
        "    content: |\n"
        f"{start_script}\n"
        "  - path: /usr/local/bin/cerberus-wait\n"
        "    permissions: '0755'\n"
        "    content: |\n"
        f"{wait_script}\n"
        "runcmd:\n"
        '  - [ sh, -c, "nohup cerberus-start >/dev/null 2>&1 &" ]\n'
        '  - [ sh, -c, "nohup cerberus-wait >/dev/null 2>&1 &" ]\n'
    )
    meta_data = ("instance-id: cerberus-" + str(int(time.time())) +
                 "\nlocal-hostname: cerberus\n")
    return _seed_iso(user_data.encode(), meta_data.encode())


# Guest boot launcher. Prints to the log AND the serial console so a failed boot
# is visible in the QEMU window instead of a silent empty page in the browser.
_START_SH = """\
#!/bin/sh
exec >>/var/log/cerberus.log 2>&1
say() {{ echo ">>> cerberus: $*" | tee /dev/console; }}
say "extracting source"
mkdir -p /opt/cerberus
if ! base64 -d /opt/cerberus.tgz.b64 | tar xzf - -C /opt/cerberus; then
  say "EXTRACT FAILED"; exit 1
fi
cd /opt/cerberus
if ! python3 -c "import cerberus.web" 2>&1 | tee /dev/console; then
  say "IMPORT FAILED (traceback above)"; exit 1
fi
say "starting dashboard on :{port}"
exec python3 -m cerberus.web --host 0.0.0.0 --port {port}
"""

# Readiness probe: reports UP (or failure) to the serial console.
_WAIT_PY = """\
#!/usr/bin/python3
import time, urllib.request
url = "http://127.0.0.1:{port}/"
for _ in range(60):
    try:
        urllib.request.urlopen(url, timeout=1)
        open("/dev/console", "w").write(
            "\\n>>> CERBERUS DASHBOARD IS UP - open "
            "http://127.0.0.1:{port} on your host <<<\\n")
        break
    except Exception:
        time.sleep(1)
else:
    open("/dev/console", "w").write(
        "\\n>>> CERBERUS FAILED TO START - log in (cerberus/cerberus) "
        "and run: cat /var/log/cerberus.log <<<\\n")
"""


def _seed_iso(user_data: bytes, meta_data: bytes) -> bytes:
    """Make a NoCloud 'cidata' seed ISO.

    Prefers the battle-tested tools if the host has them (they are correct and
    widely used); otherwise falls back to the bundled pure-Python ISO9660 +
    Rock Ridge writer so the launcher works with nothing but QEMU installed.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        dp = Path(d)
        (dp / "user-data").write_bytes(user_data)
        (dp / "meta-data").write_bytes(meta_data)
        out = dp / "seed.iso"

        if _have("cloud-localds"):
            try:
                subprocess.run(["cloud-localds", str(out), str(dp / "user-data"),
                                str(dp / "meta-data")], check=True,
                               capture_output=True)
                return out.read_bytes()
            except subprocess.CalledProcessError:
                pass
        for tool in ("genisoimage", "mkisofs", "xorriso"):
            if not _have(tool):
                continue
            base = [tool]
            if tool == "xorriso":
                base = ["xorriso", "-as", "mkisofs"]
            try:
                subprocess.run(base + ["-output", str(out), "-volid", "cidata",
                                       "-joliet", "-rock",
                                       str(dp / "user-data"), str(dp / "meta-data")],
                               check=True, capture_output=True)
                return out.read_bytes()
            except subprocess.CalledProcessError:
                continue

    # Pure-Python fallback (Rock Ridge names preserved, validated in tests).
    return write_iso({"user-data": user_data, "meta-data": meta_data}, "CIDATA")


# ----------------------------------------------------------------- image mgmt


def ensure_base(distro: str, progress=None) -> Path:
    """Return the cached base image, downloading it once.

    `progress(msg)` (optional) is called with human-readable status so a GUI can
    show download percentage instead of a frozen "please wait".
    """
    if distro not in IMAGES:
        die(f"unknown image '{distro}'; choose from {', '.join(IMAGES)}")
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"base-{distro}.img"
    if dest.exists() and dest.stat().st_size > 0:
        if progress:
            progress(f"using cached {distro} image")
        return dest
    url = IMAGES[distro]["url"]
    log(f"downloading {distro} cloud image (one time)…")
    if progress:
        progress(f"downloading {distro} image (one-time, a few hundred MB)…")
    tmp = dest.with_suffix(".part")
    try:
        with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
            total = int(r.headers.get("Content-Length", 0))
            got = last_pct = 0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if total:
                    pct = 100 * got // total
                    print(f"\r  {pct:3d}%  {got >> 20} / {total >> 20} MiB",
                          end="", file=sys.stderr)
                    # throttle GUI updates to every ~3%
                    if progress and pct >= last_pct + 3:
                        last_pct = pct
                        progress(f"downloading {distro} image "
                                 f"{pct}% ({got >> 20}/{total >> 20} MiB)")
        print(file=sys.stderr)
        tmp.rename(dest)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        die(f"download failed: {exc}\nDownload it manually to {dest} and re-run.")
    return dest


def make_overlay(base: Path, qimg: str) -> Path:
    overlay = CACHE / f"run-{os.getpid()}-{int(time.time())}.qcow2"
    subprocess.run([qimg, "create", "-q", "-f", "qcow2",
                    "-F", "qcow2", "-b", str(base), str(overlay), "16G"],
                   check=True)
    return overlay


# ------------------------------------------------------------------- qemu run


def qemu_argv(qemu: str, overlay: Path, seed: Path, port: int,
              memory: int, cpus: int, allow_net: bool) -> list[str]:
    net = (f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{port}"
           + ("" if allow_net else ",restrict=on"))
    argv = [
        qemu,
        "-name", "cerberus-vm",
        "-m", str(memory),
        "-smp", str(cpus),
        "-drive", f"file={overlay},if=virtio,cache=unsafe",
        "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
        "-netdev", net,
        "-device", "virtio-net-pci,netdev=n0",
        "-display", "none",
        "-serial", "mon:stdio",
    ]
    if _kvm_ok():
        argv[1:1] = ["-enable-kvm", "-cpu", "host"]
    else:
        argv[1:1] = ["-cpu", "max"]  # TCG fallback
    return argv


class VMHandle:
    """A booted disposable VM, with a cleanup that deletes its overlay/seed."""

    def __init__(self, proc, port, cleanup):
        self.proc = proc
        self.port = port
        self._cleanup = cleanup

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        p = self.proc
        if p and p.poll() is None:
            try:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            except Exception:
                pass
        self._cleanup()


def spawn_vm(port: int = 8787, image: str = "ubuntu", memory: int = 2048,
             cpus: int = 2, allow_net: bool = False,
             progress=None) -> VMHandle:
    """Boot a disposable VM in the background and return a handle.

    Used by the native GUI's "run in VM" mode. `progress(msg)` (optional) reports
    each stage (download %, overlay, launching QEMU) so the UI shows real
    activity. The handle's `proc.stdout` is the VM's serial console — the caller
    can read it line by line to show the live boot. Raises RuntimeError with a
    clear message if QEMU or the image can't be prepared. `stop()` terminates
    QEMU and deletes the disposable overlay.
    """
    def say(m):
        if progress:
            progress(m)

    qemu = _have("qemu-system-x86_64")
    qimg = _have("qemu-img")
    if not qemu or not qimg:
        raise RuntimeError(
            "QEMU not found. Install qemu-system-x86 and qemu-utils "
            "(apt), or @virtualization + qemu-img (dnf).")
    base = ensure_base(image, progress=progress)
    say("creating disposable overlay disk…")
    overlay = make_overlay(base, qimg)
    say("building cloud-init seed…")
    seed_path = CACHE / f"seed-{os.getpid()}-{port}.iso"
    seed_path.write_bytes(build_seed(port))
    argv = qemu_argv(qemu, overlay, seed_path, port, memory, cpus, allow_net)
    say("launching QEMU " + ("(KVM)" if _kvm_ok() else "(TCG, no KVM — slower)")
        + " …")

    # Capture the serial console so the GUI can show the live boot.
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            bufsize=1, text=True, errors="replace")

    def cleanup():
        overlay.unlink(missing_ok=True)
        seed_path.unlink(missing_ok=True)

    return VMHandle(proc, port, cleanup)


def cmd_run(args) -> int:
    # --dry-run previews the plan without needing QEMU installed or a download.
    if args.dry_run:
        qemu = _have("qemu-system-x86_64") or "qemu-system-x86_64"
        CACHE.mkdir(parents=True, exist_ok=True)
        seed_path = CACHE / f"seed-dryrun.iso"
        seed_path.write_bytes(build_seed(args.port))
        overlay = CACHE / "base-<image>.qcow2 (overlay, disposable)"
        argv = qemu_argv(qemu, overlay, seed_path, args.port, args.memory,
                         args.cpus, args.allow_net)
        log("dry run — would launch:")
        print("  " + " ".join(str(a) for a in argv))
        log(f"seed ISO built OK: {seed_path} ({seed_path.stat().st_size} bytes, "
            f"carries the Cerberus source + boot launcher)")
        log("network: " + ("ALLOWED" if args.allow_net else "ISOLATED (restrict=on)"))
        log("kvm: " + ("available" if _kvm_ok() else "not present -> TCG fallback"))
        return 0

    qemu, qimg = _check_deps()
    base = ensure_base(args.image)
    overlay = make_overlay(base, qimg)
    seed_path = CACHE / f"seed-{os.getpid()}.iso"
    seed_path.write_bytes(build_seed(args.port))

    argv = qemu_argv(qemu, overlay, seed_path, args.port, args.memory,
                     args.cpus, args.allow_net)

    if not _kvm_ok():
        log(_c("no /dev/kvm — using slow TCG emulation. Boot may take minutes.",
               "dim"))
    net_msg = ("network ISOLATED (no LAN/internet egress)" if not args.allow_net
               else _c("network ALLOWED — guest can reach the internet", "red"))
    log(net_msg)
    log(f"booting disposable VM ({args.image}); dashboard will be at "
        + _c(f"http://127.0.0.1:{args.port}", "b"))
    log("give it ~20–40s to boot, then open that URL in your browser.")
    log(_c("the serial console below shows a login prompt — ignore it; you don't "
           "need to log in.", "dim"))
    log(_c("(if you ever want to peek inside for debugging: user 'cerberus', "
           "password 'cerberus')", "dim"))
    log("Ctrl-C here destroys the VM and leaves nothing behind.")

    proc = None
    try:
        proc = subprocess.Popen(argv)
        proc.wait()
    except KeyboardInterrupt:
        log("shutting down VM…")
        if proc:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        # The whole point: the run leaves nothing behind.
        overlay.unlink(missing_ok=True)
        seed_path.unlink(missing_ok=True)
        log("overlay and seed deleted — nothing the guest did survives.")
    return 0


def cmd_clean(args) -> int:
    if not CACHE.exists():
        log("nothing to clean")
        return 0
    for p in CACHE.glob("run-*.qcow2"):
        p.unlink(missing_ok=True)
    for p in CACHE.glob("seed-*.iso"):
        p.unlink(missing_ok=True)
    if args.images:
        for p in CACHE.glob("base-*.img"):
            p.unlink(missing_ok=True)
        log("removed cached base images too")
    log("cleaned disposable run files")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cerberus-vm",
        description="Run Cerberus inside a disposable QEMU/KVM VM.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="boot a disposable VM running the dashboard")
    r.add_argument("--image", default="ubuntu", choices=list(IMAGES),
                   help="base cloud image (default: ubuntu)")
    r.add_argument("--port", type=int, default=8787, help="dashboard port")
    r.add_argument("--memory", type=int, default=2048, help="guest RAM (MiB)")
    r.add_argument("--cpus", type=int, default=2, help="guest vCPUs")
    r.add_argument("--allow-net", action="store_true",
                   help="DANGER: give the guest real network access")
    r.add_argument("--dry-run", action="store_true",
                   help="print the QEMU command and exit without booting")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("clean", help="remove cached overlays/seeds")
    c.add_argument("--images", action="store_true",
                   help="also delete downloaded base images")
    c.set_defaults(func=cmd_clean)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
