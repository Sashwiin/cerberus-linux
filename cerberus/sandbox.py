"""The isolation layer: namespaces, a tmpfs root, and nothing on disk.

Deliberately hand-rolled on top of `unshare(2)`/`pivot_root(2)` rather than
shelling out to bubblewrap or nsjail. Two reasons: Cerberus has to install its
own seccomp filter at a precise point in the setup (after the mount namespace
is built, immediately before `execve`), which an external launcher does not
expose; and the whole point of the project is the seam between isolation and
monitoring, so owning both sides keeps that seam visible.

The filesystem the payload sees is a fresh tmpfs. Interpreters and libraries
are bind-mounted in read-only, the working directory is RAM, and when the
mount namespace goes away at exit the kernel reclaims all of it. Nothing is
written to persistent storage, so there is nothing to clean up and nothing to
recover afterwards.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import resource
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import seccomp
from .cgroup import Cgroup

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_NOATIME = 1024

MNT_DETACH = 2


def _chk(ret: int, what: str) -> int:
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{what}: {os.strerror(err)}")
    return ret


def _mount(source: str, target: str, fstype: str | None, flags: int, data: str | None) -> None:
    _chk(
        _libc.mount(
            source.encode() if source else None,
            target.encode(),
            fstype.encode() if fstype else None,
            ctypes.c_ulong(flags),
            data.encode() if data else None,
        ),
        f"mount({source} -> {target}, {fstype}, flags={flags:#x})",
    )


def _umount2(target: str, flags: int) -> None:
    _chk(_libc.umount2(target.encode(), flags), f"umount2({target})")


def _pivot_root(new_root: str, put_old: str) -> None:
    # No libc wrapper on glibc; go through syscall(2). __NR_pivot_root = 155.
    _chk(_libc.syscall(155, new_root.encode(), put_old.encode()), "pivot_root")


def _unshare(flags: int) -> None:
    _chk(_libc.unshare(flags), f"unshare({flags:#x})")


# Read-only bind mounts the payload needs in order to be able to run at all.
# Note that /etc is included: the demo depends on a sensitive file such as
# /etc/shadow being *reachable* so that the monitor gets the chance to refuse
# it. Isolation that simply hid the file would prove nothing about detection.
DEFAULT_BINDS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc")
DEVICE_NODES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/urandom", "/dev/random", "/dev/tty")


@dataclass
class SandboxSpec:
    argv: list[str]
    tmpfs_size: str = "64M"
    net: str = "none"  # "none" = empty netns, "host" = share the host's
    memory_max: str | None = "256M"
    pids_max: str | None = "64"
    cpu_max: str | None = None
    binds: tuple[str, ...] = DEFAULT_BINDS
    workdir_files: dict[str, bytes] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    nofile: int = 256
    fsize_mb: int = 16
    # The uploaded code runs as this uid/gid, never as root. 65534 is the
    # conventional "nobody"/"nogroup" id. Setup (mount, pivot_root) needs root,
    # so the drop happens at the last possible moment, right before execve.
    uid: int = 65534
    gid: int = 65534

    def base_env(self) -> dict[str, str]:
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/work",
            "TMPDIR": "/tmp",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "CERBERUS_SANDBOX": "1",
        }
        env.update(self.env)
        return env


class SandboxLaunchError(RuntimeError):
    pass


def _build_rootfs(spec: SandboxSpec) -> str:
    """Create the tmpfs root and populate it. Returns the new root path."""
    root = "/tmp/.cerberus-root"
    os.makedirs(root, exist_ok=True)
    # A tmpfs is its own mount point, which pivot_root requires.
    _mount(
        "cerberus", root, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOATIME,
        f"size={spec.tmpfs_size},mode=0755",
    )

    for d in ("proc", "dev", "work", "tmp", "old_root"):
        os.makedirs(os.path.join(root, d), exist_ok=True)

    for src in spec.binds:
        if not os.path.isdir(src):
            continue
        dst = os.path.join(root, src.lstrip("/"))
        os.makedirs(dst, exist_ok=True)
        _mount(src, dst, None, MS_BIND | MS_REC, None)
        # A bind mount is read-write until it is remounted read-only; doing it
        # in one step is a common and silent mistake.
        _mount("", dst, None, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_REC, None)

    dev = os.path.join(root, "dev")
    _mount("cerberus-dev", dev, "tmpfs", MS_NOSUID, "size=1M,mode=0755")
    for node in DEVICE_NODES:
        if not os.path.exists(node):
            continue
        target = os.path.join(root, node.lstrip("/"))
        with open(target, "w"):
            pass
        try:
            _mount(node, target, None, MS_BIND, None)
        except OSError:
            os.unlink(target)

    work = os.path.join(root, "work")
    _mount("cerberus-work", work, "tmpfs", MS_NOSUID | MS_NODEV, "size=16M,mode=0777")
    _mount(
        "cerberus-tmp", os.path.join(root, "tmp"), "tmpfs",
        MS_NOSUID | MS_NODEV, "size=16M,mode=1777",
    )

    for name, content in spec.workdir_files.items():
        target = os.path.join(work, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(content)
        os.chmod(target, 0o755)

    return root


def _enter_rootfs(root: str) -> None:
    os.chdir(root)
    _pivot_root(root, os.path.join(root, "old_root"))
    os.chdir("/")
    # /proc must be mounted *after* pivot_root and from inside the new pid
    # namespace, so that it reflects the sandbox's own process tree.
    _mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)
    _umount2("/old_root", MNT_DETACH)
    try:
        os.rmdir("/old_root")
    except OSError:
        pass


def _drop_privileges(uid: int, gid: int) -> None:
    """Irreversibly drop to an unprivileged uid/gid.

    Order matters: clear supplementary groups and set the gid while still root,
    then set the uid last -- after setuid the process no longer has the
    privilege to change its gid. setresuid/setresgid set all three of real,
    effective and saved ids, so there is no saved-uid left to switch back to.
    """
    if uid == 0 and gid == 0:
        return  # explicitly opted out of the drop
    try:
        os.setgroups([])
    except OSError:
        pass
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # Sanity: if we somehow still hold uid 0, refuse to run the payload rather
    # than run untrusted code as root.
    if os.getuid() == 0 or os.geteuid() == 0:
        raise PermissionError("failed to drop root before executing payload")


def _apply_rlimits(spec: SandboxSpec) -> None:
    for what, limit in (
        (resource.RLIMIT_NOFILE, (spec.nofile, spec.nofile)),
        (resource.RLIMIT_CORE, (0, 0)),
        (resource.RLIMIT_FSIZE, (spec.fsize_mb << 20, spec.fsize_mb << 20)),
    ):
        try:
            resource.setrlimit(what, limit)
        except (ValueError, OSError):
            pass


def launch(
    spec: SandboxSpec,
    cgroup: Cgroup,
    notify: list[int],
    deny: list[int],
    default_allow: bool = True,
    allow: list[int] | tuple[int, ...] = (),
) -> tuple[int, seccomp.Listener]:
    """Start the payload, suspended, and return (outer_pid, listener).

    The payload is stopped at the socket read in step 9 below and does not run
    a single instruction of its own code until `release()` is called on the
    returned listener's companion pipe. That ordering matters: the supervisor
    is watching before the payload is alive, so there is no unmonitored window
    at startup.
    """
    if spec.net not in ("none", "host"):
        raise ValueError(f"unknown net mode {spec.net!r}")

    # Signalling between the sandbox and the supervisor rides on PIPES, not a
    # socket, and the reason is the whole reason this handshake is subtle.
    #
    # Once the inner process installs the seccomp filter, every syscall in the
    # notify set parks in the kernel until the supervisor answers it -- and the
    # supervisor cannot answer until it holds the listener fd. So between
    # installing the filter and the supervisor going live, the inner process
    # may touch *only* syscalls that are not in the notify set. `sendmsg`,
    # `sendto` and `socket` all are, which rules out a socket for signalling
    # (an earlier version deadlocked on exactly this). Plain pipe read()/write()
    # are not notified, so they are safe. The listener fd itself is pulled by
    # the supervisor with pidfd_getfd rather than pushed over SCM_RIGHTS, for
    # the same reason: SCM_RIGHTS rides on sendmsg.
    pid_r, pid_w = os.pipe()        # intermediate -> supervisor: inner's pid
    ready_r, ready_w = os.pipe()    # inner -> supervisor: "filter installed"
    go_r, go_w = os.pipe()          # supervisor -> inner: "you may exec now"

    LISTENER_FD_SLOT = 200  # a fixed, unused fd number the supervisor pulls from

    pid = os.fork()
    if pid == 0:
        # ---------------------------------------------- intermediate child
        try:
            os.close(pid_r)
            os.close(ready_r)
            os.close(go_w)
            cgroup.add_pid(os.getpid())

            flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP
            if spec.net == "none":
                flags |= CLONE_NEWNET
            # CLONE_NEWPID only takes effect for *children*, so the caller of
            # unshare stays in the old pid namespace; the inner fork is pid 1
            # of the new one.
            _unshare(flags)

            inner = os.fork()
            if inner != 0:
                # The intermediate shares the supervisor's pid namespace, so
                # the pid it gets for `inner` is valid there too. Relay it so
                # the supervisor can open a pidfd on the sandbox init process.
                os.write(pid_w, struct.pack("=i", inner))
                os.close(pid_w)
                os.close(ready_w)
                os.close(go_r)
                _, status = os.waitpid(inner, 0)
                os._exit(os.waitstatus_to_exitcode(status) & 0xFF
                         if os.WIFEXITED(status) else 128 + (status & 0x7F))

            # ------------------------------------------ sandbox init (pid 1)
            os.close(pid_w)
            # Detach mount propagation, or our tmpfs and binds leak back to the
            # host mount namespace.
            _mount("", "/", None, MS_REC | MS_PRIVATE, None)
            root = _build_rootfs(spec)
            _enter_rootfs(root)
            os.chdir("/work")
            try:
                _libc.sethostname(b"cerberus", 8)
            except Exception:
                pass
            _apply_rlimits(spec)
            # NO_NEW_PRIVS makes the filter un-droppable and blocks setuid
            # escalation through any binary we bind-mounted in.
            seccomp.set_no_new_privs()
            # Drop root BEFORE installing the filter, not after: setuid/setgid
            # are escape-class syscalls, so a post-filter drop would be parked
            # and frozen as a violation by our own monitor. With NO_NEW_PRIVS
            # already set, an unprivileged process is still allowed to install a
            # seccomp filter, so the order setup(root) -> drop -> install -> exec
            # keeps the whole payload off root while losing nothing.
            _drop_privileges(spec.uid, spec.gid)
            fd = seccomp.install_filter(notify, deny, default_allow, allow)

            # --- from here until execve: no notified syscalls allowed ---
            os.dup2(fd, LISTENER_FD_SLOT)  # dup2/dup3: not notified
            os.close(fd)
            os.write(ready_w, b"R")        # write: not notified
            os.close(ready_w)

            # Block (read: not notified) until the supervisor has stolen the fd
            # and its monitor loop is live.
            go = os.read(go_r, 1)
            if go != b"G":
                os._exit(3)
            os.close(go_r)
            # Drop our copy of the listener before handing control to the
            # payload, so untrusted code can never touch it. dup2 cleared
            # CLOEXEC on the slot, hence the explicit close.
            os.close(LISTENER_FD_SLOT)

            env = spec.base_env()
            # execve IS notified -- and that is fine: the supervisor is live
            # now and will adjudicate it as the payload's first monitored call.
            os.execvpe(spec.argv[0], spec.argv, env)
            os._exit(127)
        except BaseException as exc:  # pragma: no cover - child bail-out path
            try:
                os.write(2, f"[cerberus/sandbox] {exc!r}\n".encode())
            except Exception:
                pass
            os._exit(4)

    # ----------------------------------------------------------- supervisor
    os.close(pid_w)
    os.close(ready_w)
    os.close(go_r)

    inner_pid = _read_exact(pid_r, 4, timeout=10.0)
    os.close(pid_r)
    ready = _read_exact(ready_r, 1, timeout=10.0)
    os.close(ready_r)

    if inner_pid is None or ready != b"R":
        os.close(go_w)
        raise SandboxLaunchError(
            "sandbox exited during setup before installing a seccomp filter"
        )
    inner_pid_val = struct.unpack("=i", inner_pid)[0]

    listener_fd = _pidfd_steal(inner_pid_val, LISTENER_FD_SLOT)
    if listener_fd < 0:
        os.close(go_w)
        raise SandboxLaunchError("could not acquire the seccomp listener fd")
    listener = seccomp.Listener(listener_fd)
    listener.release_fd = go_w  # type: ignore[attr-defined]
    return pid, listener


def _read_exact(fd: int, n: int, timeout: float) -> bytes | None:
    """Read exactly n bytes from fd, or None on EOF/timeout."""
    import select

    buf = b""
    deadline = None
    while len(buf) < n:
        if timeout is not None:
            import time as _t
            if deadline is None:
                deadline = _t.time() + timeout
            remaining = deadline - _t.time()
            if remaining <= 0:
                return None
            r, _, _ = select.select([fd], [], [], remaining)
            if not r:
                return None
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _pidfd_steal(pid: int, remote_fd: int) -> int:
    """Duplicate `remote_fd` out of process `pid` into this one.

    pidfd_open(2) + pidfd_getfd(2). Returns a local fd, or -1 on failure.
    """
    pidfd = _libc.syscall(434, pid, 0)  # __NR_pidfd_open
    if pidfd < 0:
        return -1
    try:
        local = _libc.syscall(438, pidfd, remote_fd, 0)  # __NR_pidfd_getfd
        return local
    finally:
        os.close(pidfd)


def release(listener: seccomp.Listener) -> None:
    """Let the payload proceed to execve. Call once the monitor loop is up."""
    go_fd: int = listener.release_fd  # type: ignore[attr-defined]
    try:
        os.write(go_fd, b"G")
    finally:
        os.close(go_fd)


def cleanup_host_root() -> None:
    """Remove the host-side stub directory, if this process created one."""
    try:
        Path("/tmp/.cerberus-root").rmdir()
    except OSError:
        pass
