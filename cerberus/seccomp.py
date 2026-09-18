"""Raw seccomp-bpf plumbing, via ctypes only.

Two things live here:

1. `install_filter()` — assembles a classic-BPF seccomp program by hand and
   installs it with SECCOMP_FILTER_FLAG_NEW_LISTENER, which returns a file
   descriptor. Every syscall the filter classifies as "interesting" is then
   parked in the kernel and handed to whoever holds that fd.

2. `Listener` — the supervisor side of that fd. It receives notifications,
   reads the target's syscall arguments out of /proc/<pid>/mem, and answers
   allow / deny.

Why not eBPF: seccomp user notification gives the one thing the project
actually needs from eBPF — the *arguments* of a syscall, in userspace,
*before* the kernel acts on them — with no libbpf, no CO-RE, no kernel
headers, and no CAP_BPF. And unlike ptrace it is not racy by construction:
see the SECCOMP_IOCTL_NOTIF_ID_VALID dance in `read_memory()`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import struct
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------- constants

SECCOMP_SET_MODE_FILTER = 1
SECCOMP_GET_NOTIF_SIZES = 3
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_USER_NOTIF = 0x7FC00000
SECCOMP_RET_ALLOW = 0x7FFF0000

SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

AUDIT_ARCH_X86_64 = 0xC000003E

PR_SET_NO_NEW_PRIVS = 38

# classic BPF opcodes
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_JSET = 0x40
BPF_K = 0x00
BPF_RET = 0x06

# x32 ABI marker: x32 syscalls are (x86-64 nr | this bit).
X32_SYSCALL_BIT = 0x40000000

# struct seccomp_data { int nr; __u32 arch; __u64 ip; __u64 args[6]; }
OFF_NR = 0
OFF_ARCH = 4

# struct seccomp_notif { __u64 id; __u32 pid; __u32 flags; seccomp_data data; }
SIZEOF_SECCOMP_DATA = 64
SIZEOF_NOTIF = 8 + 4 + 4 + SIZEOF_SECCOMP_DATA  # 80
SIZEOF_NOTIF_RESP = 8 + 8 + 4 + 4  # 24

_IOC_WRITE = 1
_IOC_READ = 2
SECCOMP_IOC_MAGIC = ord("!")


def _ioc(direction: int, size: int, nr_: int) -> int:
    return (direction << 30) | (size << 16) | (SECCOMP_IOC_MAGIC << 8) | nr_


# struct seccomp_notif_addfd { __u64 id; __u32 flags; __u32 srcfd;
#                              __u32 newfd; __u32 newfd_flags; }  -> 24 bytes
SIZEOF_NOTIF_ADDFD = 8 + 4 + 4 + 4 + 4  # 24

SECCOMP_IOCTL_NOTIF_RECV = _ioc(_IOC_READ | _IOC_WRITE, SIZEOF_NOTIF, 0)
SECCOMP_IOCTL_NOTIF_SEND = _ioc(_IOC_READ | _IOC_WRITE, SIZEOF_NOTIF_RESP, 1)
SECCOMP_IOCTL_NOTIF_ID_VALID = _ioc(_IOC_WRITE, 8, 2)
SECCOMP_IOCTL_NOTIF_ADDFD = _ioc(_IOC_WRITE, SIZEOF_NOTIF_ADDFD, 3)

SECCOMP_ADDFD_FLAG_SETFD = 1 << 0
SECCOMP_ADDFD_FLAG_SEND = 1 << 1  # install the fd AND complete the notification

# openat2(2) resolve flags for safe, sandbox-confined path resolution.
NR_OPENAT2 = 437
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_IN_ROOT = 0x10
O_PATH = 0o10000000
O_CLOEXEC = 0o2000000
O_NOFOLLOW = 0o400
O_DIRECTORY = 0o200000

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64),
                ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]


def _check(ret: int, what: str) -> int:
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{what}: {os.strerror(err)}")
    return ret


# ------------------------------------------------------------ filter build


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


RET_DENY_EPERM = SECCOMP_RET_ERRNO | (errno.EPERM & 0xFFFF)


def build_program(
    notify: Iterable[int],
    deny: Iterable[int],
    default_allow: bool = True,
    allow: Iterable[int] = (),
) -> list[tuple[int, int, int, int]]:
    """Assemble the seccomp program.

    Each syscall check is emitted as an offset-safe *pair*::

        jeq  <syscall>, +1, +0     # no match -> fall past the return
        ret  <action>

    rather than a long chain of jumps into a shared block of returns at the
    end. Classic-BPF jump offsets are 8 bits, so a chain covering the
    ~250-syscall baseline allowlist would silently overflow past 255 and
    produce a filter that does something other than what it says. Pairs keep
    every offset at 0 or 1 regardless of how many syscalls are classified, at
    the cost of one extra instruction each -- comfortably inside the kernel's
    4096-instruction limit.

    Precedence is positional: deny is emitted first, then notify, then allow.
    A syscall named in two classes resolves by that order rather than by
    whichever check happened to come last.
    """
    deny = list(dict.fromkeys(deny))
    _denied = set(deny)
    notify = [s for s in dict.fromkeys(notify) if s not in _denied]
    _seen = _denied | set(notify)
    allow = [s for s in dict.fromkeys(allow) if s not in _seen]

    prog: list[tuple[int, int, int, int]] = []

    # Refuse anything that is not x86-64. Syscall numbers mean different
    # things under the i386 ABI, so a filter that skips this check is bypassed
    # by issuing the same call through the 32-bit entry point.
    prog.append((BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_ARCH))
    prog.append((BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64))
    prog.append((BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS))

    # Load the syscall number once; every check below reads the accumulator.
    prog.append((BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_NR))

    # Kill any syscall carrying the x32 bit (__X32_SYSCALL_BIT = 0x40000000).
    # x32 is a second ABI that shares the x86-64 audit arch but numbers its
    # syscalls as (nr | 0x40000000). Without this, a payload can invoke, say,
    # x32 ptrace as 0x40000000+101 -- a number none of our checks below match,
    # so it would sail through on the default action. This is a classic,
    # frequently-missed seccomp bypass, so we reject the whole x32 ABI outright.
    prog.append((BPF_JMP | BPF_JSET | BPF_K, 0, 1, X32_SYSCALL_BIT))
    prog.append((BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS))

    for group, action in (
        (deny, RET_DENY_EPERM),
        (notify, SECCOMP_RET_USER_NOTIF),
        (allow, SECCOMP_RET_ALLOW),
    ):
        for s in group:
            # jt=0, jf=1: on a match fall through to the RET (take the action);
            # on a miss skip it and try the next check. This is the OPPOSITE of
            # the arch guard above, which skips its RET on a match. Getting the
            # two backwards makes the filter deny (or allow) everything -- and a
            # deny-everything filter GP-faults the process, because it can no
            # longer even exit.
            prog.append((BPF_JMP | BPF_JEQ | BPF_K, 0, 1, s))
            prog.append((BPF_RET | BPF_K, 0, 0, action))

    prog.append(
        (BPF_RET | BPF_K, 0, 0,
         SECCOMP_RET_ALLOW if default_allow else RET_DENY_EPERM)
    )

    if len(prog) > 4096:
        raise ValueError(
            f"seccomp program is {len(prog)} instructions; kernel limit is 4096"
        )
    return prog


def set_no_new_privs() -> None:
    _check(_libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(NO_NEW_PRIVS)")


def install_filter(
    notify: Iterable[int],
    deny: Iterable[int],
    default_allow: bool = True,
    allow: Iterable[int] = (),
) -> int:
    """Install the filter on the calling thread. Returns the listener fd.

    Irreversible for this process and inherited across execve, which is the
    whole point: the payload cannot take it off.
    """
    prog = build_program(notify, deny, default_allow, allow)
    arr = (_SockFilter * len(prog))()
    for i, (code, jt, jf, k) in enumerate(prog):
        arr[i] = _SockFilter(code, jt, jf, k)
    fprog = _SockFprog(len(prog), arr)

    fd = _libc.syscall(
        317,  # __NR_seccomp
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        ctypes.byref(fprog),
    )
    return _check(fd, "seccomp(SET_MODE_FILTER, NEW_LISTENER)")


def notif_sizes() -> tuple[int, int, int]:
    """Ask the kernel for its struct sizes and sanity-check ours."""
    buf = ctypes.create_string_buffer(6)
    _check(
        _libc.syscall(317, SECCOMP_GET_NOTIF_SIZES, 0, ctypes.byref(buf)),
        "seccomp(GET_NOTIF_SIZES)",
    )
    n, r, d = struct.unpack("=HHH", buf.raw[:6])
    return n, r, d


# ------------------------------------------------------------- supervisor


@dataclass
class Notification:
    """One parked syscall, waiting on our verdict."""

    id: int
    pid: int
    flags: int
    nr: int
    arch: int
    ip: int
    args: tuple[int, int, int, int, int, int]


class Listener:
    """Supervisor end of a seccomp notification fd."""

    def __init__(self, fd: int):
        self.fd = fd
        # Fail loudly at startup rather than silently mis-parsing later.
        n, r, d = notif_sizes()
        if (n, r, d) != (SIZEOF_NOTIF, SIZEOF_NOTIF_RESP, SIZEOF_SECCOMP_DATA):
            raise RuntimeError(
                f"kernel seccomp_notif layout {(n, r, d)} does not match the "
                f"expected {(SIZEOF_NOTIF, SIZEOF_NOTIF_RESP, SIZEOF_SECCOMP_DATA)}"
            )

    def receive(self) -> Notification | None:
        """Block until a syscall is parked. None when the target is gone."""
        buf = ctypes.create_string_buffer(SIZEOF_NOTIF)
        try:
            import fcntl

            fcntl.ioctl(self.fd, SECCOMP_IOCTL_NOTIF_RECV, buf, True)
        except OSError as e:
            # ENOENT: the target died while we were waiting for it.
            if e.errno in (errno.ENOENT, errno.EINTR):
                return None
            raise
        nid, pid, flags = struct.unpack_from("=QII", buf.raw, 0)
        nr_, arch, ip = struct.unpack_from("=iIQ", buf.raw, 16)
        args = struct.unpack_from("=6Q", buf.raw, 32)
        return Notification(nid, pid, flags, nr_, arch, ip, args)

    def _respond(self, nid: int, error: int, val: int, flags: int) -> None:
        resp = struct.pack("=QqiI", nid, val, error, flags)
        buf = ctypes.create_string_buffer(resp, SIZEOF_NOTIF_RESP)
        try:
            import fcntl

            fcntl.ioctl(self.fd, SECCOMP_IOCTL_NOTIF_SEND, buf, True)
        except OSError as e:
            # The target vanished (or was killed by us) before it could be
            # resumed. Nothing left to answer.
            if e.errno not in (errno.ENOENT, errno.EINPROGRESS):
                raise

    def allow(self, nid: int) -> None:
        """Let the kernel carry out the syscall as originally requested."""
        self._respond(nid, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE)

    def deny(self, nid: int, err: int = errno.EPERM) -> None:
        """Fail the syscall with an errno. It never reaches the kernel.

        The kernel wants `error` as a *negative* errno here; passing a positive
        value makes the target see an unrelated error (EBADF, typically).
        """
        self._respond(nid, -abs(err), 0, 0)

    def id_valid(self, nid: int) -> bool:
        """True while the notification is still live.

        This is the TOCTOU guard. Anything read out of the target's memory is
        only trustworthy if this returns True *afterwards*: a still-valid id
        means the target has been blocked in the kernel the entire time and so
        could not have swapped the bytes we just read.
        """
        buf = struct.pack("=Q", nid)
        try:
            import fcntl

            fcntl.ioctl(self.fd, SECCOMP_IOCTL_NOTIF_ID_VALID, buf)
            return True
        except OSError:
            return False

    def read_memory(self, nid: int, pid: int, addr: int, size: int) -> bytes | None:
        """Read `size` bytes from the target, or None if it can't be trusted."""
        if addr == 0:
            return None
        try:
            with open(f"/proc/{pid}/mem", "rb", buffering=0) as fh:
                fh.seek(addr)
                data = fh.read(size)
        except (OSError, ValueError, OverflowError):
            return None
        if not self.id_valid(nid):
            return None
        return data

    def read_cstring(self, nid: int, pid: int, addr: int, limit: int = 4096) -> str | None:
        data = self.read_memory(nid, pid, addr, limit)
        if data is None:
            return None
        return data.split(b"\0", 1)[0].decode("utf-8", "replace")

    # ------------------------------------------------------ safe resolution

    def resolve_in_root(self, pid: int, path: str,
                        follow: bool = True) -> tuple[str | None, bool]:
        """Resolve `path` as the sandboxed process's kernel would, safely.

        Opens the path through /proc/<pid>/root (so it is interpreted in the
        target's mount namespace) with openat2 + RESOLVE_IN_ROOT, which confines
        resolution to the sandbox root and refuses magic-link tricks. Following
        symlinks is done by the kernel *inside* that confinement, then we read
        the fd's true location back — so a symlink like /work/x -> /etc/shadow is
        revealed as /etc/shadow and can be judged on what it really points at.

        Returns (resolved_absolute_path, exists). When the leaf does not exist
        yet (e.g. an open with O_CREAT), it resolves the parent directory and
        re-appends the basename, so a symlinked *parent* is still caught.
        """
        if not path:
            return None, False
        try:
            rootfd = os.open(f"/proc/{pid}/root", O_PATH | O_DIRECTORY)
        except OSError:
            return None, False
        try:
            rel = path.lstrip("/") or "."
            resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
            flags = O_PATH | O_CLOEXEC
            if not follow:
                flags |= O_NOFOLLOW
            resolved = self._openat2_readlink(rootfd, rel, flags, resolve)
            if resolved is not None:
                return resolved, True
            # Leaf may not exist yet: resolve the parent and re-attach basename.
            parent, _, base = rel.rpartition("/")
            if not base or base in (".", ".."):
                return None, False
            pdir = self._openat2_readlink(rootfd, parent or ".",
                                          O_PATH | O_CLOEXEC | O_DIRECTORY,
                                          resolve)
            if pdir is None:
                return None, False
            joined = (pdir.rstrip("/") + "/" + base) if pdir != "/" else "/" + base
            return joined, False
        finally:
            os.close(rootfd)

    def _openat2_readlink(self, dirfd: int, rel: str, flags: int,
                          resolve: int) -> str | None:
        how = _OpenHow(flags, 0, resolve)
        fd = _libc.syscall(NR_OPENAT2, dirfd, rel.encode(),
                           ctypes.byref(how), ctypes.sizeof(how))
        if fd < 0:
            return None
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return None
        finally:
            os.close(fd)

    def open_and_send(self, nid: int, pid: int, path: str, o_flags: int) -> bool:
        """Open `path` safely in the supervisor and inject the fd into the target.

        This is the TOCTOU-proof allow path for reads: instead of telling the
        kernel to re-run the target's open() (which would re-resolve the path,
        possibly after a second thread swapped a symlink), we open the exact,
        validated file ourselves and hand that fd to the target via ADDFD with
        SEND, which also completes the notification. The syscall returns our fd.

        Returns True on success; False means the caller should fall back.
        """
        try:
            rootfd = os.open(f"/proc/{pid}/root", O_PATH | O_DIRECTORY)
        except OSError:
            return False
        srcfd = -1
        try:
            how = _OpenHow(o_flags | O_CLOEXEC, 0,
                           RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)
            srcfd = _libc.syscall(NR_OPENAT2, rootfd, (path.lstrip("/") or ".").encode(),
                                  ctypes.byref(how), ctypes.sizeof(how))
            if srcfd < 0:
                return False
            if not self.id_valid(nid):
                return False
            addfd = struct.pack("=QIIII", nid, SECCOMP_ADDFD_FLAG_SEND, srcfd, 0, 0)
            buf = ctypes.create_string_buffer(addfd, SIZEOF_NOTIF_ADDFD)
            import fcntl
            fcntl.ioctl(self.fd, SECCOMP_IOCTL_NOTIF_ADDFD, buf, True)
            return True
        except OSError:
            return False
        finally:
            if srcfd >= 0:
                try:
                    os.close(srcfd)
                except OSError:
                    pass
            os.close(rootfd)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass
