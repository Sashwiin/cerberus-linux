"""The policy engine: what counts as unauthorised, and why.

Design commitment, stated up front because it is the decision everything else
follows from: **the syscall policy is a default-deny allowlist, and the
contextual rules on top of it are default-deny too.** A blocklist of
"known bad" behaviour is the documented weakness of lightweight sandboxing
tools — it cannot describe an attack nobody has written yet. So:

  * Syscalls are sorted into classes. A small BYPASS_DENY set (pure
    monitor-defeating vectors like io_uring and a second seccomp filter) is
    refused in-kernel with no userspace round trip. The NOTIFY set is parked
    and judged on its arguments -- and that set includes the ESCAPE syscalls
    (ptrace, mount, unshare, bpf, chroot, module loading, ...), which are
    always judged as a visible, freezing violation rather than blocked
    silently, so an escape attempt reads as CONTAINED, not CLEAN. Everything
    else is allowed, and that residual allow-set is itself an explicit,
    reviewable list (`BASELINE_ALLOW`) that the strict profile enforces rather
    than a silent catch-all.
  * Contextual rules answer "is this argument permitted", not "is this
    argument on a bad list". A file read is allowed because its path sits
    under an allowed prefix, not because it failed to match a secret pattern.
    The sensitive-path patterns exist to *classify severity* for the operator,
    not to make the allow/deny decision.

The distinction matters for the demo: a payload that reads a credential file
nobody thought to enumerate is still stopped, because the path was never under
an allowed prefix to begin with.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket as _socket
import struct
from dataclasses import dataclass, field
from enum import Enum

from .syscalls import nr

# --------------------------------------------------------------- verdicts


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Severity(str, Enum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    VIOLATION = "violation"


@dataclass
class Verdict:
    action: Action
    severity: Severity
    rule: str
    summary: str
    detail: dict = field(default_factory=dict)

    @property
    def is_violation(self) -> bool:
        return self.severity is Severity.VIOLATION


def _allow(rule: str, summary: str, **detail) -> Verdict:
    return Verdict(Action.ALLOW, Severity.INFO, rule, summary, detail)


def _watch(rule: str, summary: str, **detail) -> Verdict:
    return Verdict(Action.ALLOW, Severity.SUSPICIOUS, rule, summary, detail)


def _violation(rule: str, summary: str, **detail) -> Verdict:
    return Verdict(Action.DENY, Severity.VIOLATION, rule, summary, detail)


# ------------------------------------------------------- syscall classes

# Two ways to refuse a dangerous syscall, and the difference is the whole point
# of what a "villain" file looks like on screen:
#
#   * BYPASS_DENY -- refused *in-kernel* with EPERM, no userspace round trip.
#     The payload gets an error code and the monitor never hears about it, so
#     the attempt is invisible. We use this ONLY for syscalls whose entire
#     purpose is to defeat the monitor itself: if we parked one of these for a
#     verdict, the act of parking could be the thing that's exploited. For
#     everything else, invisibility is the wrong behaviour -- a blocked escape
#     that reads as "clean" is confusing and undersells the defence.
#
#   * ESCAPE -- parked like any NOTIFY syscall, judged, and turned into a
#     VISIBLE violation that freezes the sandbox (CONTAINED). These are the
#     classic sandbox-escape / tamper attempts. Blocking them silently in the
#     kernel made a file full of escape attempts show up as CLEAN, which is
#     exactly backwards: trying to attach a debugger or rebuild the mount table
#     is the single most incriminating thing untrusted code can do. So we park
#     the syscall (it never runs -- an unanswered notification blocks it in the
#     kernel forever), raise the violation, and freeze. The escape is still
#     100% prevented; it is now also *seen*.

# Refused in-kernel with EPERM, no notification. Reserved for pure
# monitor-bypass vectors -- parking these for a verdict is itself the risk.
BYPASS_DENY_NAMES = (
    # io_uring: submits I/O from a kernel worker thread, historically a way to
    # perform file and socket operations that a seccomp filter never sees. The
    # setup call is the choke point, and it stays a hard in-kernel refusal
    # rather than a parked notification.
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    # Filesystem access that sidesteps path resolution entirely -- resolves a
    # file by an opaque handle instead of a path the monitor can read.
    "open_by_handle_at", "name_to_handle_at",
    # Installing a *second* seccomp filter would let the payload park its own
    # syscalls and answer them itself, defeating this monitor from the inside.
    "seccomp",
)

# Parked, judged, and turned into a visible CONTAINED violation. Every one of
# these is a documented route out of a namespace jail, a way to tamper with the
# host, or an attempt to blind the monitor -- and none of them has a legitimate
# use inside untrusted sandboxed code, so any attempt is a violation on sight.
ESCAPE_NAMES = (
    # Debugger interfaces: read and write another process's memory.
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
    # Namespace and mount manipulation: re-entering or rebuilding the jail.
    "mount", "umount2", "pivot_root", "chroot", "setns", "unshare",
    "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick",
    "mount_setattr",
    # Kernel code loading.
    "init_module", "finit_module", "delete_module", "kexec_load",
    "kexec_file_load",
    # Tracing and kernel programmability: would let the payload watch or
    # subvert the monitor itself.
    "bpf", "perf_event_open",
    # Device node creation: a fresh /dev/sda is a way around a read-only bind.
    "mknod", "mknodat",
    # Fault handling and key management, both used for sandbox escapes.
    "userfaultfd", "add_key", "request_key", "keyctl",
    # Privilege and host-state changes.
    "setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid",
    "capset", "sethostname", "setdomainname", "reboot", "swapon", "swapoff",
    "acct", "settimeofday", "clock_settime", "adjtimex", "clock_adjtime",
    "iopl", "ioperm", "quotactl", "quotactl_fd",
    # Descriptor theft across processes.
    "pidfd_getfd",
)

# Human-readable descriptions for the violation summary. A syscall not listed
# here falls back to a generic "attempted a sandbox-escape syscall (<name>)".
ESCAPE_LABELS = {
    "ptrace": "attach a debugger to another process (ptrace)",
    "process_vm_readv": "read another process's memory (process_vm_readv)",
    "process_vm_writev": "write into another process's memory (process_vm_writev)",
    "kcmp": "probe another process via kcmp",
    "mount": "mount a filesystem",
    "umount2": "unmount a filesystem",
    "pivot_root": "change the root filesystem (pivot_root)",
    "chroot": "change the root directory (chroot)",
    "setns": "join another namespace (setns)",
    "unshare": "create a new namespace (unshare)",
    "open_tree": "clone a mount tree (open_tree)",
    "move_mount": "relocate a mount (move_mount)",
    "fsopen": "open a filesystem context (fsopen)",
    "fsconfig": "configure a filesystem context (fsconfig)",
    "fsmount": "create a mount from a filesystem context (fsmount)",
    "fspick": "pick a filesystem context (fspick)",
    "mount_setattr": "change mount attributes (mount_setattr)",
    "init_module": "load a kernel module (init_module)",
    "finit_module": "load a kernel module (finit_module)",
    "delete_module": "unload a kernel module (delete_module)",
    "kexec_load": "load a replacement kernel (kexec_load)",
    "kexec_file_load": "load a replacement kernel (kexec_file_load)",
    "bpf": "load a BPF program (bpf)",
    "perf_event_open": "open a kernel performance counter (perf_event_open)",
    "mknod": "create a device node (mknod)",
    "mknodat": "create a device node (mknodat)",
    "userfaultfd": "install a userfaultfd handler",
    "add_key": "add a kernel key (add_key)",
    "request_key": "request a kernel key (request_key)",
    "keyctl": "manipulate the kernel keyring (keyctl)",
    "setuid": "change user id (setuid)",
    "setgid": "change group id (setgid)",
    "setresuid": "change user id (setresuid)",
    "setresgid": "change group id (setresgid)",
    "setreuid": "change user id (setreuid)",
    "setregid": "change group id (setregid)",
    "capset": "grant itself capabilities (capset)",
    "sethostname": "change the host name (sethostname)",
    "setdomainname": "change the domain name (setdomainname)",
    "reboot": "reboot the machine (reboot)",
    "swapon": "enable swap (swapon)",
    "swapoff": "disable swap (swapoff)",
    "acct": "toggle process accounting (acct)",
    "settimeofday": "change the system clock (settimeofday)",
    "clock_settime": "change the system clock (clock_settime)",
    "adjtimex": "tune the system clock (adjtimex)",
    "clock_adjtime": "tune the system clock (clock_adjtime)",
    "iopl": "raise I/O privilege level (iopl)",
    "ioperm": "grant itself I/O port access (ioperm)",
    "quotactl": "manipulate disk quotas (quotactl)",
    "quotactl_fd": "manipulate disk quotas (quotactl_fd)",
    "pidfd_getfd": "steal a file descriptor from another process (pidfd_getfd)",
}

# Parked and judged on arguments.
NOTIFY_NAMES = (
    "open", "openat", "openat2",
    "socket", "connect", "bind", "sendto", "sendmsg",
    "execve", "execveat",
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "memfd_create",
    "clone", "clone3", "fork", "vfork",
) + ESCAPE_NAMES

# The residual allow-set, written out explicitly. The strict profile enforces
# exactly this (plus NOTIFY, minus HARD_DENY); the default profile allows
# unlisted syscalls but the list is still the reviewable statement of what a
# normal payload needs.
BASELINE_ALLOW_NAMES = (
    "read", "write", "close", "fstat", "stat", "lstat", "newfstatat", "statx",
    "lseek", "pread64", "pwrite64", "readv", "writev", "preadv", "pwritev",
    "preadv2", "pwritev2", "access", "faccessat", "faccessat2", "getdents",
    "getdents64", "getcwd", "chdir", "fchdir", "readlink", "readlinkat",
    "mkdir", "mkdirat", "rmdir", "link", "linkat", "symlink", "symlinkat",
    "chmod", "fchmod", "fchmodat", "fchmodat2", "truncate", "ftruncate",
    "fallocate", "fsync", "fdatasync", "syncfs", "sync", "sync_file_range",
    "copy_file_range", "sendfile", "splice", "tee", "utimensat", "umask",
    "statfs", "fstatfs", "flock", "fcntl", "dup", "dup2", "dup3",
    "close_range", "pipe", "pipe2", "select", "pselect6", "poll", "ppoll",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
    "epoll_pwait", "epoll_pwait2", "eventfd", "eventfd2", "signalfd",
    "signalfd4", "timerfd_create", "timerfd_settime", "inotify_init",
    "inotify_init1", "inotify_add_watch", "mmap", "mprotect", "munmap",
    "mremap", "msync", "madvise", "mincore", "brk", "pkey_mprotect",
    "pkey_alloc", "pkey_free", "mlock", "mlock2", "munlock", "membarrier",
    "mseal", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "rt_sigpending", "rt_tgsigqueueinfo", "sigaltstack", "kill", "tkill",
    "tgkill", "pause", "nanosleep", "clock_nanosleep", "clock_gettime",
    "clock_getres", "gettimeofday", "time", "times", "getrusage", "sysinfo",
    "uname", "getpid", "getppid", "gettid", "getuid", "geteuid", "getgid",
    "getegid", "getgroups", "getresuid", "getresgid", "getpgrp", "getpgid",
    "setpgid", "setsid", "getsid", "getrlimit", "setrlimit", "prlimit64",
    "getpriority", "setpriority", "sched_yield", "sched_getaffinity",
    "sched_setaffinity", "sched_getscheduler", "sched_getparam",
    "sched_get_priority_max", "sched_get_priority_min", "getcpu", "getrandom",
    "arch_prctl", "prctl", "set_tid_address", "set_robust_list",
    "get_robust_list", "rseq", "futex", "futex_waitv", "futex_wake",
    "futex_wait", "futex_requeue", "exit", "exit_group", "wait4", "waitid",
    "restart_syscall", "personality", "ioctl", "setxattr", "getxattr",
    "listxattr", "removexattr", "shutdown", "getsockname", "getpeername",
    "setsockopt", "getsockopt", "socketpair", "recvfrom", "recvmsg",
    "recvmmsg", "sendmmsg", "accept", "accept4", "listen", "epoll_ctl_old",
    "cachestat", "process_mrelease", "fadvise64", "readahead",
)


def _nrs(names) -> list[int]:
    out = []
    for n in names:
        try:
            out.append(nr(n))
        except KeyError:
            continue  # syscall unknown to our table; skip rather than crash
    return out


# HARD_DENY keeps its name (runner/tests/filter build against it) but now holds
# only the in-kernel bypass vectors; the escape syscalls live in NOTIFY.
HARD_DENY = _nrs(BYPASS_DENY_NAMES)
ESCAPE = _nrs(ESCAPE_NAMES)
NOTIFY = _nrs(NOTIFY_NAMES)
BASELINE_ALLOW = _nrs(BASELINE_ALLOW_NAMES)

# Reverse map: syscall number -> name, for building escape violation summaries.
_ESCAPE_NR_TO_NAME = {}
for _n in ESCAPE_NAMES:
    try:
        _ESCAPE_NR_TO_NAME[nr(_n)] = _n
    except KeyError:
        continue
ESCAPE_SET = frozenset(_ESCAPE_NR_TO_NAME)


# ---------------------------------------------------------- path policy

# Prefixes the payload is allowed to READ from. This covers the read-only
# system tree (interpreters, libraries, configuration) plus the sandbox's own
# writable areas. It is intentionally broad -- an interpreter touches hundreds
# of files under these paths at startup -- because the security decision that
# matters is made by the SENSITIVE_PATTERNS check above, which denies specific
# dangerous targets (credentials, keys, device memory) even when they sit under
# one of these prefixes. Reading a normal config file is not a threat; reading
# /etc/shadow is, and that is caught by pattern, not by prefix.
DEFAULT_READ_PREFIXES = (
    "/work", "/tmp", "/usr", "/lib", "/lib64", "/lib32", "/libx32",
    "/bin", "/sbin", "/opt", "/etc", "/run/systemd/resolve",
    "/dev/null", "/dev/zero", "/dev/full", "/dev/urandom", "/dev/random",
    "/dev/tty", "/dev/pts", "/dev/stdin", "/dev/stdout", "/dev/stderr",
    # All of /proc is readable. The sandbox has its own PID + mount namespaces,
    # so /proc only exposes the sandbox's OWN processes -- not the host's -- and
    # different interpreters legitimately read different /proc files at startup
    # (Python 3.14, for instance, reads /proc/<pid>/maps; 3.12 does not). Making
    # this version-dependent read a policy decision produced the same file
    # getting two different verdicts on two machines. The genuinely dangerous
    # /proc targets (/proc/*/mem, /proc/kcore) are still denied by pattern below.
    "/proc",
    "/sys/devices/system/cpu", "/sys/fs/cgroup",
)

DEFAULT_WRITE_PREFIXES = ("/work", "/tmp", "/dev/null", "/dev/tty", "/proc/self/fd")

# Patterns that make a refusal *interesting* rather than routine. These do not
# decide anything -- the prefix allowlist already refused the path -- they
# label the event so the operator sees "credential theft" instead of
# "unexpected file access".
SENSITIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("/etc/shadow*", "password hash database"),
    ("/etc/gshadow*", "group password database"),
    ("/etc/sudoers*", "sudo configuration"),
    ("*/.ssh/id_*", "SSH private key"),
    ("*/.ssh/*", "SSH configuration or known hosts"),
    ("*/.aws/credentials*", "AWS credentials"),
    ("*/.aws/config", "AWS configuration"),
    ("*/.config/gcloud/*", "Google Cloud credentials"),
    ("*/.kube/config*", "Kubernetes credentials"),
    ("*/.docker/config.json", "Docker registry credentials"),
    ("*/.netrc", "stored network credentials"),
    ("*/.git-credentials", "git credentials"),
    ("*/.gnupg/*", "GPG private keyring"),
    ("*/.env", "application secrets file"),
    ("*/.env.*", "application secrets file"),
    ("*/.bash_history", "shell history"),
    ("*/.zsh_history", "shell history"),
    ("*/Login Data*", "browser saved passwords"),
    ("*/Cookies*", "browser session cookies"),
    ("*/cookies.sqlite*", "browser session cookies"),
    ("*/logins.json", "browser saved passwords"),
    ("*wallet*.dat", "cryptocurrency wallet"),
    # Note: /proc/*/environ and /proc/*/cmdline are intentionally NOT flagged.
    # In the sandbox's own PID namespace they only reveal the sandboxed
    # process's own environment/args, not the host's, and some interpreters read
    # their own at startup -- flagging them caused version-dependent false
    # positives. Reading another process's raw *memory* is still refused.
    ("/proc/*/mem", "process memory"),
    ("/proc/kcore", "kernel memory image"),
    ("/dev/mem", "physical memory"),
    ("/dev/kmem", "kernel memory"),
    ("/dev/sd*", "raw block device"),
    ("/dev/nvme*", "raw block device"),
    ("/var/run/docker.sock", "Docker control socket"),
    ("/run/docker.sock", "Docker control socket"),
    ("/var/lib/kubelet/*", "Kubernetes node secrets"),
    ("/run/secrets/*", "injected secrets"),
    ("/root/*", "root's home directory"),
    ("/home/*", "a user's home directory"),
)

# Binaries whose presence in an exec is worth flagging even when permitted:
# these are the standard second stage of an exfiltration chain.
EXFIL_TOOLS = (
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "rsync", "ftp", "tftp", "telnet", "openssl", "gpg", "base64", "xxd",
    "dig", "nslookup", "host", "ping", "nmap", "tcpdump",
)


def classify_path(path: str) -> str | None:
    for pattern, label in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(path, pattern):
            return label
    return None


O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000
_O_NOFOLLOW = 0o400


def _is_write(flags: int) -> bool:
    return bool(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))


def _under(path: str, prefixes) -> bool:
    for p in prefixes:
        if path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


# -------------------------------------------------------- socket policy

AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET = 1, 2, 10, 16, 17

AF_NAMES = {
    AF_UNIX: "AF_UNIX", AF_INET: "AF_INET", AF_INET6: "AF_INET6",
    AF_NETLINK: "AF_NETLINK", AF_PACKET: "AF_PACKET",
}

SOCK_TYPES = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 5: "SOCK_SEQPACKET"}


def parse_sockaddr(data: bytes) -> dict:
    """Decode the parts of a sockaddr we make decisions on."""
    if data is None or len(data) < 2:
        return {"family": None}
    (family,) = struct.unpack_from("=H", data, 0)
    out: dict = {"family": family, "family_name": AF_NAMES.get(family, f"AF_{family}")}
    try:
        if family == AF_INET and len(data) >= 8:
            port, raw = struct.unpack_from("!H4s", data, 2)
            out["port"] = port
            out["address"] = str(ipaddress.IPv4Address(raw))
        elif family == AF_INET6 and len(data) >= 24:
            port = struct.unpack_from("!H", data, 2)[0]
            raw = data[8:24]
            out["port"] = port
            out["address"] = str(ipaddress.IPv6Address(raw))
        elif family == AF_UNIX:
            path = data[2:110].split(b"\0", 1)[0]
            out["address"] = path.decode("utf-8", "replace") or "<abstract>"
    except (ValueError, struct.error):
        pass
    return out


def _is_local(addr: str | None) -> bool:
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


# ------------------------------------------------------------- profiles


@dataclass
class Policy:
    """A named set of rules. `strict` is the default."""

    name: str = "strict"
    allow_network: bool = False
    allow_loopback: bool = True
    read_prefixes: tuple[str, ...] = DEFAULT_READ_PREFIXES
    write_prefixes: tuple[str, ...] = DEFAULT_WRITE_PREFIXES
    allow_exec: bool = True
    freeze_on_violation: bool = True
    default_allow_unlisted: bool = True
    # Behavioural fork-bomb threshold: total process-creation syscalls before
    # the monitor trips a violation. Normal programs spawn a handful; a fork
    # bomb blows past this immediately.
    max_processes: int = 128

    # ----------------------------------------------------------- dispatch

    def judge(self, nr_: int, args, reader) -> Verdict:
        """Decide one parked syscall.

        `reader(index, size)` fetches `size` bytes from the target's memory at
        `args[index]`, TOCTOU-checked, returning None if it cannot be trusted.
        """
        # Escape/tamper syscalls are parked and turned into a visible,
        # freezing violation rather than refused silently in-kernel. The
        # syscall never runs -- the notification is left unanswered, which
        # blocks it in the kernel -- so the escape is prevented AND seen.
        if nr_ in ESCAPE_SET:
            return self._judge_escape(nr_)
        handler = self._handlers().get(nr_)
        if handler is None:
            return _allow("unclassified", f"{nr_} permitted by default")
        return handler(args, reader)

    def _judge_escape(self, nr_: int) -> Verdict:
        name = _ESCAPE_NR_TO_NAME.get(nr_, str(nr_))
        label = ESCAPE_LABELS.get(name, f"a sandbox-escape syscall ({name})")
        return _violation(
            f"escape.{name}",
            f"attempted to {label}",
            syscall=name,
        )

    def _handlers(self):
        if getattr(self, "_h", None) is None:
            h = {}
            for n in ("open",):
                h[nr(n)] = self._judge_open_legacy
            for n in ("openat", "openat2"):
                h[nr(n)] = self._judge_openat
            h[nr("socket")] = self._judge_socket
            h[nr("connect")] = self._judge_connect
            h[nr("bind")] = self._judge_bind
            h[nr("sendto")] = self._judge_sendto
            h[nr("sendmsg")] = self._judge_sendmsg
            h[nr("execve")] = self._judge_execve
            h[nr("execveat")] = self._judge_execveat
            for n in ("unlink",):
                h[nr(n)] = self._judge_unlink
            for n in ("unlinkat",):
                h[nr(n)] = self._judge_unlinkat
            for n in ("rename", "renameat", "renameat2"):
                h[nr(n)] = self._judge_rename
            h[nr("memfd_create")] = self._judge_memfd
            for n in ("clone", "clone3", "fork", "vfork"):
                h[nr(n)] = self._judge_clone
            object.__setattr__(self, "_h", h)
        return self._h

    # -------------------------------------------------------------- files

    def _judge_path(self, raw: str | None, resolved: str | None,
                    write: bool, syscall: str) -> Verdict:
        if raw is None:
            # We could not read the argument, or it changed under us. Refusing
            # is the only safe answer: allowing an unreadable path would be a
            # hole an attacker could drive a truck through.
            return _violation(
                "path.unreadable",
                f"{syscall} with an unverifiable path argument",
                syscall=syscall,
            )
        # The decision is made on the *resolved* target -- the true file after
        # symlinks -- so a link like /work/x -> /etc/shadow is judged as
        # /etc/shadow, not as the innocent-looking /work/x. `raw` is kept only
        # for the human-readable summary.
        path = resolved or raw
        label = classify_path(path)
        shown = raw if raw == path else f"{raw} → {path}"

        # A sensitive target is ALWAYS a violation, no matter where the path
        # started. This is the core of the default-deny stance: credentials,
        # keys, other processes' memory, raw devices -- reading any of them is
        # never legitimate for sandboxed code, so a symlink or a bind-mounted
        # /etc can't launder access to them.
        if label:
            return _violation(
                "path.sensitive",
                f"attempted to {'write' if write else 'read'} {label}",
                path=path, raw=raw, label=label, write=write, syscall=syscall,
            )

        prefixes = self.write_prefixes if write else self.read_prefixes
        if _under(path, prefixes):
            return _allow("path.allowed", f"{syscall} {shown}",
                          path=path, raw=raw, write=write)
        return _violation(
            "path.outside_allowlist",
            f"{'write' if write else 'read'} outside the permitted filesystem "
            f"({shown})",
            path=path, raw=raw, write=write, syscall=syscall,
        )

    def _judge_openat(self, args, reader) -> Verdict:
        raw = reader.cstring(1)
        flags = args[2]
        if raw and not raw.startswith("/"):
            raw = self._resolve_relative(raw, args[0], reader)
        resolved, _ = reader.resolve(raw, follow=not bool(flags & _O_NOFOLLOW))
        return self._judge_path(raw, resolved, _is_write(flags), "openat")

    def _judge_open_legacy(self, args, reader) -> Verdict:
        raw = reader.cstring(0)
        flags = args[1]
        if raw and not raw.startswith("/"):
            raw = self._resolve_relative(raw, -100, reader)
        resolved, _ = reader.resolve(raw, follow=not bool(flags & _O_NOFOLLOW))
        return self._judge_path(raw, resolved, _is_write(flags), "open")

    def _resolve_relative(self, path: str, dirfd: int, reader) -> str:
        """Resolve a relative path against the target's own cwd or dirfd.

        Without this a payload could reach anything by opening "../.." chains,
        because a relative path never matches an absolute allow-prefix and a
        naive implementation would either refuse everything or, worse, compare
        the wrong string.
        """
        import os as _os

        base = None
        pid = reader.pid
        try:
            if dirfd == -100 or (dirfd & 0xFFFFFFFF) == 0xFFFFFF9C:
                base = _os.readlink(f"/proc/{pid}/cwd")
            elif dirfd >= 0:
                base = _os.readlink(f"/proc/{pid}/fd/{dirfd}")
        except OSError:
            return path
        if base is None:
            return path
        return _os.path.normpath(_os.path.join(base, path))

    def _judge_unlink(self, args, reader) -> Verdict:
        raw = reader.cstring(0)
        resolved, _ = reader.resolve(raw, follow=False)
        return self._judge_path(raw, resolved, True, "unlink")

    def _judge_unlinkat(self, args, reader) -> Verdict:
        raw = reader.cstring(1)
        resolved, _ = reader.resolve(raw, follow=False)
        return self._judge_path(raw, resolved, True, "unlinkat")

    def _judge_rename(self, args, reader) -> Verdict:
        raw = reader.cstring(0)
        resolved, _ = reader.resolve(raw, follow=False)
        return self._judge_path(raw, resolved, True, "rename")

    def _judge_memfd(self, args, reader) -> Verdict:
        # Anonymous executable memory is how fileless payloads stage a second
        # binary. Permitted, but always surfaced.
        return _watch(
            "memfd.created",
            "created an anonymous in-memory file",
            name=reader.cstring(0),
        )

    def _judge_clone(self, args, reader) -> Verdict:
        # Namespace creation via clone would otherwise sidestep the unshare
        # hard-deny entirely.
        ns_flags = {
            0x00020000: "CLONE_NEWNS", 0x02000000: "CLONE_NEWCGROUP",
            0x04000000: "CLONE_NEWUTS", 0x08000000: "CLONE_NEWIPC",
            0x10000000: "CLONE_NEWUSER", 0x20000000: "CLONE_NEWPID",
            0x40000000: "CLONE_NEWNET",
        }
        requested = [n for bit, n in ns_flags.items() if args[0] & bit]
        if requested:
            return _violation(
                "clone.new_namespace",
                f"tried to create new namespaces ({', '.join(requested)})",
                flags=requested,
            )
        return _allow("clone.ordinary", "spawned a thread or child process")

    # ------------------------------------------------------------ network

    def _judge_socket(self, args, reader) -> Verdict:
        domain, sock_type = args[0], args[1] & 0xF
        fam = AF_NAMES.get(domain, f"AF_{domain}")
        stype = SOCK_TYPES.get(sock_type, f"type{sock_type}")
        if domain == AF_PACKET or sock_type == 3:
            return _violation(
                "socket.raw",
                f"opened a raw socket ({fam}/{stype})",
                family=fam, type=stype,
            )
        if domain in (AF_INET, AF_INET6):
            if not self.allow_network and not self.allow_loopback:
                return _violation(
                    "socket.network_denied",
                    f"opened a network socket ({fam}/{stype}) under a no-network policy",
                    family=fam, type=stype,
                )
            # Creating the socket is harmless on its own; where it is pointed
            # is the decision that matters, and connect() makes that.
            return _watch(
                "socket.network_created",
                f"created a network socket ({fam}/{stype})",
                family=fam, type=stype,
            )
        return _allow("socket.local", f"created a {fam}/{stype} socket", family=fam)

    def _judge_endpoint(self, sa: dict, syscall: str) -> Verdict:
        fam = sa.get("family")
        if fam is None:
            return _violation(
                "endpoint.unreadable",
                f"{syscall} with an unverifiable address",
                syscall=syscall,
            )
        if fam == AF_UNIX:
            path = sa.get("address", "")
            label = classify_path(path)
            if label:
                return _violation(
                    "endpoint.unix_sensitive",
                    f"connected to {label}",
                    address=path, label=label,
                )
            if _under(path, ("/work", "/tmp")) or path == "<abstract>":
                return _allow("endpoint.unix_local", f"{syscall} to {path}", address=path)
            return _violation(
                "endpoint.unix_outside",
                f"{syscall} to a socket outside the sandbox ({path})",
                address=path,
            )
        if fam in (AF_INET, AF_INET6):
            addr = sa.get("address")
            port = sa.get("port")
            if _is_local(addr):
                if self.allow_loopback:
                    return _allow(
                        "endpoint.loopback", f"{syscall} to loopback {addr}:{port}",
                        address=addr, port=port,
                    )
                return _violation(
                    "endpoint.loopback_denied", f"{syscall} to loopback {addr}:{port}",
                    address=addr, port=port,
                )
            if self.allow_network:
                return _watch(
                    "endpoint.remote_allowed",
                    f"{syscall} to {addr}:{port}",
                    address=addr, port=port,
                )
            # This is the headline event: outbound data egress, refused before
            # a single byte leaves the machine.
            return _violation(
                "endpoint.egress",
                f"attempted outbound connection to {addr}:{port}",
                address=addr, port=port, syscall=syscall,
            )
        if fam == AF_NETLINK:
            return _allow("endpoint.netlink", f"{syscall} to netlink")
        return _violation(
            "endpoint.unknown_family",
            f"{syscall} to an unexpected address family ({sa.get('family_name')})",
            family=sa.get("family_name"),
        )

    def _judge_connect(self, args, reader) -> Verdict:
        sa = parse_sockaddr(reader.raw(1, min(int(args[2]) or 128, 128)))
        return self._judge_endpoint(sa, "connect")

    def _judge_sendto(self, args, reader) -> Verdict:
        if args[4] == 0:
            # No destination: this is a send() on an already-connected socket,
            # which connect() already adjudicated.
            return _allow("sendto.connected", "sent on an established socket")
        sa = parse_sockaddr(reader.raw(4, min(int(args[5]) or 128, 128)))
        return self._judge_endpoint(sa, "sendto")

    def _judge_sendmsg(self, args, reader) -> Verdict:
        # struct msghdr { void *name; socklen_t namelen; ... }
        hdr = reader.raw(1, 16)
        if not hdr:
            return _violation("sendmsg.unreadable", "sendmsg with an unverifiable header")
        name_ptr, namelen = struct.unpack_from("=QI", hdr, 0)
        if name_ptr == 0 or namelen == 0:
            return _allow("sendmsg.connected", "sent on an established socket")
        sa = parse_sockaddr(reader.at(name_ptr, min(namelen, 128)))
        return self._judge_endpoint(sa, "sendmsg")

    def _judge_bind(self, args, reader) -> Verdict:
        sa = parse_sockaddr(reader.raw(1, min(int(args[2]) or 128, 128)))
        fam = sa.get("family")
        if fam in (AF_INET, AF_INET6) and not self.allow_network:
            return _violation(
                "bind.listener",
                f"tried to listen on {sa.get('address')}:{sa.get('port')}",
                address=sa.get("address"), port=sa.get("port"),
            )
        return _allow("bind.ok", "bound a local socket", **sa)

    # --------------------------------------------------------------- exec

    def _judge_exec(self, path: str | None, syscall: str) -> Verdict:
        if path is None:
            return _violation(
                "exec.unreadable", f"{syscall} with an unverifiable path", syscall=syscall
            )
        if not self.allow_exec:
            return _violation("exec.denied", f"tried to execute {path}", path=path)
        import os as _os

        base = _os.path.basename(path)
        if base in EXFIL_TOOLS:
            return _watch(
                "exec.exfil_tool",
                f"executed {base}, a common data-transfer tool",
                path=path, tool=base,
            )
        if not _under(path, self.read_prefixes):
            return _violation(
                "exec.outside_allowlist",
                f"tried to execute a binary outside the permitted filesystem ({path})",
                path=path,
            )
        return _allow("exec.ok", f"executed {path}", path=path)

    def _judge_execve(self, args, reader) -> Verdict:
        raw = reader.cstring(0)
        resolved, _ = reader.resolve(raw, follow=True)
        return self._judge_exec(resolved or raw, "execve")

    def _judge_execveat(self, args, reader) -> Verdict:
        raw = reader.cstring(1)
        resolved, _ = reader.resolve(raw, follow=True)
        return self._judge_exec(resolved or raw, "execveat")


PROFILES = {
    # No network, no filesystem outside the sandbox, exec permitted. This is
    # the profile the demo runs.
    "strict": Policy(name="strict", allow_network=False, allow_loopback=False),
    # Loopback permitted, for payloads that talk to a local service.
    "loopback": Policy(name="loopback", allow_network=False, allow_loopback=True),
    # Network permitted and merely recorded. For observing a payload you have
    # already decided to let out, not for containing one.
    "observe": Policy(
        name="observe", allow_network=True, allow_loopback=True,
        freeze_on_violation=False,
    ),
    # Nothing but compute: no exec, no network, no filesystem beyond /work.
    "paranoid": Policy(
        name="paranoid", allow_network=False, allow_loopback=False,
        allow_exec=False, default_allow_unlisted=False, max_processes=16,
        read_prefixes=("/work", "/tmp", "/usr", "/lib", "/lib64", "/bin",
                       "/dev/null", "/dev/zero", "/dev/urandom", "/proc/self",
                       "/etc/ld.so.cache", "/etc/localtime"),
    ),
}


def get_profile(name: str) -> Policy:
    try:
        return PROFILES[name]
    except KeyError:
        raise SystemExit(
            f"unknown policy profile {name!r}; available: {', '.join(PROFILES)}"
        )


def filter_sets(policy: Policy) -> tuple[list[int], list[int], bool]:
    """Return (notify, hard_deny, default_allow) for the seccomp filter."""
    notify = list(NOTIFY)
    deny = list(HARD_DENY)
    if policy.default_allow_unlisted:
        return notify, deny, True
    # Strict allowlist mode: everything not baseline-allowed and not notified
    # is refused by the filter's default action.
    allowed = set(BASELINE_ALLOW) | set(notify)
    deny = [d for d in deny if d not in allowed]
    return notify, deny, False
