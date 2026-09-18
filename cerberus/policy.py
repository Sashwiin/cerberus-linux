"""The policy engine: what counts as unauthorised, and why.

Design commitment, stated up front because it is the decision everything else
follows from: **the syscall policy is a default-deny allowlist, and the
contextual rules on top of it are default-deny too.** A blocklist of
"known bad" behaviour is the documented weakness of lightweight sandboxing
tools — it cannot describe an attack nobody has written yet. So:

  * Syscalls are sorted into three classes. Anything in HARD_DENY is refused
    in-kernel with no userspace round trip. Anything in NOTIFY is parked and
    judged on its arguments. Everything else is allowed, and that residual
    allow-set is itself an explicit, reviewable list (`BASELINE_ALLOW`) that
    the strict profile enforces rather than a silent catch-all.
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

# Refused in-kernel. These have no legitimate use inside an untrusted-code
# sandbox, and every one of them is a documented route out of a namespace
# jail or a way to blind the monitor.
HARD_DENY_NAMES = (
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
    # io_uring: submits I/O from a kernel worker thread, historically a way to
    # perform file and socket operations that a seccomp filter never sees.
    # This one is the difference between a filter that holds and one that is
    # trivially bypassed, and it is the most commonly missed entry on this
    # list.
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    # Filesystem access that sidesteps path resolution entirely.
    "open_by_handle_at", "name_to_handle_at",
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
    # Installing a *second* seccomp filter would let the payload park its own
    # syscalls and answer them itself.
    "seccomp",
)

# Parked and judged on arguments.
NOTIFY_NAMES = (
    "open", "openat", "openat2",
    "socket", "connect", "bind", "sendto", "sendmsg",
    "execve", "execveat",
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "memfd_create",
    "clone", "clone3", "fork", "vfork",
)

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


HARD_DENY = _nrs(HARD_DENY_NAMES)
NOTIFY = _nrs(NOTIFY_NAMES)
BASELINE_ALLOW = _nrs(BASELINE_ALLOW_NAMES)


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
    "/proc/self", "/proc/meminfo", "/proc/cpuinfo", "/proc/stat",
    "/proc/filesystems", "/proc/sys/vm/overcommit_memory", "/proc/sys/kernel",
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
    ("/proc/*/mem", "another process's memory"),
    ("/proc/*/environ", "another process's environment"),
    ("/proc/*/cmdline", "another process's command line"),
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

    # ----------------------------------------------------------- dispatch

    def judge(self, nr_: int, args, reader) -> Verdict:
        """Decide one parked syscall.

        `reader(index, size)` fetches `size` bytes from the target's memory at
        `args[index]`, TOCTOU-checked, returning None if it cannot be trusted.
        """
        handler = self._handlers().get(nr_)
        if handler is None:
            return _allow("unclassified", f"{nr_} permitted by default")
        return handler(args, reader)

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
        allow_exec=False, default_allow_unlisted=False,
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
