"""Live architecture facts, read off the real policy/sandbox modules.

Both front ends -- the web dashboard's Architecture & System tab and the
native Qt app's equivalent panel -- show the same numbers because they both
call `system_info()` here rather than each hand-typing a copy. That is the
whole point: these figures can never drift from what the monitor actually
enforces, because they are read from the same objects that enforce it.
"""

from __future__ import annotations

from .policy import (
    BYPASS_DENY_NAMES, ESCAPE_NAMES, NOTIFY_NAMES, BASELINE_ALLOW_NAMES,
    DEFAULT_READ_PREFIXES, DEFAULT_WRITE_PREFIXES, SENSITIVE_PATTERNS,
    PROFILES,
)
from .sandbox import SandboxSpec, DEFAULT_BINDS, DEVICE_NODES


def system_info() -> dict:
    """Real architecture facts, pulled from the live policy/sandbox modules
    rather than written out by hand -- so this can never drift from what the
    monitor actually enforces."""
    spec = SandboxSpec(argv=[])
    return {
        "interception": "seccomp user-notification (SECCOMP_RET_USER_NOTIF)",
        "kernel_min": "5.14 (cgroup.kill); 5.9+ with a weaker teardown",
        "namespaces": ["mount", "pid", "net", "ipc", "uts", "cgroup"],
        "storage_root": f"tmpfs, RAM only ({spec.tmpfs_size})",
        "cgroup": {
            "version": "v2",
            "memory_max": spec.memory_max,
            "pids_max": spec.pids_max,
            "response": "cgroup.freeze (stasis) / cgroup.kill (atomic teardown)",
        },
        "run_as": f"uid {spec.uid} / gid {spec.gid} (unprivileged)",
        "read_only_binds": list(DEFAULT_BINDS),
        "device_nodes": list(DEVICE_NODES),
        "syscall_tiers": {
            "bypass_deny": {
                "count": len(BYPASS_DENY_NAMES),
                "names": list(BYPASS_DENY_NAMES),
                "action": "refused in-kernel (EPERM), no userspace round trip",
            },
            "escape": {
                "count": len(ESCAPE_NAMES),
                "sample": list(ESCAPE_NAMES[:8]),
                "action": "parked, judged, and turned into a visible freezing "
                          "violation (CONTAINED) -- never blocked silently",
            },
            "notify": {
                "count": len(NOTIFY_NAMES),
                "action": "parked and judged on arguments",
            },
            "baseline_allow": {
                "count": len(BASELINE_ALLOW_NAMES),
                "action": "explicit reviewable allow-list (enforced by "
                          "'paranoid'; informative for other profiles)",
            },
        },
        "read_prefixes": list(DEFAULT_READ_PREFIXES),
        "write_prefixes": list(DEFAULT_WRITE_PREFIXES),
        "sensitive_patterns": len(SENSITIVE_PATTERNS),
        "profiles": {
            name: {
                "allow_network": p.allow_network,
                "allow_loopback": p.allow_loopback,
                "allow_exec": p.allow_exec,
                "default_allow_unlisted": p.default_allow_unlisted,
                "max_processes": p.max_processes,
            }
            for name, p in PROFILES.items()
        },
    }
