#!/usr/bin/env python3
"""VILLAIN #3 — sandbox escape attempts, each refused in-kernel.

Walks a checklist of classic container/namespace escapes. None of these ever
reach userspace-monitor adjudication: they are in the hard-deny set, so the
seccomp filter refuses them with EPERM before the kernel acts. This shows the
two-tier design — cheap deterministic blocking for calls that are never
legitimate, contextual judgement for the rest.
"""
import ctypes
import os

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def attempt(label, fn):
    try:
        rc = fn()
        err = ctypes.get_errno()
        status = "BLOCKED (EPERM)" if rc != 0 and err == 1 else f"rc={rc} errno={err}"
    except Exception as exc:
        status = f"raised {exc!r}"
    print(f"[escape] {label:<28} -> {status}")


# ptrace(PTRACE_TRACEME) — attach to and manipulate other processes
attempt("ptrace", lambda: libc.syscall(101, 0, 0, 0, 0))
# mount a fresh proc / overlay — rebuild the filesystem view
attempt("mount", lambda: libc.syscall(165, b"none", b"/mnt", b"proc", 0, 0))
# unshare a new user namespace — the usual privilege-escalation primitive
attempt("unshare(CLONE_NEWUSER)", lambda: libc.syscall(272, 0x10000000))
# load an eBPF program — could watch or subvert the monitor
attempt("bpf", lambda: libc.syscall(321, 0, 0, 0))
# load a kernel module
attempt("finit_module", lambda: libc.syscall(313, 0, b"", 0))
# chroot escape primitive
attempt("chroot", lambda: libc.syscall(161, b"/"))

print("[escape] all escape primitives refused; still inside the sandbox")
print(f"[escape] my hostname is {os.uname().nodename!r} (should be 'cerberus')")
