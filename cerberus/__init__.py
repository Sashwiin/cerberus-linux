"""Cerberus — an ephemeral RAM-disk sandbox with real-time syscall defense."""

__version__ = "0.6.0"
# Bumped whenever behaviour changes so you can confirm which build is running.
# 0.6.0: escape/tamper syscalls (ptrace, mount, unshare, bpf, chroot, module
#        loading, ...) now surface as VISIBLE freezing violations (CONTAINED)
#        instead of a silent in-kernel EPERM that read as CLEAN.
# 0.5.0: /proc readable (fixes version-dependent /proc/maps false positive),
#        disposable-VM mode with live boot console + persistent mode badge.
BUILD = "0.6.0 (visible-escape)"
