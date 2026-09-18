"""The supervisor loop: observe, decide, respond.

This is where the three layers meet. One thread blocks on the seccomp
notification fd; for each parked syscall it reads the arguments out of the
target, asks the policy for a verdict, and -- on a violation -- freezes the
cgroup and fails the syscall.

Ordering of the response matters and is deliberate:

  1. Freeze the cgroup.
  2. *Then* answer the notification with an error.

The thread that made the offending call is already stopped dead inside the
kernel waiting on our answer, so it is in no danger of proceeding. Its
siblings are the problem: a payload with a second thread, or a child it forked
earlier, keeps running while we deliberate. Freezing first stops the whole
process group atomically before anything is resumed. Answering first would
leave a window in which the payload learns its syscall failed and can react.
"""

from __future__ import annotations

import errno
import os
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from . import seccomp
from .cgroup import Cgroup
from .events import EventBus
from .policy import Action, Policy, Severity
from .syscalls import name as syscall_name


class ArgReader:
    """Policy-facing view of one notification's arguments.

    Every read is TOCTOU-guarded: see `seccomp.Listener.read_memory`.
    """

    __slots__ = ("_listener", "_nid", "pid", "_args")

    def __init__(self, listener: seccomp.Listener, nid: int, pid: int, args):
        self._listener = listener
        self._nid = nid
        self.pid = pid
        self._args = args

    def cstring(self, index: int, limit: int = 4096) -> str | None:
        return self._listener.read_cstring(self._nid, self.pid, self._args[index], limit)

    def raw(self, index: int, size: int) -> bytes | None:
        return self._listener.read_memory(self._nid, self.pid, self._args[index], size)

    def at(self, addr: int, size: int) -> bytes | None:
        return self._listener.read_memory(self._nid, self.pid, addr, size)

    def resolve(self, path: str | None, follow: bool = True):
        """Resolve `path` to its true target in the sandbox (symlinks and all).

        Returns (resolved_absolute_path, exists) or (None, False). The policy
        judges the resolved path so a symlink can't disguise the real target.
        """
        if not path:
            return None, False
        return self._listener.resolve_in_root(self.pid, path, follow=follow)


@dataclass
class Stats:
    notifications: int = 0
    allowed: int = 0
    suspicious: int = 0
    violations: int = 0
    denied: int = 0
    by_syscall: Counter = field(default_factory=Counter)
    by_rule: Counter = field(default_factory=Counter)
    decide_us: list[float] = field(default_factory=list)
    response_us: list[float] = field(default_factory=list)

    def snapshot(self) -> dict:
        def pct(vals: list[float], p: float) -> float | None:
            if not vals:
                return None
            s = sorted(vals)
            k = min(len(s) - 1, int(round((p / 100) * (len(s) - 1))))
            return round(s[k], 1)

        return {
            "notifications": self.notifications,
            "allowed": self.allowed,
            "suspicious": self.suspicious,
            "violations": self.violations,
            "denied": self.denied,
            "top_syscalls": self.by_syscall.most_common(8),
            "top_rules": self.by_rule.most_common(8),
            "decide_us_p50": pct(self.decide_us, 50),
            "decide_us_p99": pct(self.decide_us, 99),
            "decide_us_max": round(max(self.decide_us), 1) if self.decide_us else None,
            "response_us": [round(v, 1) for v in self.response_us],
        }


class Monitor:
    """Runs the notification loop until the sandbox exits."""

    def __init__(
        self,
        listener: seccomp.Listener,
        policy: Policy,
        cgroup: Cgroup,
        bus: EventBus,
        stop_on_violation: bool = True,
    ):
        self.listener = listener
        self.policy = policy
        self.cgroup = cgroup
        self.bus = bus
        self.stop_on_violation = stop_on_violation
        self.stats = Stats()
        self.state = "starting"
        self.first_violation: dict | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------- control

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="cerberus-monitor",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def set_state(self, state: str, **detail) -> None:
        self.state = state
        self.bus.emit("state", "info", summary=state, detail=detail)

    # ---------------------------------------------------------------- loop

    def _run(self) -> None:
        self.set_state("running")
        try:
            while not self._stop.is_set():
                notif = self.listener.receive()
                if notif is None:
                    break
                self._handle(notif)
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.EBADF, errno.EINTR):
                self.bus.emit("lifecycle", "suspicious",
                              summary=f"monitor loop error: {exc}")
        finally:
            if self.state == "running":
                self.set_state("exited")

    def _handle(self, notif) -> None:
        t0 = time.perf_counter()
        sname = syscall_name(notif.nr)
        reader = ArgReader(self.listener, notif.id, notif.pid, notif.args)

        try:
            verdict = self.policy.judge(notif.nr, notif.args, reader)
        except Exception as exc:  # a policy bug must not become a sandbox escape
            self.bus.emit("lifecycle", "suspicious",
                          syscall=sname, pid=notif.pid,
                          summary=f"policy error on {sname}, denying: {exc!r}")
            self.listener.deny(notif.id)
            self.stats.notifications += 1
            self.stats.denied += 1
            return

        decide_us = (time.perf_counter() - t0) * 1e6
        self.stats.notifications += 1
        self.stats.by_syscall[sname] += 1
        self.stats.by_rule[verdict.rule] += 1
        self.stats.decide_us.append(decide_us)

        if verdict.severity is Severity.VIOLATION:
            self._respond_violation(notif, sname, verdict, t0)
            return

        if verdict.severity is Severity.SUSPICIOUS:
            self.stats.suspicious += 1
        else:
            self.stats.allowed += 1

        # Anti-TOCTOU allow for read opens: rather than CONTINUE (which makes the
        # kernel re-resolve the path, so a second thread could swap a symlink
        # between our check and the kernel's open), we open the exact validated
        # file ourselves and inject that fd. The syscall returns our fd; the
        # path is never resolved a second time. Falls back to CONTINUE if
        # injection isn't applicable or fails.
        action = "allow"
        injected = False
        if (verdict.rule.startswith("path.")
                and not verdict.detail.get("write")
                and sname in ("open", "openat", "openat2")):
            target = verdict.detail.get("path")
            if target and self.listener.open_and_send(notif.id, notif.pid,
                                                       target, os.O_RDONLY):
                injected = True
                action = "allow+fd"
        if not injected:
            self.listener.allow(notif.id)

        self.bus.emit(
            "syscall", verdict.severity.value, syscall=sname, pid=notif.pid,
            rule=verdict.rule, summary=verdict.summary, action=action,
            detail=verdict.detail, latency_us=round(decide_us, 1),
        )

    def _respond_violation(self, notif, sname: str, verdict, t0: float) -> None:
        self.stats.violations += 1
        self.stats.denied += 1

        froze = False
        if self.policy.freeze_on_violation and self.stop_on_violation:
            try:
                # Freeze every task in the cgroup -- siblings and any children
                # the offending thread spawned -- atomically in the kernel.
                self.cgroup.freeze()
                froze = True
            except OSError as exc:
                self.bus.emit("lifecycle", "suspicious",
                              summary=f"freeze failed, falling back to kill: {exc}")
                self.cgroup.kill()

        if froze:
            # Deliberately DO NOT answer the notification. An unanswered seccomp
            # user-notif keeps the offending thread blocked inside the kernel,
            # so it never returns to userspace to observe the result or run
            # another instruction. Answering with EPERM here instead would open
            # a race: freezing is asynchronous, and the thread could execute a
            # few userspace instructions after getting its errno but before the
            # freezer catches it. Leaving it parked closes that race completely.
            total_us = (time.perf_counter() - t0) * 1e6
        else:
            # Not freezing (observe mode, or freeze failed): refuse the call so
            # the kernel never performs it, and let execution continue.
            self.listener.deny(notif.id, errno.EPERM)
            total_us = (time.perf_counter() - t0) * 1e6
        self.stats.response_us.append(total_us)

        self.bus.emit(
            "violation", "violation", syscall=sname, pid=notif.pid,
            rule=verdict.rule, summary=verdict.summary,
            action="deny+freeze" if froze else "deny",
            detail=dict(verdict.detail, frozen=froze),
            latency_us=round(total_us, 1),
        )

        if self.first_violation is None:
            self.first_violation = {
                "syscall": sname, "rule": verdict.rule,
                "summary": verdict.summary, "detail": verdict.detail,
                "response_us": round(total_us, 1),
            }

        if froze:
            self.set_state("frozen", rule=verdict.rule, syscall=sname,
                           response_us=round(total_us, 1))
            # Nothing in the cgroup will run again, so stop reading the
            # notification fd; remaining parked syscalls die with the process.
            self._stop.set()


def wait_for_exit(pid: int, timeout: float = 30.0) -> int | None:
    """Reap the sandbox's outer process. None on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            done, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return 0
        if done == pid:
            if os.WIFEXITED(status):
                return os.waitstatus_to_exitcode(status)
            return -(status & 0x7F)
        time.sleep(0.01)
    return None


def wait_for_exit_or_frozen(pid: int, monitor: "Monitor",
                            timeout: float = 30.0) -> int | None:
    """Like wait_for_exit, but returns early once the monitor freezes.

    A frozen process never exits on its own, so waiting for its exit would
    always burn the full timeout. Returning as soon as `monitor.state` is
    "frozen" is what makes containment feel instantaneous end to end.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if monitor.state == "frozen":
            return None
        try:
            done, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return 0
        if done == pid:
            if os.WIFEXITED(status):
                return os.waitstatus_to_exitcode(status)
            return -(status & 0x7F)
        time.sleep(0.005)
    return None
