"""Session orchestration: build the sandbox, attach the monitor, report."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field

from . import sandbox as sandbox_mod
from .cgroup import Cgroup, CgroupUnavailable
from .events import EventBus
from .monitor import Monitor, wait_for_exit, wait_for_exit_or_frozen
from .policy import BASELINE_ALLOW, Policy, filter_sets


@dataclass
class SessionResult:
    session_id: str
    verdict: str  # clean | contained | error
    exit_code: int | None
    duration_s: float
    frozen: bool
    first_violation: dict | None
    stats: dict
    degraded: list[str] = field(default_factory=list)


class Session:
    def __init__(
        self,
        spec: sandbox_mod.SandboxSpec,
        policy: Policy,
        bus: EventBus | None = None,
        session_id: str | None = None,
    ):
        self.spec = spec
        self.policy = policy
        self.bus = bus or EventBus()
        self.session_id = session_id or uuid.uuid4().hex[:8]
        self.monitor: Monitor | None = None
        self.cgroup: Cgroup | None = None

    def run(self, timeout: float = 30.0) -> SessionResult:
        started = time.time()
        notify, deny, default_allow = filter_sets(self.policy)
        allow = BASELINE_ALLOW if not default_allow else ()

        self.bus.emit(
            "lifecycle", "info",
            summary=f"starting sandbox under policy '{self.policy.name}'",
            detail={
                "session": self.session_id,
                "argv": self.spec.argv,
                "policy": self.policy.name,
                "net": self.spec.net,
                "notify_syscalls": len(notify),
                "hard_denied_syscalls": len(deny),
                "default_action": "allow" if default_allow else "deny",
            },
        )

        try:
            cg = Cgroup(f"cerberus-{self.session_id}").create(
                memory_max=self.spec.memory_max,
                pids_max=self.spec.pids_max,
                cpu_max=self.spec.cpu_max,
            )
        except CgroupUnavailable as exc:
            self.bus.emit("lifecycle", "violation", summary=str(exc))
            return SessionResult(self.session_id, "error", None,
                                 time.time() - started, False, None, {})
        self.cgroup = cg
        if cg.degraded:
            self.bus.emit(
                "lifecycle", "suspicious",
                summary="some resource caps unavailable: "
                        + ", ".join(cg.degraded)
                        + " (controller not delegated to this cgroup)",
            )

        pid = None
        try:
            pid, listener = sandbox_mod.launch(
                self.spec, cg, notify, deny, default_allow, allow=allow
            )
            mon = Monitor(listener, self.policy, cg, self.bus)
            self.monitor = mon
            mon.start()
            # The payload has not executed a single instruction yet; it is
            # parked waiting for this byte. Releasing only now guarantees
            # there is no unmonitored window at startup.
            sandbox_mod.release(listener)
            self.bus.emit("lifecycle", "info", summary="payload released under monitor")

            # Wait for the payload to finish -- but a frozen payload never
            # will, so stop the moment the monitor reports containment. Without
            # this the run would block for the full timeout on every violation,
            # because the offending process is suspended, not dead.
            exit_code = wait_for_exit_or_frozen(pid, mon, timeout=timeout)
            timed_out = exit_code is None and mon.state != "frozen"
            if timed_out:
                self.bus.emit("lifecycle", "suspicious",
                              summary=f"payload exceeded {timeout:.0f}s, terminating")
                cg.kill()
                exit_code = wait_for_exit(pid, timeout=2.0)

            mon.stop()
            mon.join(timeout=1.0)
            listener.close()

            frozen = cg.frozen_flag()
            if frozen:
                verdict = "contained"
            elif mon.stats.violations:
                verdict = "contained"
            else:
                verdict = "clean"

            result = SessionResult(
                session_id=self.session_id,
                verdict=verdict,
                exit_code=exit_code,
                duration_s=time.time() - started,
                frozen=frozen,
                first_violation=mon.first_violation,
                stats=mon.stats.snapshot(),
                degraded=cg.degraded,
            )
            self.bus.emit(
                "lifecycle", "violation" if verdict == "contained" else "info",
                summary=(
                    "sandbox contained: payload was stopped mid-syscall"
                    if verdict == "contained"
                    else "sandbox exited with no policy violations"
                ),
                detail={
                    "verdict": verdict, "exit_code": exit_code,
                    "frozen": frozen,
                    "duration_s": round(result.duration_s, 3),
                    **mon.stats.snapshot(),
                },
            )
            return result
        finally:
            if pid is not None:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    pass
            # The tmpfs and every mount inside it disappear with the sandbox's
            # mount namespace, so teardown is just the cgroup.
            cg.destroy()
            sandbox_mod.cleanup_host_root()
