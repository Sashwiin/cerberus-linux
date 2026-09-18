"""cgroup v2 containment and the response primitives built on it.

The freezer is the reason this file exists. `cgroup.freeze` stops *every*
task in the cgroup atomically in the kernel — there is no window in which a
forked child keeps running while its parent is being stopped, which is
exactly the hole you get from sending SIGSTOP to pids by hand.
"""

from __future__ import annotations

import os
import time
from pathlib import Path


class CgroupUnavailable(RuntimeError):
    pass


def find_cgroup2_root() -> Path:
    """Locate the cgroup2 mount.

    Unified-only systems (Fedora, recent Ubuntu) mount it at /sys/fs/cgroup.
    Hybrid systems park it at /sys/fs/cgroup/unified. Containers vary.
    """
    candidates: list[Path] = []
    try:
        with open("/proc/self/mounts", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "cgroup2":
                    candidates.append(Path(parts[1]))
    except OSError as exc:
        raise CgroupUnavailable(f"cannot read /proc/self/mounts: {exc}") from exc

    if not candidates:
        raise CgroupUnavailable(
            "no cgroup2 filesystem mounted; Cerberus needs cgroup v2 for the "
            "freezer (kernel 4.15+, and the distro must not be cgroup v1 only)"
        )
    # Prefer the shallowest mount, which on a unified system is /sys/fs/cgroup.
    candidates.sort(key=lambda p: len(p.parts))
    return candidates[0]


class Cgroup:
    """One sandbox's cgroup, plus freeze/kill."""

    def __init__(self, name: str, root: Path | None = None):
        self.root = root or find_cgroup2_root()
        self.path = self.root / name
        self.name = name
        self._created = False
        self.degraded: list[str] = []

    # ------------------------------------------------------------- lifecycle

    def create(
        self,
        memory_max: str | None = "256M",
        pids_max: str | None = "64",
        cpu_max: str | None = None,
    ) -> "Cgroup":
        try:
            self.path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CgroupUnavailable(
                f"cannot create cgroup at {self.path}: {exc}. Run as root, or "
                f"delegate a subtree to your user."
            ) from exc
        self._created = True

        # Enable the controllers we need in the PARENT's subtree_control, or the
        # child's memory.max / pids.max files won't exist and the caps become
        # no-ops. Without this a fork bomb is only "best effort" contained;
        # with it, pids.max is a hard wall. Requires the parent itself to have
        # the controllers available (delegation), so it's still best-effort, but
        # we now actively try rather than assuming.
        self._enable_controllers()

        for fname, value in (
            ("memory.max", memory_max),
            ("pids.max", pids_max),
            ("cpu.max", cpu_max),
        ):
            if value is None:
                continue
            if not self._write(fname, value):
                self.degraded.append(fname)
        return self

    def _enable_controllers(self, controllers=("memory", "pids", "cpu")) -> None:
        """Turn on controllers in the parent's subtree_control.

        A cgroup v2 controller is only usable in a child if the parent lists it
        in cgroup.subtree_control, and it can only be enabled there if the
        parent has it available (cgroup.controllers). We enable what we can and
        silently skip the rest -- the per-cap write later records anything that
        still didn't take.
        """
        parent = self.path.parent
        try:
            available = (parent / "cgroup.controllers").read_text().split()
        except OSError:
            return
        want = [c for c in controllers if c in available]
        for c in want:
            try:
                (parent / "cgroup.subtree_control").write_text(f"+{c}")
            except OSError:
                pass

    def _write(self, fname: str, value: str) -> bool:
        try:
            (self.path / fname).write_text(value)
            return True
        except OSError:
            return False

    def add_pid(self, pid: int) -> None:
        """Move a process in. Descendants inherit membership across fork."""
        (self.path / "cgroup.procs").write_text(str(pid))

    def pids(self) -> list[int]:
        try:
            raw = (self.path / "cgroup.procs").read_text()
        except OSError:
            return []
        return [int(x) for x in raw.split()]

    # ------------------------------------------------------------- response

    def freeze(self) -> float:
        """Freeze every task in the cgroup. Returns wall time in seconds.

        Returns as soon as the write completes. The kernel has already stopped
        scheduling the tasks at that point; `cgroup.events` reporting
        frozen=1 lags slightly behind because it waits for every task to
        actually park.
        """
        t0 = time.perf_counter()
        (self.path / "cgroup.freeze").write_text("1")
        return time.perf_counter() - t0

    def thaw(self) -> None:
        (self.path / "cgroup.freeze").write_text("0")

    def is_frozen(self) -> bool:
        try:
            for line in (self.path / "cgroup.events").read_text().splitlines():
                if line.startswith("frozen "):
                    return line.split()[1] == "1"
        except OSError:
            pass
        return False

    def frozen_flag(self) -> bool:
        """The requested state, as opposed to the settled state."""
        try:
            return (self.path / "cgroup.freeze").read_text().strip() == "1"
        except OSError:
            return False

    def kill_atomic(self) -> bool:
        """SIGKILL everything at once via cgroup.kill (kernel 5.14+).

        Works even on a frozen cgroup. Returns False if the interface is not
        available (older kernel), so the caller can thaw and fall back.
        """
        try:
            (self.path / "cgroup.kill").write_text("1")
            return True
        except OSError:
            return False

    def kill(self) -> bool:
        """SIGKILL everything in the cgroup. Prefers the atomic interface."""
        if self.kill_atomic():
            return True
        killed = False
        for pid in self.pids():
            try:
                os.kill(pid, 9)
                killed = True
            except OSError:
                pass
        return killed

    # -------------------------------------------------------------- cleanup

    def destroy(self) -> None:
        if not self._created:
            return
        # Kill a frozen cgroup WITHOUT thawing it first. `cgroup.kill` SIGKILLs
        # every member atomically even while frozen (kernel 5.14+), so the
        # contained payload never gets a scheduling slice on the way out --
        # thawing first would hand it one, letting it flush buffered output or
        # fire a parting syscall. Only fall back to thaw+kill if cgroup.kill is
        # unavailable.
        if not self.kill_atomic():
            # Older kernel without cgroup.kill: a SIGKILL to a frozen task is
            # only delivered once it runs, so we must thaw. This reintroduces
            # the brief output-flush window, unavoidable pre-5.14.
            try:
                if self.frozen_flag():
                    self.thaw()
            except OSError:
                pass
            self.kill()
        for _ in range(50):
            if not self.pids():
                break
            time.sleep(0.01)
        try:
            self.path.rmdir()
        except OSError:
            pass
        self._created = False

    def __enter__(self) -> "Cgroup":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.destroy()
