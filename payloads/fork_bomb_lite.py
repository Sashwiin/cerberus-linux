#!/usr/bin/env python3
"""VILLAIN #2 — resource exhaustion, contained by cgroup caps, not the monitor.

Tries to spawn a runaway tree of children. Under Cerberus the pids.max cap
stops it and the process count never explodes. This one demonstrates that
isolation carries its own weight even when no *syscall* is a policy violation:
containment is layered.
"""
import os
import time

n = 0
try:
    while True:
        pid = os.fork()
        if pid == 0:
            time.sleep(30)  # child just sits, holding a pid slot
            os._exit(0)
        n += 1
        if n % 20 == 0:
            print(f"[forkbomb] spawned {n} children")
        if n > 5000:
            break
except OSError as exc:
    print(f"[forkbomb] fork failed after {n} children: {exc}")
print(f"[forkbomb] total children: {n}")
