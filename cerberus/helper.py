"""Privileged worker for the native GUI.

The GUI runs as an ordinary user; this helper is what gets elevated (pkexec /
sudo) to do the part that actually needs root — building the sandbox and running
the monitor. It executes one session and streams every event to stdout as a
line of JSON, then exits. The GUI reads those lines and paints them into native
widgets.

This keeps the privilege boundary in the right place: only the sandbox work is
root, and there is no web server, socket, or browser anywhere in the path — just
a pipe between two processes.

Protocol: one JSON object per line on stdout. Event objects mirror EventBus
events; the final line is {"kind":"result", ...} with the verdict.
"""

from __future__ import annotations

import argparse
import base64
import json
import queue
import sys
import threading

from .events import EventBus
from .policy import get_profile
from .runner import Session
from .sandbox import SandboxSpec


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cerberus-helper")
    ap.add_argument("--policy", default="strict")
    ap.add_argument("--net", default="none", choices=["none", "host"])
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--name", default="uploaded.py",
                    help="filename to present inside the sandbox")
    ap.add_argument("--interp", default="python3",
                    help="interpreter to run the file with")
    ap.add_argument("--b64", action="store_true",
                    help="read the script as base64 from stdin (default: raw stdin)")
    args = ap.parse_args(argv)

    import os
    if os.geteuid() != 0:
        _emit({"kind": "error", "severity": "violation",
               "summary": "cerberus-helper must run as root"})
        return 2

    raw = sys.stdin.buffer.read()
    data = base64.b64decode(raw) if args.b64 else raw
    if not data:
        _emit({"kind": "error", "severity": "violation",
               "summary": "no script provided on stdin"})
        return 2

    bus = EventBus(history=2000)
    q = bus.subscribe()
    spec = SandboxSpec(
        argv=[args.interp, f"/work/{args.name}"],
        net=args.net,
        workdir_files={args.name: data},
    )
    session = Session(spec, get_profile(args.policy), bus=bus)

    stop = threading.Event()

    def pump() -> None:
        while not stop.is_set():
            try:
                ev = q.get(timeout=0.1)
            except queue.Empty:
                continue
            _emit({
                "kind": ev.kind, "severity": ev.severity, "seq": ev.seq,
                "ts": ev.ts, "syscall": ev.syscall, "pid": ev.pid,
                "rule": ev.rule, "summary": ev.summary, "action": ev.action,
                "detail": ev.detail, "latency_us": ev.latency_us,
            })

    t = threading.Thread(target=pump, daemon=True)
    t.start()

    result = session.run(timeout=args.timeout)
    stop.set()
    t.join(timeout=1.0)

    _emit({
        "kind": "result",
        "verdict": result.verdict,
        "exit_code": result.exit_code,
        "frozen": result.frozen,
        "duration_s": round(result.duration_s, 3),
        "first_violation": result.first_violation,
        "stats": result.stats,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
