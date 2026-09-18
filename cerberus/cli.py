"""cerberus run — launch a script in the sandbox from the command line."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .events import Event, EventBus
from .policy import PROFILES, get_profile
from .runner import Session
from .sandbox import SandboxSpec

RESET = "\033[0m"
DIM = "\033[2m"
COLORS = {
    "info": "\033[36m", "suspicious": "\033[33m", "violation": "\033[1;31m",
}
GREEN = "\033[32m"
RED = "\033[1;31m"


def _tty() -> bool:
    return sys.stderr.isatty()


def _c(text: str, color: str) -> str:
    if not _tty():
        return text
    return f"{color}{text}{RESET}"


def _print_event(ev: Event, json_mode: bool) -> None:
    if json_mode:
        print(ev.to_json(), flush=True)
        return
    if ev.kind == "syscall" and ev.severity == "info":
        return  # keep the terminal readable; -v shows these
    color = COLORS.get(ev.severity, "")
    tag = {
        "violation": "VIOLATION", "state": "STATE",
        "lifecycle": "•", "syscall": "syscall", "stats": "stats",
    }.get(ev.kind, ev.kind)
    line = f"  {_c(tag, color):>10}  {ev.summary}"
    if ev.syscall and ev.kind in ("syscall", "violation"):
        line += _c(f"  [{ev.syscall}]", DIM)
    if ev.latency_us is not None and ev.kind == "violation":
        line += _c(f"  ({ev.latency_us:.0f}µs)", DIM)
    print(line, file=sys.stderr, flush=True)


def cmd_run(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        print("cerberus: must run as root (needs mount, cgroup, and seccomp "
              "privileges). Try sudo.", file=sys.stderr)
        return 2

    target = args.command
    workdir_files: dict[str, bytes] = {}
    if args.script:
        with open(args.script, "rb") as fh:
            workdir_files[os.path.basename(args.script)] = fh.read()
        interp = args.interpreter or _guess_interpreter(args.script)
        target = [interp, os.path.join("/work", os.path.basename(args.script))]
        target += args.command  # any extra args after --

    if not target:
        print("cerberus: nothing to run", file=sys.stderr)
        return 2

    policy = get_profile(args.policy)
    if args.net == "host":
        # A host-network sandbox only makes sense with a network-permitting
        # policy; warn rather than silently contradict the flags.
        if not (policy.allow_network or policy.allow_loopback):
            print(f"cerberus: warning: --net host with policy '{policy.name}' "
                  f"will still refuse connections", file=sys.stderr)

    spec = SandboxSpec(
        argv=target,
        net=args.net,
        memory_max=args.memory,
        pids_max=str(args.pids),
        workdir_files=workdir_files,
    )

    bus = EventBus()
    q = bus.subscribe()
    session = Session(spec, policy, bus=bus)

    import threading

    result_box: dict = {}

    def _drain() -> None:
        import queue as _queue
        while True:
            try:
                ev = q.get(timeout=0.2)
            except _queue.Empty:
                if result_box.get("done"):
                    break
                continue
            _print_event(ev, args.json)

    printer = threading.Thread(target=_drain, daemon=True)
    printer.start()

    if not args.json:
        print(_c("┌─ Cerberus", "\033[1m")
              + _c(f"  policy={policy.name} net={args.net}", DIM),
              file=sys.stderr)

    result = session.run(timeout=args.timeout)
    result_box["done"] = True
    printer.join(timeout=1.0)

    if args.json:
        print(json.dumps({
            "session_id": result.session_id, "verdict": result.verdict,
            "exit_code": result.exit_code, "frozen": result.frozen,
            "duration_s": round(result.duration_s, 3),
            "first_violation": result.first_violation, "stats": result.stats,
        }))
    else:
        print(file=sys.stderr)
        if result.verdict == "contained":
            fv = result.first_violation or {}
            print(_c("└─ CONTAINED", RED)
                  + f"  {fv.get('summary', 'policy violation')}",
                  file=sys.stderr)
            if fv.get("response_us"):
                print(f"     detected and frozen in "
                      + _c(f"{fv['response_us']:.0f} µs", "\033[1m"),
                      file=sys.stderr)
        elif result.verdict == "clean":
            print(_c("└─ CLEAN", GREEN)
                  + f"  exit={result.exit_code}, "
                  + f"{result.stats.get('notifications', 0)} syscalls inspected",
                  file=sys.stderr)
        else:
            print(_c("└─ ERROR", RED) + "  sandbox could not start",
                  file=sys.stderr)

    # Exit code: 0 clean, 3 contained, 2 error. Lets scripts gate on it.
    return {"clean": 0, "contained": 3, "error": 2}.get(result.verdict, 1)


def _guess_interpreter(path: str) -> str:
    ext = os.path.splitext(path)[1]
    return {
        ".py": "python3", ".sh": "bash", ".js": "node",
        ".rb": "ruby", ".pl": "perl",
    }.get(ext, "python3")


def cmd_policies(_args: argparse.Namespace) -> int:
    for pname, pol in PROFILES.items():
        print(f"{pname}:")
        print(f"    network       : {'allowed' if pol.allow_network else 'denied'}")
        print(f"    loopback      : {'allowed' if pol.allow_loopback else 'denied'}")
        print(f"    exec          : {'allowed' if pol.allow_exec else 'denied'}")
        print(f"    unlisted call : {'allow' if pol.default_allow_unlisted else 'DENY'}")
        print(f"    on violation  : {'freeze' if pol.freeze_on_violation else 'observe'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cerberus",
        description="Run untrusted code in an ephemeral, monitored sandbox.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a script or command in the sandbox")
    r.add_argument("-s", "--script", help="a script file to copy in and run")
    r.add_argument("-i", "--interpreter", help="interpreter for --script")
    r.add_argument("-p", "--policy", default="strict", choices=list(PROFILES),
                   help="policy profile (default: strict)")
    r.add_argument("--net", default="none", choices=["none", "host"],
                   help="network mode (default: none)")
    r.add_argument("--memory", default="256M", help="memory cap (default: 256M)")
    r.add_argument("--pids", type=int, default=64, help="max processes")
    r.add_argument("--timeout", type=float, default=30.0, help="wall-clock limit")
    r.add_argument("--json", action="store_true", help="emit JSONL events")
    r.add_argument("command", nargs="*", help="command to run (after --)")
    r.set_defaults(func=cmd_run)

    pol = sub.add_parser("policies", help="list policy profiles")
    pol.set_defaults(func=cmd_policies)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
