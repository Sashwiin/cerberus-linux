"""End-to-end: run each payload through a real sandbox and assert the outcome."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cerberus.policy import get_profile  # noqa: E402
from cerberus.runner import Session  # noqa: E402
from cerberus.sandbox import SandboxSpec  # noqa: E402

PAYDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads")


def _run(script, policy="strict", net="none", timeout=20):
    with open(os.path.join(PAYDIR, script), "rb") as fh:
        data = fh.read()
    spec = SandboxSpec(
        argv=["python3", f"/work/{script}"],
        net=net,
        workdir_files={script: data},
    )
    return Session(spec, get_profile(policy)).run(timeout=timeout)


def check(name, cond, extra=""):
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name} {extra}")
    return cond


def main():
    ok = True

    print("== benign_wordcount (control, must be CLEAN) ==")
    r = _run("benign_wordcount.py")
    ok &= check("verdict is clean", r.verdict == "clean", f"(got {r.verdict})")
    ok &= check("exited 0", r.exit_code == 0, f"(got {r.exit_code})")
    ok &= check("no violations", r.stats.get("violations") == 0)
    ok &= check("inspected some syscalls", r.stats.get("notifications", 0) > 0,
                f"({r.stats.get('notifications')} syscalls)")

    print("== exfil_credentials (villain #1, must be CONTAINED) ==")
    r = _run("exfil_credentials.py")
    ok &= check("verdict is contained", r.verdict == "contained", f"(got {r.verdict})")
    ok &= check("froze the process", r.frozen)
    fv = r.first_violation or {}
    ok &= check("first violation is a read or connect",
                fv.get("rule", "").startswith(("path.", "endpoint.", "socket.")),
                f"(rule={fv.get('rule')})")
    if fv.get("response_us"):
        print(f"       detect->freeze latency: {fv['response_us']:.1f} us")

    print("== escape_attempt (villain #3, must be CONTAINED) ==")
    r = _run("escape_attempt.py")
    # Escape-class syscalls are parked and judged as violations: the first one
    # (ptrace) freezes the sandbox before it runs, so the payload never reaches
    # its later escape attempts and the verdict is contained.
    ok &= check("verdict is contained", r.verdict == "contained", f"(got {r.verdict})")
    ok &= check("froze the process", r.frozen)
    ok &= check("first violation is an escape",
                (r.first_violation or {}).get("rule", "").startswith("escape."),
                f"(rule={(r.first_violation or {}).get('rule')})")

    print("== fork_bomb_lite (villain #2, caught as fork-bomb behaviour) ==")
    r = _run("fork_bomb_lite.py", timeout=15)
    ok &= check("contained", r.verdict == "contained", f"(got {r.verdict})")
    ok &= check("flagged as fork bomb",
                (r.first_violation or {}).get("rule") == "process.fork_bomb",
                f"(rule={(r.first_violation or {}).get('rule')})")

    print()
    print("ALL PASS" if ok else "SOME FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
