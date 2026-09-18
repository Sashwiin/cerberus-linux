"""cerberus doctor — self-diagnostic. Run: sudo python3 -m cerberus.doctor

Prints the running version, proves whether this copy has the /proc read fix,
and runs the payloads through a real sandbox so you can see the actual verdicts
on THIS machine (and this Python). If something is off, paste this whole output.
"""

from __future__ import annotations

import os
import sys

from . import __version__, BUILD
from .policy import DEFAULT_READ_PREFIXES, get_profile
from .runner import Session
from .sandbox import SandboxSpec

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAYLOAD_DIR = os.path.join(ROOT, "payloads")


def _run_code(code: bytes, name="probe.py", policy="strict"):
    spec = SandboxSpec(argv=["python3", f"/work/{name}"],
                       workdir_files={name: code})
    return Session(spec, get_profile(policy)).run(timeout=20)


def main() -> int:
    print("=" * 64)
    print(f" Cerberus doctor — v{__version__}  ({BUILD})")
    print(f" python : {sys.version.split()[0]}   ({sys.executable})")
    print(f" source : {ROOT}")
    print("=" * 64)

    # 1. Does THIS loaded code have the /proc read fix?
    has_proc = "/proc" in DEFAULT_READ_PREFIXES
    print(f"[{'ok' if has_proc else 'STALE'}] /proc in read allowlist: {has_proc}"
          + ("" if has_proc else
             "  <-- you are running OLD code (stale bytecode or wrong folder)"))
    if not has_proc:
        print("\n  FIX: from this folder run:")
        print("     find . -name __pycache__ -type d -exec rm -rf {} +")
        print("     python3 -c \"import cerberus,os;print(os.path.abspath(cerberus.__file__))\"")
        print("  and make sure that path is inside THIS folder, then re-run.")

    if os.geteuid() != 0:
        print("\n(run again with sudo to exercise the sandbox: "
              "sudo python3 -m cerberus.doctor)")
        return 0 if has_proc else 1

    print("\nrunning payloads through a real sandbox on this machine…\n")

    checks = []

    def show(label, r, expect):
        v = r.verdict
        fv = r.first_violation or {}
        mark = "ok" if v == expect else "!!"
        detail = ""
        if fv:
            detail = f"  → {fv.get('rule')}: {fv.get('summary','')[:60]}"
        print(f"  [{mark}] {label:<26} {v:<10} (expect {expect}){detail}")
        checks.append(v == expect)

    show("benign_wordcount", _run_code(open(f"{PAYLOAD_DIR}/benign_wordcount.py","rb").read(),
                                       "benign_wordcount.py"), "clean")
    show("escape_attempt", _run_code(open(f"{PAYLOAD_DIR}/escape_attempt.py","rb").read(),
                                     "escape_attempt.py"), "contained")
    show("read /proc/1/maps", _run_code(b"open('/proc/1/maps').read();"
                                        b"open('/proc/self/maps').read()"), "clean")
    show("exfil_credentials", _run_code(open(f"{PAYLOAD_DIR}/exfil_credentials.py","rb").read(),
                                        "exfil_credentials.py"), "contained")
    show("read /proc/1/mem", _run_code(b"\ntry:\n open('/proc/1/mem','rb').read(1)\n"
                                       b"except Exception: pass\n"), "contained")

    ok = has_proc and all(checks)
    print("\n" + ("ALL GOOD — this build behaves correctly on this machine."
                  if ok else
                  "PROBLEM — see the lines marked !! or STALE above; paste this output."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
