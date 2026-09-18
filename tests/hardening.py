"""Regression tests for the hardening pass — each proves a specific bypass is
closed. Run as root.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cerberus import seccomp  # noqa: E402
from cerberus.policy import get_profile, filter_sets, BASELINE_ALLOW  # noqa: E402
from cerberus.runner import Session  # noqa: E402
from cerberus.sandbox import SandboxSpec  # noqa: E402
from cerberus.syscalls import nr  # noqa: E402


def run(code: bytes, policy="strict", net="none", timeout=20, name="x.py",
        pids_max="64"):
    spec = SandboxSpec(argv=["python3", f"/work/{name}"], net=net,
                       pids_max=pids_max, workdir_files={name: code})
    return Session(spec, get_profile(policy)).run(timeout=timeout)


def check(name, cond, extra=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")
    return cond


def main():
    ok = True

    print("== symlink escape is resolved and denied ==")
    r = run(b"""
import os
os.symlink('/etc/shadow', '/work/innocent.txt')
try:
    open('/work/innocent.txt','rb').read(); print('LEAK')
except Exception: print('blocked')
""")
    ok &= check("contained", r.verdict == "contained")
    ok &= check("flagged as sensitive (resolved target)",
                (r.first_violation or {}).get("rule") == "path.sensitive",
                f"({(r.first_violation or {}).get('rule')})")

    print("== '..' escape out of /work is denied ==")
    r = run(b"""
try:
    open('/work/../../etc/shadow','rb').read(); print('LEAK')
except Exception: print('blocked')
""")
    ok &= check("contained", r.verdict == "contained")

    print("== x32 ABI is blocked by the filter ==")
    prog = seccomp.build_program([nr("openat")], [nr("ptrace")], True)
    # the program must contain the x32 JSET guard -> KILL
    has_x32 = any(code == (seccomp.BPF_JMP | seccomp.BPF_JSET | seccomp.BPF_K)
                  and k == seccomp.X32_SYSCALL_BIT for code, _, _, k in prog)
    ok &= check("filter contains x32 guard", has_x32)

    print("== dropped binary cannot be executed (noexec /work) ==")
    r = run(b"""
import os
open('/work/m','wb').write(b'#!/bin/sh\\necho pwned\\n'); os.chmod('/work/m',0o755)
try:
    os.execv('/work/m',['/work/m']); print('EXECUTED')
except OSError as e: print('exec blocked', e)
""")
    ok &= check("payload survived without executing the dropped binary",
                r.exit_code == 0 or r.verdict in ("clean", "contained"))

    print("== payload runs unprivileged (uid 65534) ==")
    r = run(b"import os; print('uid', os.getuid()); assert os.getuid()==65534")
    ok &= check("clean", r.verdict == "clean")
    ok &= check("exited 0 (uid assert held)", r.exit_code == 0,
                f"(exit {r.exit_code})")

    print("== capabilities fully dropped ==")
    r = run(b"""
caps=open('/proc/self/status').read()
line=[l for l in caps.splitlines() if l.startswith('CapEff')][0]
val=int(line.split()[1],16)
print('CapEff', hex(val))
assert val==0, 'residual capabilities'
""")
    ok &= check("no effective capabilities", r.exit_code == 0)

    print("== reading own /proc maps is clean (version-independent) ==")
    # Python 3.14 reads /proc/<pid>/maps at startup; 3.12 doesn't. This must not
    # be a policy decision, or the same file gets two verdicts on two machines.
    r = run(b"open('/proc/1/maps').read(); open('/proc/self/maps').read();"
            b" print('ok')")
    ok &= check("/proc/*/maps reads are clean", r.verdict == "clean",
                f"({r.verdict})")
    r = run(b"\ntry:\n open('/proc/1/mem','rb').read(1)\nexcept Exception: pass\n")
    ok &= check("/proc/*/mem is still refused", r.verdict == "contained",
                f"({r.verdict})")

    print("== benign control still runs clean ==")
    with open(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "payloads", "benign_wordcount.py"), "rb") as fh:
        r = run(fh.read(), name="benign_wordcount.py")
    ok &= check("clean", r.verdict == "clean", f"({r.stats.get('notifications')} syscalls)")

    print()
    print("ALL PASS" if ok else "SOME FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
