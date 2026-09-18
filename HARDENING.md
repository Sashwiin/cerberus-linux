# Cerberus — hardening

This documents the hardening pass: the bypasses that were found and closed, how
each is verified, the gaps that remain, and the roadmap to a boundary you could
trust with genuinely hostile malware.

Run the regression suite (as root):

```bash
sudo python3 tests/hardening.py
```

## Bypasses found and closed

Each of these was a real hole; each has a test in `tests/hardening.py`.

| # | Bypass | Before | After |
|---|--------|--------|-------|
| 1 | **Symlink escape** — a symlink under `/work` pointing at `/etc/shadow`; the policy saw an allowed `/work/…` path and permitted the open. | allowed (verdict CLEAN) | resolved through `/proc/<pid>/root` with `openat2(RESOLVE_IN_ROOT\|RESOLVE_NO_MAGICLINKS)` and judged on the **true target** → **denied** |
| 2 | **`..` traversal** out of the sandbox root. | relied on string prefixing | resolution is confined to the sandbox root; escapes are refused |
| 3 | **TOCTOU on allowed opens** — `CONTINUE` makes the kernel re-resolve the path, so a second thread could swap a symlink after the check. | racy | the supervisor opens the validated file itself and injects the fd with `SECCOMP_ADDFD` (`FLAG_SEND`); the path is never resolved twice |
| 4 | **x32 ABI** — syscalls issued as `nr \| 0x40000000` share the x86-64 audit arch but dodge every number-based check. | sailed through on the default action | filter kills any syscall carrying the x32 bit |
| 5 | **Dropped-binary execution** — write a binary to `/work` and `execve` it. | ran | `/work` and `/tmp` are mounted **noexec**; the interpreter (on read-only `/usr`) still reads the script, which noexec permits |
| 6 | **Sensitive file under an allowed prefix** — `/etc` is bind-mounted, and the old logic *allowed-but-flagged* sensitive files that sat under an allowed prefix. | `/etc/shadow` was "watched", not denied | sensitive targets (credentials, keys, `/proc/*/mem`, raw devices) are **always a violation**, regardless of prefix |
| 7 | **Capability / privilege retention.** | dropped to uid 65534 only | also empties the capability **bounding set**, locks **securebits** (`SECBIT_NOROOT`), and confirms `CapEff == 0` — verified by test |
| 8 | **Resource limits not enforced** where controllers weren't delegated. | best-effort | enables `+memory +pids +cpu` in the parent's `subtree_control` so `pids.max` is a hard wall (needs a host with cgroup v2 controllers; degrades gracefully otherwise) |

The design principle throughout: **decide on the resolved reality, not the
requested string**, and **deny sensitive targets by identity, not by location**.

## What is deliberately still not covered

Honesty matters more than a bigger table.

- **A kernel exploit escapes everything here.** Cerberus shares the host kernel.
  seccomp, namespaces, and cgroups all run on it, so a local privilege-escalation
  bug in the kernel defeats the whole model. Closing this needs a second machine
  boundary — a VM (below).
- **Side channels** (timing, Spectre-class, resource observation) are out of
  scope.
- **The `observe` policy** intentionally allows network and only records — it is
  for watching code you've already decided to let out, not for containment.
- **TOCTOU on non-read opens** (writes/creates) still uses `CONTINUE` after a
  resolved-path check; the injected-fd path currently covers read opens, which is
  where the exfiltration threat lives.

## Roadmap to a boundary you could trust with real malware

The in-process hardening above makes Cerberus solid for **studying code you're
suspicious of**. To **cage code you know is hostile**, add the missing hard
boundary. In rough order of effort:

1. **Run Cerberus inside a disposable VM.** A throwaway KVM/QEMU guest with a
   copy-on-write overlay disk (discarded after each run), no shared folders, and
   an isolated network. A kernel break-out then only wrecks the guest. This is
   the single biggest jump in safety and needs no code change to Cerberus — it's
   a deployment wrapper. See `packaging/run_in_vm.md` for a concrete QEMU recipe.
2. **Swap the namespace sandbox for gVisor (`runsc`).** A user-space kernel that
   intercepts the guest's syscalls itself, shrinking the host-kernel attack
   surface dramatically. Cerberus's monitor concept ports on top of it.
3. **Independent audit** of the seccomp filter, the pidfd handshake, and the
   privilege-drop ordering. Today it is solo code with a self-written test suite.

A realistic framing for a reviewer: *Cerberus is a working detect-and-contain
engine with argument-level policy and a live, latency-instrumented view — the
component you would run **inside** layer 1 or 2 above, not a replacement for
them.*
