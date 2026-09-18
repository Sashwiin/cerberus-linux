# Changelog

All notable changes to Cerberus are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version the code reports lives in `cerberus/__init__.py` (`__version__`) and
is shown in the app window header and the `run-native.sh` startup line.

## [Unreleased]

- Nothing yet.

## [0.6.0] — 2026-09-19

Escape attempts are now visible.

### Changed
- **Escape/tamper syscalls now show as CONTAINED, not CLEAN.** Previously the
  escape class (`ptrace`, `mount`, `umount2`, `pivot_root`, `chroot`, `setns`,
  `unshare`, `bpf`, `perf_event_open`, module loading, `mknod`, key management,
  privilege- and host-state changes, `pidfd_getfd`, …) was refused in-kernel
  with `EPERM` and never reported, so a file full of escape attempts —
  `escape_attempt.py` — read as **CLEAN**. These syscalls are now parked and
  judged as **visible, freezing violations**: the attempt is prevented *and*
  seen. `escape_attempt.py` now trips `escape.ptrace` on its first call and the
  sandbox freezes (**CONTAINED**), with a human-readable summary
  (e.g. *"attempted to attach a debugger to another process (ptrace)"*).
- The in-kernel silent block is now reserved for the small set of pure
  monitor-bypass vectors where parking the call for a verdict would itself be
  the risk: the `io_uring` family, `open_by_handle_at` / `name_to_handle_at`,
  and installing a second `seccomp` filter.

### Fixed
- `escape_attempt.py` and the `cerberus doctor` / integration expectations
  updated to reflect the CONTAINED verdict; the sandbox still drops privileges
  *before* installing the filter, so its own `setresuid`/`setresgid` are never
  caught by the new escape rules.

## [0.5.0] — 2026-09-19

Disposable-VM mode inside the native window, cross-machine consistency, and
diagnostics.

### Added
- **"Run in disposable VM"** in the native GUI: runs each check two boundaries
  deep (Cerberus's sandbox *inside* a throwaway QEMU VM) with results rendered
  in the **same native window** — no browser. The window becomes a native client
  of the in-VM sandbox server (`cerberus/wsclient.py`, stdlib-only WebSocket).
- Live VM **boot console** (kernel + cloud-init) and **download %/stage
  progress** streamed into the window, so you can see exactly what is happening
  during boot.
- Persistent **execution-mode badge** in the header: `LOCAL SANDBOX`, or
  `DISPOSABLE VM · off/BOOTING/LIVE`, so you always know where code runs.
- **`cerberus doctor`** self-diagnostic (`sudo python3 -m cerberus.doctor`):
  prints the version, proves whether the copy has the `/proc` fix, and runs the
  payloads through a real sandbox to show verdicts on the user's own machine.
- **Version stamp** shown in the window header and printed by `run-native.sh`.

### Fixed
- **Same file, two verdicts across machines.** Python 3.14 reads
  `/proc/<pid>/maps` at interpreter startup while 3.12 does not; the policy
  flagged that interpreter-internal read as "outside allowlist", so
  `escape_attempt.py` showed CONTAINED on one machine and CLEAN on another. All
  of `/proc` is now readable (the sandbox's own PID+mount namespaces make it
  safe); `/proc/*/mem` and `/proc/kcore` stay denied by pattern.
- **Stale bytecode ran old code.** Extracting over an existing folder could keep
  Python using a stale `__pycache__/*.pyc`. `run-native.sh` now wipes
  `__pycache__` on start and runs with `-B`; the elevated helper runs with `-B`.
- **VM served nothing (empty page).** `textwrap.dedent` took the embedded base64
  source tarball as its indentation baseline and stripped every file body out of
  the cloud-config, so cloud-init silently skipped `write_files`/`runcmd`. The
  cloud-config is now built with explicit indentation and validated by a real
  YAML parser in `tests/vm_seed.py`.

### Changed
- Fork-bomb detection now triggers on **rate** (process spawns per second)
  rather than an absolute count, so it fires before the cgroup pids cap stops
  (and hides) the bomb — consistent whether or not the cap is enforced.
- VM boot no longer runs an offline `apt install` (it stalled ~30s against the
  intentionally cut-off network); cloud images already ship Python 3. Added a
  debug console login and clearer boot messaging.

## [0.4.0] — 2026-09-18

Hardening pass and the disposable-VM boundary.

### Added
- **QEMU disposable-VM launcher** (`python3 -m cerberus.vm run`): downloads a
  small cloud image once, boots a copy-on-write overlay deleted on exit, with an
  isolated network (`restrict=on`) and one forwarded dashboard port. Seed is a
  dependency-free pure-Python ISO9660 + Rock Ridge cloud-init image
  (`cerberus/iso9660.py`), carrying the source and a boot launcher.
- **Behavioural fork-bomb detection** — surfaced as a visible violation instead
  of the silent cgroup pids cap.
- `tests/hardening.py` regression suite; `HARDENING.md` and
  `packaging/run_in_vm.md`.

### Security
- Closed real sandbox-evasion bypasses:
  - **Symlink and `..` escapes** — paths are resolved through
    `/proc/<pid>/root` with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`
    and judged on the true target.
  - **seccomp-notify TOCTOU on read opens** — the supervisor opens the
    validated file itself and injects the fd with `SECCOMP_ADDFD` instead of
    `CONTINUE`.
  - **x32 ABI** — syscalls carrying `0x40000000` are killed.
  - **Dropped-binary execution** — `/work` and `/tmp` mounted `noexec`.
  - Sensitive targets are always denied regardless of prefix; capability
    bounding set emptied and securebits locked (`CapEff == 0`); cgroup
    controllers delegated so resource caps actually enforce.

## [0.3.0] — 2026-09-18

Desktop packaging.

### Added
- **Portable Linux AppImage** (`Cerberus-x86_64.AppImage`): bundles a
  relocatable CPython and the whole app; `AppRun` elevates only the sandbox
  server via `pkexec` while opening the browser as the user.
- **Native Tkinter desktop app** (no browser): the window runs as the user and
  streams events from a privileged helper (`cerberus/helper.py`) over a pipe.
  `run-native.sh`, `NATIVE.md`, and a native-GUI AppImage build script.

## [0.2.0] — 2026-09-18

Upload entry point (project brief §6.1).

### Added
- **Drag-and-drop upload** as the primary way to check a file in the dashboard;
  bundled sample villains kept as a secondary option.
- Upload hardening: 256 KiB size cap, per-client rate limit, filename/extension
  validation, binary-blob rejection, one session at a time.

### Changed
- Uploaded code runs as an **unprivileged uid (65534)**, never root; setup keeps
  root only for mount/pivot_root, dropping privileges just before `execve`.

## [0.1.0] — 2026-09-18

Initial working build for VinHack 2026 (Trust, Safety & Digital Security).

### Added
- Ephemeral **tmpfs + namespace sandbox** (mount/pid/net/ipc/uts/cgroup),
  read-only binds, resource caps.
- Hand-assembled **seccomp user-notification monitor** (ctypes only, no eBPF /
  libseccomp), with the listener fd pulled via `pidfd_getfd` to avoid the
  sendmsg deadlock.
- **Default-deny policy engine** with argument-level rules (sensitive paths,
  non-loopback connect, socket families, exec tracking).
- **Freeze-mid-syscall response** via the cgroup v2 freezer, with microsecond
  detect-to-freeze latency measurement.
- Dependency-free **web dashboard** (HTTP + WebSocket), CLI, four villain
  payloads and a benign control, smoke + integration tests.

[Unreleased]: https://github.com/Sashwiin/cerberus-linux/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Sashwiin/cerberus-linux/releases/tag/v0.6.0
[0.5.0]: https://github.com/Sashwiin/cerberus-linux/releases/tag/v0.5.0
[0.4.0]: https://github.com/Sashwiin/cerberus-linux/releases/tag/v0.4.0
[0.3.0]: https://github.com/Sashwiin/cerberus-linux/releases/tag/v0.3.0
[0.2.0]: https://github.com/Sashwiin/cerberus-linux/releases/tag/v0.2.0
[0.1.0]: https://github.com/Sashwiin/cerberus-linux/releases/tag/v0.1.0
