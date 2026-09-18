# Cerberus — demo runbook

The whole demo is four runs and about 90 seconds of talking. The goal is to make
the judges *see* the freeze happen and *see* the microsecond latency, because
that number is the thing no other project in the room will have.

## Before you present (2 min, do it once)

```bash
cd cerberus
sudo python3 -m cerberus.web        # leave running
```

Open `http://127.0.0.1:8787` on the projector. Full-screen the browser. Confirm
the top-right says **● live** (WebSocket connected). Have one script of your own
ready on the desktop to drag in during Beat 0.

If cgroup v2 isn't the default (rare on Fedora/recent Ubuntu), check:

```bash
stat -fc %T /sys/fs/cgroup       # want: cgroup2fs
uname -r                         # want: 5.14 or newer
```

## The script

### Beat 0 — the hook: "Give me any script." (15s)

Ask a judge for a file, or drop one you wrote in front of them. **Drag it onto
the page.** It runs the instant it lands.

> "You don't pick from a list — you hand Cerberus a file you don't trust and it
> checks it live. It's running right now inside a throwaway RAM-only sandbox, as
> an unprivileged user, with every system call inspected."

This is the strongest opening because it's obviously not staged. Then use the
bundled samples below to show the specific behaviours cleanly.

### Beat 1 — "It doesn't cry wolf." (15s)

Drop **`payloads/benign_wordcount.py`** (or select it under *try a sample*).

> "This is ordinary code — it generates text, writes a file, counts words. Watch
> the feed: every syscall is inspected and allowed. Panel goes green: CLEAN. A
> security tool that blocks real work is useless, so we start here."

Point at **syscalls seen / allowed** counters and the green orb.

### Beat 2 — the headline. "Now something malicious." (30s)

Select **`exfil_credentials.py`**. Before you press Run:

> "This one pretends to be a health check. It really tries to read credential
> files and ship them out. It's brand new code — no signature, no prior
> knowledge."

Press **Run**.

> "There go the allowed calls — loading Python, reading its own script... and —"

The panel slams to **FROZEN**, red banner:

> "— the instant it touched `/etc/shadow`, Cerberus froze the entire process
> **in the kernel, before the read completed**. Look at the number: **detected
> and frozen in about 180 microseconds.** The credential never left the file,
> let alone the machine."

Let the **CONTAINED — detected & frozen in ~180 µs** banner sit on screen. This
is the moment.

### Beat 3 — "It reasons about *arguments*, not just calls." (20s)

Select **`exfil_network.py`**, change **Policy** to **`loopback`**, **Network**
to **host**, press **Run**.

> "This one skips files and goes straight for the network. Under a policy that
> allows *local* connections, Cerberus lets the socket open — harmless — and
> freezes the instant `connect()` names a public IP. It's not blocking the
> syscall, it's judging the destination: loopback fine, the internet not."

Banner: *attempted outbound connection to 93.184.216.34:443*.

### Beat 4 — "And the classic escapes don't even get to run." (15s)

Select **`escape_attempt.py`**, Policy back to **strict**, press **Run**.

> "Finally, the greatest hits of container escapes — `ptrace`, `mount`,
> `unshare`, loading an eBPF program, a kernel module. It tries to attach a
> debugger on line one, and that's as far as it gets: **VIOLATION**, the panel
> freezes, *attempted to attach a debugger (ptrace)*. The escape never runs, and
> it's flagged as malicious — not swept under the rug. The one tier below this,
> reserved for pure monitor-bypass tricks like io_uring, is refused straight in
> the kernel; everything else is judged on its arguments."

## If asked "how is this different from Falco / Firejail?"

> "Firejail isolates but is blind to what the code *does*. Falco sees it but only
> *reports*, after the fact, and you bolt on a separate response engine. Cerberus
> is isolation, detection, and automatic response in one loop — and it acts
> *before* the syscall runs, not after. The 180-microsecond number is that
> difference made concrete."

## If asked "is this production-grade?"

Be honest — it scores points:

> "No, and we don't claim it is. A namespace sandbox isn't gVisor. This is a
> focused, transparent implementation of the *detect-and-contain* idea you'd
> otherwise assemble from three tools — built to be understood and demoed. Every
> primitive is a real, mainline kernel feature: seccomp user-notification, cgroup
> v2 freezer, pidfd."

## Fallback if the live demo misbehaves

Run the CLI, which prints the same verdict and latency to the terminal:

```bash
sudo python3 -m cerberus.cli run -s payloads/exfil_credentials.py
```

Or show `docs/dashboard_contained.png` (a real captured run) and
`python3 tests/integration.py` output.

## Numbers to quote (measured, strict policy, this build)

- detect → freeze latency: **median ~155 µs**, p90 ~180 µs, across repeated runs
- benign control: **0 violations**, ~45 syscalls inspected, runs to completion
- 4 malicious payloads: **4/4 contained**
- dependencies added: **0** (Python stdlib + Linux kernel only)
