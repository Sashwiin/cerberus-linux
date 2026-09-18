"""Cerberus native desktop GUI — Tkinter, no web anything.

A real application window built from native widgets. It runs as an ordinary
user and shells out to the privileged `cerberus.helper` (via pkexec / sudo) to
do the sandboxing, reading that helper's JSON-line event stream and painting it
into the window live. There is no browser, no HTML, no local server, and no
socket — just a pipe between the GUI and a root worker.

Tkinter ships with CPython (`python3-tk` on Debian/Ubuntu, `python3-tkinter` on
Fedora), so this needs no third-party GUI toolkit.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, ttk

# ---- palette (mirrors the design language of the project) -------------------
BG = "#0a0e14"
PANEL = "#111722"
PANEL2 = "#0d131c"
LINE = "#1e2836"
INK = "#e6edf3"
DIM = "#8b98a9"
FAINT = "#5a6675"
INFO = "#39a0ed"
OK = "#3fb950"
WARN = "#d29922"
BAD = "#f85149"
ACCENT = "#7c5cff"
MONO = ("DejaVu Sans Mono", 10)
MONO_S = ("DejaVu Sans Mono", 9)
SANS = ("DejaVu Sans", 10)
SANS_B = ("DejaVu Sans", 11, "bold")
BIG = ("DejaVu Sans", 20, "bold")
HUGE = ("DejaVu Sans Mono", 26, "bold")

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(os.path.dirname(HERE), "payloads")
INTERP_BY_EXT = {".py": "python3", ".sh": "bash", ".js": "node",
                 ".rb": "ruby", ".pl": "perl", ".lua": "lua"}
MAX_BYTES = 256 * 1024


def _find_python() -> str:
    return sys.executable or "python3"


class CerberusGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.running = False
        self.seen = self.allowed = self.watched = self.viol = 0
        self.first_violation_shown = False
        # disposable-VM mode state
        self.run_in_vm = tk.BooleanVar(value=False)
        self._vm = None
        self._vm_port = 8799
        self.vm_image = "ubuntu"

        root.title("Cerberus")
        root.configure(bg=BG)
        root.geometry("1080x720")
        root.minsize(880, 560)

        self._build_header()
        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)
        self._build_main(body)

        self._set_state("idle", "idle", "open a script to check it")
        self.root.after(60, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        vm = self._vm
        if vm is not None and vm.is_running():
            try:
                vm.stop()  # terminate QEMU and delete the disposable overlay
            except Exception:
                pass
        self.root.destroy()

    # ------------------------------------------------------------- layout

    def _build_header(self) -> None:
        h = tk.Frame(self.root, bg=PANEL2, height=64)
        h.pack(fill="x")
        h.pack_propagate(False)
        # a small drawn mark
        c = tk.Canvas(h, width=40, height=40, bg=PANEL2, highlightthickness=0)
        c.place(x=18, y=12)
        c.create_oval(4, 4, 36, 36, outline=ACCENT, width=2)
        c.create_arc(10, 12, 30, 34, start=0, extent=180, style="arc",
                     outline=ACCENT, width=2)
        for cx in (14, 20, 26):
            c.create_oval(cx - 2, 15, cx + 2, 19, fill=BAD, outline="")
        tk.Label(h, text="Cerberus", bg=PANEL2, fg=INK,
                 font=("DejaVu Sans", 15, "bold")).place(x=70, y=10)
        tk.Label(h, text="ephemeral sandbox · real-time syscall defense",
                 bg=PANEL2, fg=DIM, font=("DejaVu Sans", 9)).place(x=70, y=36)

    def _build_sidebar(self, parent: tk.Frame) -> None:
        s = tk.Frame(parent, bg=PANEL2, width=290)
        s.pack(side="left", fill="y")
        s.pack_propagate(False)

        def label(txt):
            tk.Label(s, text=txt, bg=PANEL2, fg=FAINT,
                     font=("DejaVu Sans", 8, "bold")).pack(anchor="w", padx=18, pady=(16, 4))

        label("CHECK A FILE")
        self.drop = tk.Frame(s, bg=PANEL, highlightbackground=LINE,
                             highlightthickness=2, height=120)
        self.drop.pack(fill="x", padx=18)
        self.drop.pack_propagate(False)
        tk.Label(self.drop, text="⬆", bg=PANEL, fg=ACCENT,
                 font=("DejaVu Sans", 22)).pack(pady=(18, 0))
        tk.Label(self.drop, text="Open a script…", bg=PANEL, fg=INK,
                 font=SANS_B).pack()
        tk.Label(self.drop, text=".py .sh .js .rb .pl .lua · max 256 KiB",
                 bg=PANEL, fg=FAINT, font=("DejaVu Sans", 8)).pack(pady=(4, 0))
        for w in (self.drop, *self.drop.winfo_children()):
            w.bind("<Button-1>", lambda e: self.pick_file())
            w.bind("<Enter>", lambda e: self.drop.config(highlightbackground=ACCENT))
            w.bind("<Leave>", lambda e: self.drop.config(highlightbackground=LINE))

        label("POLICY PROFILE")
        self.policy = tk.StringVar(value="strict")
        self._combo(s, self.policy, ["strict", "loopback", "observe", "paranoid"])

        label("NETWORK")
        self.net = tk.StringVar(value="none")
        self._combo(s, self.net, ["none", "host"])

        # disposable-VM toggle: run two boundaries deep, still in this window
        vmf = tk.Frame(s, bg=PANEL2)
        vmf.pack(fill="x", padx=18, pady=(16, 0))
        cb = tk.Checkbutton(
            vmf, text=" Run in disposable VM", variable=self.run_in_vm,
            bg=PANEL2, fg=INK, selectcolor=PANEL, activebackground=PANEL2,
            activeforeground=INK, font=SANS, bd=0, highlightthickness=0,
            anchor="w")
        cb.pack(fill="x")
        tk.Label(vmf, text="kernel-escape isolation · needs qemu · slower boot",
                 bg=PANEL2, fg=FAINT, font=("DejaVu Sans", 8),
                 wraplength=250, justify="left").pack(anchor="w")

        label("OR TRY A BUNDLED SAMPLE")
        self.sample = tk.StringVar()
        samples = [f for f in sorted(os.listdir(PAYLOAD_DIR))
                   if f.endswith(".py")] if os.path.isdir(PAYLOAD_DIR) else []
        if samples:
            self.sample.set(samples[0])
            self._combo(s, self.sample, samples)
        tk.Button(s, text="▶  Run sample", command=self.run_sample,
                  bg=PANEL, fg=DIM, activebackground=LINE, activeforeground=INK,
                  relief="flat", font=SANS, bd=0, highlightthickness=1,
                  highlightbackground=LINE).pack(fill="x", padx=18, pady=(10, 0))

        # legend
        leg = tk.Frame(s, bg=PANEL2)
        leg.pack(anchor="w", padx=18, pady=(22, 0))
        for col, txt in ((INFO, "allowed"), (WARN, "watched"), (BAD, "violation")):
            row = tk.Frame(leg, bg=PANEL2)
            row.pack(anchor="w")
            tk.Canvas(row, width=10, height=10, bg=PANEL2,
                      highlightthickness=0).pack(side="left")
            tk.Label(row, text="  " + txt, bg=PANEL2, fg=DIM,
                     font=("DejaVu Sans", 8)).pack(side="left")
            row.winfo_children()[0].create_oval(2, 2, 9, 9, fill=col, outline="")

    def _combo(self, parent, var, values):
        f = tk.Frame(parent, bg=PANEL2)
        f.pack(fill="x", padx=18)
        om = tk.OptionMenu(f, var, *values)
        om.config(bg=PANEL, fg=INK, activebackground=LINE, activeforeground=INK,
                  relief="flat", font=SANS, highlightthickness=1,
                  highlightbackground=LINE, anchor="w")
        om["menu"].config(bg=PANEL, fg=INK, activebackground=ACCENT)
        om.pack(fill="x")

    def _build_main(self, parent: tk.Frame) -> None:
        m = tk.Frame(parent, bg=BG)
        m.pack(side="left", fill="both", expand=True, padx=16, pady=16)

        # state pill
        self.state_frame = tk.Frame(m, bg=PANEL, highlightbackground=LINE,
                                    highlightthickness=1)
        self.state_frame.pack(fill="x")
        self.orb = tk.Canvas(self.state_frame, width=44, height=44, bg=PANEL,
                             highlightthickness=0)
        self.orb.pack(side="left", padx=16, pady=14)
        self._orb_id = self.orb.create_oval(6, 6, 40, 40, fill="#2a3646", outline="")
        tf = tk.Frame(self.state_frame, bg=PANEL)
        tf.pack(side="left", pady=14)
        self.state_big = tk.Label(tf, text="idle", bg=PANEL, fg=INK, font=BIG)
        self.state_big.pack(anchor="w")
        self.state_sub = tk.Label(tf, text="", bg=PANEL, fg=DIM, font=SANS)
        self.state_sub.pack(anchor="w")

        # violation banner (hidden until a violation)
        self.banner = tk.Frame(m, bg="#1a0e12", highlightbackground=BAD,
                               highlightthickness=1)
        self.banner_title = tk.Label(self.banner, text="", bg="#1a0e12", fg=BAD,
                                     font=("DejaVu Sans", 12, "bold"))
        self.banner_title.pack(anchor="w", padx=16, pady=(12, 2))
        self.banner_desc = tk.Label(self.banner, text="", bg="#1a0e12", fg=INK,
                                    font=SANS)
        self.banner_desc.pack(anchor="w", padx=16)
        self.banner_lat = tk.Label(self.banner, text="", bg="#1a0e12", fg="#ffffff",
                                   font=HUGE)
        self.banner_lat.pack(anchor="w", padx=16, pady=(2, 12))

        # metrics
        mt = tk.Frame(m, bg=BG)
        mt.pack(fill="x", pady=(12, 0))
        self.metric_vars = {}
        for key, txt, col in (("seen", "syscalls seen", INK),
                              ("allowed", "allowed", OK),
                              ("watched", "watched", WARN),
                              ("viol", "violations", BAD)):
            cell = tk.Frame(mt, bg=PANEL, highlightbackground=LINE,
                            highlightthickness=1)
            cell.pack(side="left", expand=True, fill="both", padx=(0, 8))
            v = tk.Label(cell, text="0", bg=PANEL, fg=col, font=HUGE)
            v.pack(anchor="w", padx=14, pady=(10, 0))
            tk.Label(cell, text=txt, bg=PANEL, fg=FAINT,
                     font=("DejaVu Sans", 8, "bold")).pack(anchor="w", padx=14, pady=(0, 10))
            self.metric_vars[key] = v

        # feed
        fh = tk.Frame(m, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        fh.pack(fill="both", expand=True, pady=(12, 0))
        top = tk.Frame(fh, bg=PANEL)
        top.pack(fill="x")
        tk.Label(top, text="live syscall feed", bg=PANEL, fg=DIM,
                 font=("DejaVu Sans", 9)).pack(side="left", padx=12, pady=8)
        self.meta = tk.Label(top, text="", bg=PANEL, fg=FAINT,
                             font=("DejaVu Sans", 8))
        self.meta.pack(side="right", padx=12)
        self.feed = tk.Text(fh, bg=PANEL, fg=INK, font=MONO_S, bd=0,
                            highlightthickness=0, wrap="none", state="disabled",
                            padx=10, pady=6)
        self.feed.pack(fill="both", expand=True)
        self.feed.tag_config("info", foreground=INFO)
        self.feed.tag_config("suspicious", foreground=WARN)
        self.feed.tag_config("violation", foreground=BAD)
        self.feed.tag_config("dim", foreground=FAINT)
        self.feed.tag_config("ink", foreground=INK)

    # ------------------------------------------------------------- actions

    def pick_file(self) -> None:
        if self.running:
            return
        path = filedialog.askopenfilename(
            title="Choose a script to check",
            filetypes=[("Scripts", "*.py *.sh *.js *.rb *.pl *.lua"),
                       ("All files", "*.*")])
        if path:
            self.run_path(path)

    def run_sample(self) -> None:
        if self.running or not self.sample.get():
            return
        self.run_path(os.path.join(PAYLOAD_DIR, self.sample.get()))

    def run_path(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            self._show_error(f"cannot read file: {e}")
            return
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        if ext not in INTERP_BY_EXT:
            self._show_error(f"unsupported type '{ext or 'none'}'")
            return
        if len(data) > MAX_BYTES:
            self._show_error(f"file too large ({len(data)//1024} KiB > 256 KiB)")
            return
        if b"\x00" in data[:4096]:
            self._show_error("looks like a binary, not a script")
            return
        self._start_run(name, INTERP_BY_EXT[ext], data)

    def _start_run(self, name: str, interp: str, data: bytes) -> None:
        self._reset_run()
        self.running = True
        in_vm = bool(self.run_in_vm.get())
        where = "in disposable VM" if in_vm else "under monitor"
        self._set_state("running", "running", f"{name} — executing {where}")
        self.meta.config(text=f"{name} · {len(data)} bytes · uid 65534"
                         + (" · VM" if in_vm else ""))
        target = self._worker_vm if in_vm else self._worker
        threading.Thread(target=target, args=(name, interp, data),
                         daemon=True).start()

    def _worker_vm(self, name: str, interp: str, data: bytes) -> None:
        """Run inside a disposable VM: boot it (once), then stream events over
        the forwarded port into the same native widgets. No browser involved."""
        from . import vm as vmmod
        from . import wsclient
        host, port = "127.0.0.1", self._vm_port

        try:
            if self._vm is None or not self._vm.is_running():
                self.q.put({"kind": "lifecycle", "severity": "info", "ts": None,
                            "summary": "booting disposable VM (first run downloads "
                                       "a small image; ~20–60s)…"})
                self._vm = vmmod.spawn_vm(port=port, image=self.vm_image)
                if not wsclient.wait_up(host, port, timeout=180):
                    self.q.put({"kind": "error",
                                "summary": "VM booted but the dashboard never came "
                                           "up; check the VM console"})
                    self.q.put({"kind": "run_end", "detail": {"verdict": "error"}})
                    return
                self.q.put({"kind": "lifecycle", "severity": "info", "ts": None,
                            "summary": "VM up — sandbox now runs two boundaries deep"})

            # open the event stream first so we don't miss early events
            events = wsclient.WSEvents(host, port)
            events.connect()
            wsclient.upload(host, port, name, data,
                            policy=self.policy.get(), net=self.net.get())
            for ev in events:
                self.q.put(ev)
                if ev.get("kind") == "run_end":
                    break
            events.close()
        except Exception as exc:
            self.q.put({"kind": "error", "summary": f"VM run failed: {exc}"})
            self.q.put({"kind": "run_end", "detail": {"verdict": "error"}})

    def _worker(self, name: str, interp: str, data: bytes) -> None:
        """Spawn the elevated helper and read its JSON event stream."""
        pybin = _find_python()
        helper = [pybin, "-m", "cerberus.helper", "--policy", self.policy.get(),
                  "--net", self.net.get(), "--name", name, "--interp", interp,
                  "--b64"]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(HERE) + os.pathsep + env.get("PYTHONPATH", "")

        if os.geteuid() == 0:
            cmd = helper
        elif _which("pkexec") and (os.environ.get("DISPLAY") or
                                   os.environ.get("WAYLAND_DISPLAY")):
            cmd = ["pkexec", "env", f"PYTHONPATH={env['PYTHONPATH']}", *helper]
        elif _which("sudo"):
            cmd = ["sudo", "-E", *helper]
        else:
            self.q.put({"kind": "error", "summary": "need root: no pkexec or sudo"})
            self.q.put({"kind": "result", "verdict": "error"})
            return

        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=env)
        except OSError as e:
            self.q.put({"kind": "error", "summary": f"failed to launch helper: {e}"})
            self.q.put({"kind": "result", "verdict": "error"})
            return

        proc.stdin.write(base64.b64encode(data))
        proc.stdin.close()
        for line in proc.stdout:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                pass
        err = proc.stderr.read().decode("utf-8", "replace")
        proc.wait()
        if proc.returncode != 0 and not self.first_violation_shown:
            self.q.put({"kind": "error",
                        "summary": f"helper exited {proc.returncode}: "
                                   f"{err.strip()[:200] or 'authorization cancelled?'}"})
            self.q.put({"kind": "result", "verdict": "error"})

    # ------------------------------------------------------ event pump (Tk thread)

    def _drain_queue(self) -> None:
        try:
            while True:
                ev = self.q.get_nowait()
                self._handle(ev)
        except queue.Empty:
            pass
        self.root.after(60, self._drain_queue)

    def _handle(self, ev: dict) -> None:
        kind = ev.get("kind")
        if kind == "syscall":
            self.seen += 1
            if ev.get("severity") == "suspicious":
                self.watched += 1
            else:
                self.allowed += 1
            self._metrics()
            self._append_feed(ev)
        elif kind == "violation":
            self.seen += 1
            self.viol += 1
            self._metrics()
            self._append_feed(ev)
            self._show_violation(ev)
            self._set_state("frozen", "FROZEN", "process group stopped mid-syscall")
        elif kind in ("lifecycle", "state"):
            self._append_feed(ev)
        elif kind == "run_start":
            # emitted by the in-VM web server; the local helper doesn't send it
            pass
        elif kind == "error":
            self._show_error(ev.get("summary", "error"))
        elif kind in ("result", "run_end"):
            self._finish(ev)

    def _finish(self, ev: dict) -> None:
        self.running = False
        # local helper puts the verdict/stats at the top level ("result");
        # the in-VM web server nests them under "detail" ("run_end").
        src = ev.get("detail") if ev.get("kind") == "run_end" else ev
        src = src or ev
        v = src.get("verdict")
        stats = src.get("stats") or {}
        if v == "contained":
            self._set_state("frozen", "CONTAINED", "payload stopped before it could act")
        elif v == "clean":
            self._set_state("clean", "CLEAN", "payload finished — no violations")
        else:
            self._set_state("error", "ERROR", ev.get("summary", "run failed"))
        meta = f"{stats.get('notifications', 0)} syscalls inspected"
        if stats.get("decide_us_p50") is not None:
            meta += f" · median decide {stats['decide_us_p50']}µs"
        self.meta.config(text=meta)

    # ------------------------------------------------------------- painting

    def _set_state(self, cls: str, big: str, sub: str) -> None:
        colors = {"idle": "#2a3646", "running": INFO, "frozen": BAD,
                  "clean": OK, "error": BAD}
        border = {"idle": LINE, "running": INFO, "frozen": BAD, "clean": OK,
                  "error": BAD}
        self.orb.itemconfig(self._orb_id, fill=colors.get(cls, "#2a3646"))
        self.state_frame.config(highlightbackground=border.get(cls, LINE))
        self.state_big.config(text=big, fg=BAD if cls in ("frozen", "error")
                              else (OK if cls == "clean" else INK))
        self.state_sub.config(text=sub)

    def _metrics(self) -> None:
        self.metric_vars["seen"].config(text=str(self.seen))
        self.metric_vars["allowed"].config(text=str(self.allowed))
        self.metric_vars["watched"].config(text=str(self.watched))
        self.metric_vars["viol"].config(text=str(self.viol))

    def _append_feed(self, ev: dict) -> None:
        sev = ev.get("severity", "info")
        if ev.get("kind") == "syscall" and sev == "info":
            # keep the native feed readable; show watched/violations and lifecycle
            if self.seen % 1 != 0:
                return
        ts = ""
        if ev.get("ts"):
            ts = datetime.fromtimestamp(ev["ts"]).strftime("%H:%M:%S.%f")[:-3]
        sc = ev.get("syscall") or "·"
        lat = f"  {ev['latency_us']:.0f}µs" if ev.get("latency_us") is not None else ""
        self.feed.config(state="normal")
        self.feed.insert("end", f"{ts:<13} ", "dim")
        self.feed.insert("end", f"{sc:<14} ", sev)
        self.feed.insert("end", f"{ev.get('summary','')}", "ink")
        self.feed.insert("end", f"{lat}\n", "dim")
        # cap lines
        if int(self.feed.index("end-1c").split(".")[0]) > 800:
            self.feed.delete("1.0", "200.0")
        self.feed.see("end")
        self.feed.config(state="disabled")

    def _show_violation(self, ev: dict) -> None:
        if self.first_violation_shown:
            return
        self.first_violation_shown = True
        self.banner.pack(fill="x", pady=(12, 0), after=self.state_frame)
        self.banner_title.config(text=f"⛔ CONTAINED — {ev.get('rule','')}")
        self.banner_desc.config(text=ev.get("summary", ""))
        frozen = (ev.get("detail") or {}).get("frozen", True)
        who = "detected & frozen in" if frozen else "detected & denied in"
        lat = ev.get("latency_us")
        self.banner_lat.config(
            text=f"{lat:.0f} µs" if lat is not None else "—")
        self.banner_desc.config(text=f"{ev.get('summary','')}    ({who})")

    def _reset_run(self) -> None:
        self.seen = self.allowed = self.watched = self.viol = 0
        self.first_violation_shown = False
        self._metrics()
        self.banner.pack_forget()
        self.feed.config(state="normal")
        self.feed.delete("1.0", "end")
        self.feed.config(state="disabled")
        self.meta.config(text="")

    def _show_error(self, msg: str) -> None:
        self.running = False
        self.banner.pack(fill="x", pady=(12, 0), after=self.state_frame)
        self.banner.config(highlightbackground=WARN)
        self.banner_title.config(text="⚠ could not run", fg=WARN)
        self.banner_desc.config(text=msg)
        self.banner_lat.config(text="")
        self._set_state("idle", "idle", "ready")


def _which(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def main() -> int:
    root = tk.Tk()
    # dark title area where the WM honours it
    try:
        root.tk.call("tk", "scaling", 1.2)
    except tk.TclError:
        pass
    CerberusGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
