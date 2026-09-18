"""A dependency-free live dashboard.

Deliberately built on nothing but the Python standard library -- no FastAPI, no
websockets package, no build step. A hackathon judge clones the repo and runs
one command; asking them to `pip install` a web stack first is friction that
loses the room. The WebSocket server here is a minimal RFC 6455 implementation,
just enough to stream text frames one way (server -> browser), which is all a
live event feed needs.

The dashboard runs a real sandbox session on demand and streams every syscall
verdict, the sandbox state, and the detect->freeze latency to the browser as
they happen.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .events import EventBus
from .policy import PROFILES, get_profile
from .runner import Session
from .sandbox import SandboxSpec

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(os.path.dirname(HERE), "payloads")

# --- upload limits (the entry point is a public attack surface) --------------
MAX_UPLOAD_BYTES = 256 * 1024          # 256 KiB — a script, not a payload dump
RATE_WINDOW_S = 60.0                    # sliding window for rate limiting
RATE_MAX_RUNS = 20                      # at most this many runs per window per ip
# Interpreter chosen by extension. Anything not here is refused before it ever
# reaches the sandbox launcher.
INTERP_BY_EXT = {
    ".py": ["python3"],
    ".sh": ["bash"],
    ".js": ["node"],
    ".rb": ["ruby"],
    ".pl": ["perl"],
    ".lua": ["lua"],
}


def _ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_MAGIC).encode()).digest()).decode()


def _ws_frame(payload: bytes) -> bytes:
    """Encode a single unmasked text frame (server->client)."""
    header = bytearray([0x81])  # FIN + text opcode
    n = len(payload)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack("!H", n)
    else:
        header.append(127)
        header += struct.pack("!Q", n)
    return bytes(header) + payload


class DashboardState:
    """Shared between HTTP handlers and the WebSocket broadcaster."""

    def __init__(self):
        self.bus = EventBus(history=1000)
        self.clients: list[socket.socket] = []
        self.lock = threading.Lock()
        self.running = False
        self.session_summary: dict | None = None
        self._rate: dict[str, list[float]] = {}
        self._rate_lock = threading.Lock()
        self._vm = None
        self._vm_phase = "off"  # off | booting | live
        self._vm_port = 8799
        self.vm_image = "ubuntu"

    # --------------------------------------------------------- validation

    def rate_ok(self, ip: str) -> bool:
        """Sliding-window rate limit per client address."""
        now = time.time()
        with self._rate_lock:
            hits = [t for t in self._rate.get(ip, []) if now - t < RATE_WINDOW_S]
            if len(hits) >= RATE_MAX_RUNS:
                self._rate[ip] = hits
                return False
            hits.append(now)
            self._rate[ip] = hits
            return True

    @staticmethod
    def validate_upload(filename: str, data: bytes) -> tuple[bool, str, list[str] | None]:
        """Gate an upload before it reaches the sandbox launcher.

        Returns (ok, message, interpreter_argv_prefix). The checks here are the
        cheap, deterministic ones the spec calls for -- size, a sane filename,
        and a known extension. The sandbox itself is the real containment; this
        just keeps obvious junk and abuse off the launcher.
        """
        if not data:
            return False, "empty file", None
        if len(data) > MAX_UPLOAD_BYTES:
            return (False,
                    f"file is {len(data)} bytes; limit is {MAX_UPLOAD_BYTES} "
                    f"({MAX_UPLOAD_BYTES // 1024} KiB)", None)
        base = os.path.basename(filename or "").strip() or "upload"
        # No path traversal, no hidden control chars in the name we echo back.
        base = base.replace("\x00", "")
        if "/" in base or "\\" in base or base in (".", ".."):
            return False, "invalid filename", None
        ext = os.path.splitext(base)[1].lower()
        if ext not in INTERP_BY_EXT:
            return (False,
                    f"unsupported type '{ext or 'none'}'; allowed: "
                    + ", ".join(sorted(INTERP_BY_EXT)), None)
        # A submitted script must be text, not a binary blob.
        if b"\x00" in data[:4096]:
            return False, "looks like a binary, not a script", None
        return True, base, INTERP_BY_EXT[ext]

    def add_client(self, conn: socket.socket) -> None:
        with self.lock:
            self.clients.append(conn)

    def remove_client(self, conn: socket.socket) -> None:
        with self.lock:
            if conn in self.clients:
                self.clients.remove(conn)

    def broadcast(self, obj: dict) -> None:
        data = _ws_frame(json.dumps(obj).encode())
        with self.lock:
            dead = []
            for c in self.clients:
                try:
                    c.sendall(data)
                except OSError:
                    dead.append(c)
            for c in dead:
                if c in self.clients:
                    self.clients.remove(c)

    def list_payloads(self) -> list[dict]:
        out = []
        for fn in sorted(os.listdir(PAYLOAD_DIR)):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(PAYLOAD_DIR, fn)) as fh:
                doc = ""
                src = fh.read()
                if '"""' in src:
                    doc = src.split('"""', 2)[1].strip().split("\n")[0]
            out.append({"name": fn, "summary": doc})
        return out

    def run_sample(self, payload: str, policy_name: str, net: str, in_vm: bool = False) -> None:
        """Run one of the bundled demo payloads by name."""
        path = os.path.join(PAYLOAD_DIR, os.path.basename(payload))
        if not os.path.isfile(path):
            self.broadcast({"kind": "error", "summary": f"no such payload {payload}"})
            return
        with open(path, "rb") as fh:
            data = fh.read()
        self.run_session(os.path.basename(payload), data, ["python3"],
                         policy_name, net, source="sample", in_vm=in_vm)

    def run_session(self, filename: str, data: bytes, interp: list[str],
                    policy_name: str, net: str, source: str = "upload",
                    in_vm: bool = False) -> None:
        if self.running:
            self.broadcast({"kind": "error",
                            "summary": "a session is already running"})
            return
        self.running = True

        if in_vm:
            threading.Thread(
                target=self._worker_vm,
                args=(filename, interp, data, policy_name, net),
                daemon=True,
            ).start()
            return

        if os.geteuid() != 0:
            interp_cmd = interp[0] if interp else "python3"
            threading.Thread(
                target=self._worker_helper,
                args=(filename, interp_cmd, data, policy_name, net, source),
                daemon=True,
            ).start()
            return

        bus = EventBus(history=1000)
        q = bus.subscribe()
        spec = SandboxSpec(
            argv=interp + [f"/work/{filename}"],
            net=net,
            workdir_files={filename: data},
        )
        session = Session(spec, get_profile(policy_name), bus=bus)

        stop = threading.Event()

        def pump():
            while not stop.is_set():
                try:
                    ev = q.get(timeout=0.2)
                except queue.Empty:
                    continue
                self.broadcast({
                    "kind": ev.kind, "severity": ev.severity, "seq": ev.seq,
                    "ts": ev.ts, "syscall": ev.syscall, "pid": ev.pid,
                    "rule": ev.rule, "summary": ev.summary, "action": ev.action,
                    "detail": ev.detail, "latency_us": ev.latency_us,
                })

        pump_thread = threading.Thread(target=pump, daemon=True)
        pump_thread.start()

        self.broadcast({"kind": "run_start",
                        "summary": f"launching {filename} ({source})",
                        "detail": {"policy": policy_name, "net": net,
                                   "filename": filename, "source": source,
                                   "bytes": len(data), "uid": "65534 (unprivileged)"}})
        try:
            result = session.run(timeout=25.0)
            self.session_summary = {
                "verdict": result.verdict, "exit_code": result.exit_code,
                "frozen": result.frozen, "first_violation": result.first_violation,
                "stats": result.stats, "duration_s": round(result.duration_s, 3),
            }
            time.sleep(0.3)  # let the pump flush the tail
            self.broadcast({"kind": "run_end", "severity":
                            "violation" if result.verdict == "contained" else "info",
                            "summary": f"session {result.verdict}",
                            "detail": self.session_summary})
        finally:
            stop.set()
            self.running = False

    def _worker_helper(self, name: str, interp: str, data: bytes, policy_name: str, net: str, source: str = "upload") -> None:
        """Spawn the elevated helper (via pkexec or sudo) to execute with root privileges."""
        import subprocess, shutil
        pybin = sys.executable or "python3"
        helper = [pybin, "-B", "-m", "cerberus.helper", "--policy", policy_name,
                  "--net", net, "--name", name, "--interp", interp,
                  "--b64"]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(HERE) + os.pathsep + env.get("PYTHONPATH", "")

        if os.geteuid() == 0:
            cmd = helper
        elif shutil.which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            cmd = ["pkexec", "env", f"PYTHONPATH={env['PYTHONPATH']}", *helper]
        elif shutil.which("sudo"):
            cmd = ["sudo", "-E", *helper]
        else:
            self.broadcast({"kind": "error", "summary": "need root: no pkexec or sudo found"})
            self.broadcast({"kind": "run_end", "detail": {"verdict": "error"}})
            self.running = False
            return

        self.broadcast({"kind": "run_start",
                        "summary": f"launching {name} ({source})",
                        "detail": {"policy": policy_name, "net": net,
                                   "filename": name, "source": source,
                                   "bytes": len(data), "uid": "65534 (unprivileged)"}})

        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=env)
        except OSError as e:
            self.broadcast({"kind": "error", "summary": f"failed to launch helper: {e}"})
            self.broadcast({"kind": "run_end", "detail": {"verdict": "error"}})
            self.running = False
            return

        proc.stdin.write(base64.b64encode(data))
        proc.stdin.close()

        first_violation = None
        for line in proc.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("kind") == "violation" and not first_violation:
                first_violation = ev
            if ev.get("kind") == "result":
                self.session_summary = {
                    "verdict": ev.get("verdict"),
                    "exit_code": ev.get("exit_code"),
                    "frozen": ev.get("frozen"),
                    "first_violation": ev.get("first_violation"),
                    "stats": ev.get("stats", {}),
                    "duration_s": ev.get("duration_s", 0.0),
                }
                self.broadcast({
                    "kind": "run_end",
                    "severity": "violation" if ev.get("verdict") == "contained" else "info",
                    "summary": f"session {ev.get('verdict')}",
                    "detail": self.session_summary
                })
            else:
                self.broadcast(ev)

        err = proc.stderr.read().decode("utf-8", "replace")
        proc.wait()
        if proc.returncode != 0 and not self.session_summary:
            err_msg = err.strip().split("\n")[-1] if err.strip() else f"helper exited with code {proc.returncode}"
            self.broadcast({"kind": "error", "summary": err_msg})
            self.broadcast({"kind": "run_end", "detail": {"verdict": "error"}})

        self.running = False

    def _worker_vm(self, name: str, interp: list[str], data: bytes, policy_name: str, net: str) -> None:
        """Boot disposable VM (once) and stream execution events back to browser."""
        from . import vm as vmmod
        from . import wsclient
        host, port = "127.0.0.1", self._vm_port

        def status(msg: str):
            self.broadcast({"kind": "vm_status", "summary": msg})

        self.broadcast({"kind": "run_start",
                        "summary": f"launching {name} (in disposable VM)",
                        "detail": {"policy": policy_name, "net": net,
                                   "filename": name, "source": "vm",
                                   "bytes": len(data), "uid": "65534 (VM isolated)"}})
        try:
            if self._vm is None or not self._vm.is_running():
                self._vm_phase = "booting"
                self.broadcast({"kind": "vm_phase", "phase": "booting"})
                status("preparing disposable VM…")
                self._vm = vmmod.spawn_vm(port=port, image=self.vm_image, progress=status)
                self._start_console_reader(self._vm)
                status("waiting for the VM to finish booting…")
                if not wsclient.wait_up(host, port, timeout=240):
                    self._vm_phase = "off"
                    self.broadcast({"kind": "vm_phase", "phase": "off"})
                    self.broadcast({"kind": "error", "summary": "VM booted but dashboard never came up"})
                    self.broadcast({"kind": "run_end", "detail": {"verdict": "error"}})
                    return
                self._vm_phase = "live"
                self.broadcast({"kind": "vm_phase", "phase": "live"})
                status("VM up — sandbox runs two boundaries deep")
            else:
                self._vm_phase = "live"
                self.broadcast({"kind": "vm_phase", "phase": "live"})

            events = wsclient.WSEvents(host, port)
            events.connect()
            wsclient.upload(host, port, name, data, policy=policy_name, net=net)
            for ev in events.stream():
                self.broadcast(ev)
        except Exception as exc:
            self.broadcast({"kind": "error", "summary": f"VM run failed: {exc}"})
            self.broadcast({"kind": "run_end", "detail": {"verdict": "error"}})
        finally:
            self.running = False

    def _start_console_reader(self, vm) -> None:
        def reader():
            try:
                for line in vm.proc.stdout:
                    line = line.rstrip("\n")
                    if line.strip():
                        self.broadcast({"kind": "vm_console", "summary": line})
            except Exception:
                pass
        threading.Thread(target=reader, daemon=True).start()

    def stop_vm(self) -> None:
        vm = self._vm
        if vm is not None and vm.is_running():
            try:
                vm.stop()
            except Exception:
                pass
        self._vm = None
        self._vm_phase = "off"


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body: bytes, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/" or self.path == "/index.html":
                with open(os.path.join(HERE, "..", "static", "index.html"), "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            elif self.path == "/api/status":
                self._send(200, json.dumps({
                    "running": state.running,
                    "vm_phase": state._vm_phase,
                    "vm_port": state._vm_port,
                }).encode())
            elif self.path == "/api/payloads":
                self._send(200, json.dumps({
                    "payloads": state.list_payloads(),
                    "policies": list(PROFILES),
                }).encode())
            elif self.path == "/ws":
                self._handle_ws()
            else:
                self._send(404, b'{"error":"not found"}')

        def _client_ip(self) -> str:
            return self.client_address[0] if self.client_address else "?"

        def _read_body(self, cap: int) -> bytes | None:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > cap:
                return None  # refuse before reading it into memory
            return self.rfile.read(n) if n else b""

        def do_POST(self):
            if self.path == "/api/run":
                # Bundled demo payloads, selected by name.
                body = json.loads(self._read_body(64 * 1024) or b"{}")
                payload = body.get("payload", "exfil_credentials.py")
                policy = body.get("policy", "strict")
                net = body.get("net", "none")
                in_vm = bool(body.get("vm", False))
                if state.running:
                    self._send(409, b'{"error":"a session is already running"}')
                    return
                threading.Thread(
                    target=state.run_sample, args=(payload, policy, net, in_vm),
                    daemon=True,
                ).start()
                self._send(200, b'{"status":"started"}')

            elif self.path.startswith("/api/upload"):
                self._handle_upload()

            else:
                self._send(404, b'{"error":"not found"}')

        def _handle_upload(self):
            # Query carries policy/net; body is the raw file bytes. Filename
            # comes from the X-Filename header (browsers can't set it on a raw
            # PUT/POST body otherwise). This avoids a multipart parser while
            # keeping the endpoint simple and auditable.
            from urllib.parse import urlparse, parse_qs

            ip = self._client_ip()
            if not state.rate_ok(ip):
                self._send(429, json.dumps({
                    "error": f"rate limit: max {RATE_MAX_RUNS} runs per "
                             f"{int(RATE_WINDOW_S)}s"}).encode())
                return
            if state.running:
                self._send(409, b'{"error":"a session is already running"}')
                return

            # Read at most one byte over the cap so we can distinguish "exactly
            # at limit" from "too big" and reject cleanly.
            data = self._read_body(MAX_UPLOAD_BYTES + 1)
            if data is None:
                self._send(413, json.dumps({
                    "error": f"file too large; limit is "
                             f"{MAX_UPLOAD_BYTES // 1024} KiB"}).encode())
                return

            q = parse_qs(urlparse(self.path).query)
            policy = (q.get("policy") or ["strict"])[0]
            net = (q.get("net") or ["none"])[0]
            in_vm = (q.get("vm") or ["0"])[0] in ("1", "true", "True")
            filename = self.headers.get("X-Filename", "upload.py")

            ok, msg, interp = state.validate_upload(filename, data)
            if not ok:
                self._send(400, json.dumps({"error": msg}).encode())
                return

            threading.Thread(
                target=state.run_session,
                args=(msg, data, interp, policy, net, "upload", in_vm),
                daemon=True,
            ).start()
            self._send(200, json.dumps({"status": "started", "filename": msg,
                                        "bytes": len(data)}).encode())

        def _handle_ws(self):
            key = self.headers.get("Sec-WebSocket-Key")
            if not key:
                self._send(400, b'{"error":"not a websocket handshake"}')
                return
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", _ws_accept(key))
            self.end_headers()
            conn = self.connection
            state.add_client(conn)
            # Replay recent history so a client that connects mid-session isn't
            # staring at a blank feed.
            try:
                for ev in state.bus.history()[-50:]:
                    conn.sendall(_ws_frame(json.dumps({
                        "kind": ev.kind, "severity": ev.severity,
                        "summary": ev.summary, "syscall": ev.syscall,
                        "rule": ev.rule, "latency_us": ev.latency_us,
                    }).encode()))
            except OSError:
                pass
            # Hold the connection open; we only push, so just park until the
            # client disconnects (read returns empty / errors).
            try:
                conn.settimeout(None)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
            except OSError:
                pass
            finally:
                state.remove_client(conn)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    state = DashboardState()
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"Cerberus dashboard on http://{host}:{port}")
    print("  (run a payload from the browser; every syscall verdict streams live)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        state.stop_vm()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    serve(args.host, args.port)
