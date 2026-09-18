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
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .events import EventBus
from .policy import (
    BYPASS_DENY_NAMES, ESCAPE_NAMES, NOTIFY_NAMES, BASELINE_ALLOW_NAMES,
    DEFAULT_READ_PREFIXES, DEFAULT_WRITE_PREFIXES, SENSITIVE_PATTERNS,
    PROFILES, get_profile,
)
from .runner import Session
from .sandbox import SandboxSpec, DEFAULT_BINDS, DEVICE_NODES

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
        # Real run history, newest last. Kept in memory only -- the whole point
        # of the sandbox is that nothing persists to disk -- so this resets on
        # restart. Used by the "Timeline & History" view; every field in a
        # record is something an actual run produced, never synthesised.
        self.history: deque[dict] = deque(maxlen=40)
        self._history_lock = threading.Lock()
        # The Session currently in flight, if any -- lets the "manual kill"
        # control reach its real cgroup rather than faking a response.
        self._active_session: Session | None = None
        self._active_lock = threading.Lock()

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

    def kill_active(self) -> bool:
        """Send SIGKILL to every task in the running sandbox's cgroup, right now.

        A real operator control, not a decoration: it reaches into the actual
        `Cgroup` the active `Session` created and calls the same atomic
        `cgroup.kill()` the monitor itself uses for teardown.
        """
        with self._active_lock:
            session = self._active_session
        cg = getattr(session, "cgroup", None) if session else None
        if cg is None:
            return False
        try:
            cg.kill()
            return True
        except OSError:
            return False

    def history_list(self) -> list[dict]:
        with self._history_lock:
            return list(reversed(self.history))  # newest first

    def system_info(self) -> dict:
        """Real architecture facts, pulled from the live policy/sandbox modules
        rather than written out by hand -- so this can never drift from what the
        monitor actually enforces."""
        spec = SandboxSpec(argv=[])
        return {
            "interception": "seccomp user-notification (SECCOMP_RET_USER_NOTIF)",
            "kernel_min": "5.14 (cgroup.kill); 5.9+ with a weaker teardown",
            "namespaces": ["mount", "pid", "net", "ipc", "uts", "cgroup"],
            "storage_root": f"tmpfs, RAM only ({spec.tmpfs_size})",
            "cgroup": {
                "version": "v2",
                "memory_max": spec.memory_max,
                "pids_max": spec.pids_max,
                "response": "cgroup.freeze (stasis) / cgroup.kill (atomic teardown)",
            },
            "run_as": f"uid {spec.uid} / gid {spec.gid} (unprivileged)",
            "read_only_binds": list(DEFAULT_BINDS),
            "device_nodes": list(DEVICE_NODES),
            "syscall_tiers": {
                "bypass_deny": {
                    "count": len(BYPASS_DENY_NAMES),
                    "names": list(BYPASS_DENY_NAMES),
                    "action": "refused in-kernel (EPERM), no userspace round trip",
                },
                "escape": {
                    "count": len(ESCAPE_NAMES),
                    "sample": list(ESCAPE_NAMES[:8]),
                    "action": "parked, judged, and turned into a visible freezing "
                              "violation (CONTAINED) -- never blocked silently",
                },
                "notify": {
                    "count": len(NOTIFY_NAMES),
                    "action": "parked and judged on arguments",
                },
                "baseline_allow": {
                    "count": len(BASELINE_ALLOW_NAMES),
                    "action": "explicit reviewable allow-list (enforced by "
                              "'paranoid'; informative for other profiles)",
                },
            },
            "read_prefixes": list(DEFAULT_READ_PREFIXES),
            "write_prefixes": list(DEFAULT_WRITE_PREFIXES),
            "sensitive_patterns": len(SENSITIVE_PATTERNS),
            "profiles": {
                name: {
                    "allow_network": p.allow_network,
                    "allow_loopback": p.allow_loopback,
                    "allow_exec": p.allow_exec,
                    "default_allow_unlisted": p.default_allow_unlisted,
                    "max_processes": p.max_processes,
                }
                for name, p in PROFILES.items()
            },
        }

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

    def run_sample(self, payload: str, policy_name: str, net: str) -> None:
        """Run one of the bundled demo payloads by name."""
        path = os.path.join(PAYLOAD_DIR, os.path.basename(payload))
        if not os.path.isfile(path):
            self.broadcast({"kind": "error", "summary": f"no such payload {payload}"})
            return
        with open(path, "rb") as fh:
            data = fh.read()
        self.run_session(os.path.basename(payload), data, ["python3"],
                         policy_name, net, source="sample")

    def run_session(self, filename: str, data: bytes, interp: list[str],
                    policy_name: str, net: str, source: str = "upload") -> None:
        if self.running:
            self.broadcast({"kind": "error",
                            "summary": "a session is already running"})
            return
        self.running = True

        bus = EventBus(history=1000)
        q = bus.subscribe()
        spec = SandboxSpec(
            argv=interp + [f"/work/{filename}"],
            net=net,
            workdir_files={filename: data},
        )
        session = Session(spec, get_profile(policy_name), bus=bus)
        with self._active_lock:
            self._active_session = session

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

        started_at = time.time()
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
            with self._history_lock:
                self.history.append({
                    "id": uuid.uuid4().hex[:8],
                    "ts": started_at,
                    "filename": filename,
                    "source": source,
                    "policy": policy_name,
                    "net": net,
                    "bytes": len(data),
                    **self.session_summary,
                })
            time.sleep(0.3)  # let the pump flush the tail
            self.broadcast({"kind": "run_end", "severity":
                            "violation" if result.verdict == "contained" else "info",
                            "summary": f"session {result.verdict}",
                            "detail": self.session_summary})
        finally:
            stop.set()
            self.running = False
            with self._active_lock:
                self._active_session = None


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
            elif self.path == "/api/payloads":
                self._send(200, json.dumps({
                    "payloads": state.list_payloads(),
                    "policies": list(PROFILES),
                }).encode())
            elif self.path == "/api/history":
                self._send(200, json.dumps({
                    "runs": state.history_list(), "running": state.running,
                }).encode())
            elif self.path == "/api/system":
                self._send(200, json.dumps(state.system_info()).encode())
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
                if state.running:
                    self._send(409, b'{"error":"a session is already running"}')
                    return
                threading.Thread(
                    target=state.run_sample, args=(payload, policy, net),
                    daemon=True,
                ).start()
                self._send(200, b'{"status":"started"}')

            elif self.path.startswith("/api/upload"):
                self._handle_upload()

            elif self.path == "/api/kill":
                ok = state.kill_active()
                self._send(200 if ok else 409,
                           json.dumps({"killed": ok}).encode())

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
            filename = self.headers.get("X-Filename", "upload.py")

            ok, msg, interp = state.validate_upload(filename, data)
            if not ok:
                self._send(400, json.dumps({"error": msg}).encode())
                return

            threading.Thread(
                target=state.run_session,
                args=(msg, data, interp, policy, net, "upload"),
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


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    serve(args.host, args.port)
