"""Minimal HTTP + WebSocket client (stdlib only).

Lets the native GUI drive a Cerberus dashboard server running somewhere else --
specifically inside a disposable VM -- and stream its events back into native
widgets. No third-party websocket library; just enough of RFC 6455 to POST an
upload and read the server's one-way text-frame event stream.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import urllib.request


def wait_up(host: str, port: int, timeout: float = 90.0, interval: float = 0.5) -> bool:
    """Block until the server answers on host:port, or timeout."""
    import time
    deadline = time.time() + timeout
    url = f"http://{host}:{port}/api/payloads"
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(interval)
    return False


def upload(host: str, port: int, filename: str, data: bytes,
           policy: str = "strict", net: str = "none") -> dict:
    """POST a script to the dashboard's /api/upload endpoint."""
    from urllib.parse import urlencode
    q = urlencode({"policy": policy, "net": net})
    req = urllib.request.Request(
        f"http://{host}:{port}/api/upload?{q}", data=data, method="POST",
        headers={"Content-Type": "application/octet-stream",
                 "X-Filename": filename})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"{}")


def run_sample(host: str, port: int, payload: str,
               policy: str = "strict", net: str = "none") -> dict:
    body = json.dumps({"payload": payload, "policy": policy, "net": net}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/api/run", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"{}")


def list_payloads(host: str, port: int) -> dict:
    with urllib.request.urlopen(f"http://{host}:{port}/api/payloads", timeout=5) as r:
        return json.loads(r.read() or b"{}")


class WSEvents:
    """Connect to /ws and iterate decoded JSON event dicts (server -> client)."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None

    def __enter__(self) -> "WSEvents":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        s = socket.create_connection((self.host, self.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall(
            (f"GET /ws HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
             f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
            .encode())
        resp = s.recv(4096)
        if b" 101 " not in resp.split(b"\r\n", 1)[0]:
            s.close()
            raise ConnectionError("server did not accept the WebSocket upgrade")
        self.sock = s

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __iter__(self):
        assert self.sock is not None
        buf = b""
        while True:
            # decode as many frames as are already buffered
            while True:
                frame, buf = _decode_frame(buf)
                if frame is None:
                    break
                opcode, payload = frame
                if opcode == 0x8:      # close
                    return
                if opcode in (0x1, 0x2):
                    try:
                        yield json.loads(payload)
                    except ValueError:
                        pass
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk


def _decode_frame(buf: bytes):
    """Return ((opcode, payload), rest) or (None, buf) if incomplete."""
    if len(buf) < 2:
        return None, buf
    b0, b1 = buf[0], buf[1]
    opcode = b0 & 0x0F
    masked = b1 & 0x80
    ln = b1 & 0x7F
    off = 2
    if ln == 126:
        if len(buf) < 4:
            return None, buf
        ln = struct.unpack_from("!H", buf, 2)[0]
        off = 4
    elif ln == 127:
        if len(buf) < 10:
            return None, buf
        ln = struct.unpack_from("!Q", buf, 2)[0]
        off = 10
    mask = b""
    if masked:
        if len(buf) < off + 4:
            return None, buf
        mask = buf[off:off + 4]
        off += 4
    if len(buf) < off + ln:
        return None, buf
    payload = bytearray(buf[off:off + ln])
    if masked:
        for i in range(ln):
            payload[i] ^= mask[i % 4]
    return (opcode, bytes(payload)), buf[off + ln:]
