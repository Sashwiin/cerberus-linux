"""Smoke test for the riskiest primitive: does seccomp user-notify actually
work here? Child installs a filter notifying on openat, parent reads the path
out of the child's memory and denies one specific file.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cerberus import seccomp  # noqa: E402
from cerberus.syscalls import nr  # noqa: E402

NOTIFY = [nr("openat"), nr("connect"), nr("socket")]
DENY = [nr("ptrace"), nr("mount"), nr("bpf")]


def main() -> int:
    print("kernel notif sizes:", seccomp.notif_sizes())
    prog = seccomp.build_program(NOTIFY, DENY)
    print(f"assembled {len(prog)} BPF instructions")

    parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()

    if pid == 0:
        parent_sock.close()
        try:
            seccomp.set_no_new_privs()
            fd = seccomp.install_filter(NOTIFY, DENY)
            socket.send_fds(child_sock, [b"L"], [fd])
            child_sock.recv(1)  # wait for supervisor to be ready

            # Benign read: should be allowed through.
            with open("/etc/hostname", "rb") as fh:
                fh.read(16)
            os.write(2, b"[child] allowed open of /etc/hostname\n")

            # Sensitive read: supervisor should deny this.
            try:
                with open("/etc/shadow", "rb") as fh:
                    fh.read(16)
                os.write(2, b"[child] FAIL: read /etc/shadow\n")
                os._exit(1)
            except PermissionError:
                os.write(2, b"[child] denied open of /etc/shadow (EPERM)\n")

            # Hard-denied syscall, blocked in-kernel with no notification.
            import ctypes

            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            rc = libc.syscall(101, 0, 0, 0, 0)  # ptrace
            os.write(2, b"[child] ptrace rc=%d errno=%d\n"
                     % (rc, ctypes.get_errno()))
            os._exit(0)
        except Exception as exc:  # pragma: no cover
            os.write(2, f"[child] error: {exc!r}\n".encode())
            os._exit(2)

    child_sock.close()
    _msg, fds, _f, _a = socket.recv_fds(parent_sock, 1, 1)
    listener = seccomp.Listener(fds[0])
    print(f"[supervisor] got listener fd {fds[0]}")
    parent_sock.send(b"G")

    seen = 0
    while True:
        notif = listener.receive()
        if notif is None:
            break
        seen += 1
        if notif.nr == nr("openat"):
            path = listener.read_cstring(notif.id, notif.pid, notif.args[1])
            verdict = "DENY" if path in ("/etc/shadow", "/etc/gshadow") else "allow"
            print(f"[supervisor] openat({path!r}) -> {verdict}")
            if verdict == "DENY":
                listener.deny(notif.id)
            else:
                listener.allow(notif.id)
        else:
            print(f"[supervisor] {notif.nr} -> allow")
            listener.allow(notif.id)
        if seen > 400:
            print("[supervisor] too many events, bailing")
            break

    _, status = os.waitpid(pid, 0)
    print(f"[supervisor] child exited status={status}, {seen} notifications")
    return 0 if status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
