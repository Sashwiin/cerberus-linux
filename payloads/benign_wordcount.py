#!/usr/bin/env python3
"""CONTROL — a legitimate payload that must run to completion, untouched.

This is the other half of the demo: proving Cerberus does not cry wolf. It
does real work (generates text, writes a file under /work, reads it back,
computes statistics) using only syscalls a normal program needs. Cerberus
should allow every one of them and report CLEAN.
"""
import collections
import os
import random

random.seed(1234)
WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet "
         "kilo lima mike november oscar papa quebec romeo sierra tango").split()

path = "/work/corpus.txt"
with open(path, "w") as fh:
    for _ in range(2000):
        line = " ".join(random.choice(WORDS) for _ in range(random.randint(4, 12)))
        fh.write(line + "\n")

counts: collections.Counter = collections.Counter()
with open(path) as fh:
    for line in fh:
        counts.update(line.split())

total = sum(counts.values())
print(f"[wordcount] processed {total} words across {os.path.getsize(path)} bytes")
for word, n in counts.most_common(5):
    print(f"[wordcount]   {word:<10} {n:>5}  ({100 * n / total:.1f}%)")
print("[wordcount] done")
