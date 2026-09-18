"""Validate the disposable-VM seed without booting a VM.

Proves the pure-Python ISO9660 + Rock Ridge writer produces a cloud-init NoCloud
seed whose files carry their real hyphenated names and whose user-data embeds an
extractable copy of the Cerberus source. Boot itself needs KVM and is out of
scope for a unit test.
"""
import base64
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cerberus.iso9660 import write_iso  # noqa: E402
from cerberus.vm import build_seed, _make_source_tar  # noqa: E402

S = 2048


def _nm(rec: bytes):
    nl = rec[32]
    off = 33 + nl + (1 if nl % 2 == 0 else 0)
    su = rec[off:]
    j = 0
    while j + 4 <= len(su):
        ln = su[j + 2]
        if ln == 0:
            break
        if su[j:j + 2] == b"NM":
            return su[j + 5:j + ln].decode()
        j += ln
    return None


def _root_files(data: bytes):
    pvd = data[16 * S:17 * S]
    rr = pvd[156:190]
    ext = struct.unpack("<I", rr[2:6])[0]
    length = struct.unpack("<I", rr[10:14])[0]
    rd = data[ext * S:ext * S + length]
    out = {}
    i = 0
    while i < len(rd):
        L = rd[i]
        if L == 0:
            break
        rec = rd[i:i + L]
        name = _nm(rec)
        if name:
            out[name] = (struct.unpack("<I", rec[2:6])[0],
                         struct.unpack("<I", rec[10:14])[0])
        i += L
    return out


def check(name, cond, extra=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")
    return cond


def main():
    ok = True

    print("== ISO9660 volume + Rock Ridge names ==")
    iso = write_iso({"user-data": b"#cloud-config\n", "meta-data": b"x\n"}, "CIDATA")
    pvd = iso[16 * S:17 * S]
    ok &= check("valid PVD signature", pvd[0] == 1 and pvd[1:6] == b"CD001")
    ok &= check("volume id is CIDATA", pvd[40:72].decode().rstrip() == "CIDATA")
    files = _root_files(iso)
    ok &= check("names restored to user-data / meta-data",
                set(files) == {"user-data", "meta-data"}, f"({set(files)})")

    print("== seed carries an extractable source tree ==")
    want_b64 = base64.b64encode(_make_source_tar()).decode()
    seed = build_seed(8787)
    files = _root_files(seed)
    ok &= check("seed has user-data + meta-data", set(files) == {"user-data", "meta-data"})
    ext, length = files["user-data"]
    ud = seed[ext * S:ext * S + length].decode()
    flat = re.sub(r"\s", "", ud)
    ok &= check("exact source tarball base64 embedded", want_b64 in flat)
    ok &= check("boot launcher + dashboard command present",
                "cerberus-start" in ud and "cerberus.web" in ud)
    ok &= check("meta-data provides an instance-id",
                b"instance-id" in seed[files['meta-data'][0] * S:
                                       files['meta-data'][0] * S + files['meta-data'][1]])

    print("== user-data is valid cloud-config YAML (the dedent-bug regression) ==")
    try:
        import yaml
    except ImportError:
        print("  [skip] PyYAML not installed; install it to run this check")
    else:
        import io as _io
        import tarfile as _tf
        doc = yaml.safe_load(ud)
        ok &= check("parses as a YAML mapping", isinstance(doc, dict))
        wf = {w["path"]: w["content"] for w in doc.get("write_files", [])}
        ok &= check("write_files has all three files", len(wf) == 3, f"({len(wf)})")
        # the tarball must decode FROM THE PARSED YAML, not just from raw bytes —
        # this is what catches indentation bugs that break cloud-init
        raw = base64.b64decode("".join(wf["/opt/cerberus.tgz.b64"].split()))
        names = _tf.open(fileobj=_io.BytesIO(raw)).getnames()
        ok &= check("tarball decodes from parsed YAML and has web.py",
                    any(n.endswith("cerberus/web.py") for n in names))
        ok &= check("runcmd launches start + wait",
                    len(doc.get("runcmd", [])) == 2)

    print()
    print("ALL PASS" if ok else "SOME FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
