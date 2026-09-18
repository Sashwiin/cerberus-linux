"""A tiny, dependency-free ISO9660 writer.

Just enough of ISO9660 to produce a cloud-init "NoCloud" seed: a single-level
image with a volume label and a handful of small files in the root directory.
Written by hand so the VM launcher needs nothing but QEMU on the host -- no
genisoimage, no xorriso, no cloud-image-utils.

Not a general ISO writer: no Joliet, no Rock Ridge, no subdirectories. Filenames
are upper-cased to the 8.3-ish "d-characters" ISO9660 allows, which is all
cloud-init's seed needs (USER-DATA, META-DATA).
"""

from __future__ import annotations

import struct
import time

SECTOR = 2048


def _both_endian32(n: int) -> bytes:
    return struct.pack("<I", n) + struct.pack(">I", n)


def _both_endian16(n: int) -> bytes:
    return struct.pack("<H", n) + struct.pack(">H", n)


def _dt(t: time.struct_time) -> bytes:
    # ISO9660 directory-record 7-byte timestamp.
    return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday,
                  t.tm_hour, t.tm_min, t.tm_sec, 0])


def _iso_name(name: str) -> str:
    """Map a filename to an ISO9660 identifier: A-Z 0-9 _ and a version ';1'."""
    up = "".join(c if (c.isascii() and (c.isalnum() or c in "_.")) else "_"
                 for c in name.upper())
    if "." not in up:
        up += "."
    return up + ";1"


def _rr_nm(name: str) -> bytes:
    """Rock Ridge NM (alternate name) entry — preserves the real filename."""
    n = name.encode("ascii")
    return b"NM" + bytes([5 + len(n), 1, 0]) + n


def _rr_sp() -> bytes:
    """Rock Ridge SP (sharing protocol) entry — enables RR on the root '.'."""
    return b"SP" + bytes([7, 1]) + b"\xbe\xef" + b"\x00"


def _dir_record(name_id: bytes, extent: int, length: int, is_dir: bool,
                dt: bytes, system_use: bytes = b"") -> bytes:
    flags = 0x02 if is_dir else 0x00
    body = b""
    body += b"\x00"                         # extended attribute record length
    body += _both_endian32(extent)          # extent LBA
    body += _both_endian32(length)          # data length
    body += dt                              # 7-byte datetime
    body += bytes([flags])                  # file flags
    body += b"\x00"                         # file unit size
    body += b"\x00"                         # interleave gap
    body += _both_endian16(1)               # volume sequence number
    body += bytes([len(name_id)])           # length of identifier
    body += name_id                         # identifier
    if len(name_id) % 2 == 0:               # pad so System Use starts on even
        body += b"\x00"
    body += system_use                      # Rock Ridge entries go here
    rec = bytes([0]) + body                 # placeholder length byte
    if len(rec) % 2:                        # records are padded to even length
        rec += b"\x00"
    rec = bytes([len(rec)]) + rec[1:]
    return rec


def write_iso(files: dict[str, bytes], volume_id: str = "CIDATA") -> bytes:
    """Build an ISO9660 image containing `files` in the root directory."""
    t = time.gmtime()
    dt = _dt(t)

    # Layout: [0..15] system area, [16] PVD, [17] terminator, [18] L-path table,
    # [19] M-path table, [20] root directory, [21..] file data.
    ROOT_LBA = 20
    file_lbas: dict[str, int] = {}
    lba = 21
    for name, data in files.items():
        file_lbas[name] = lba
        lba += (len(data) + SECTOR - 1) // SECTOR
    total_sectors = lba

    # --- root directory extent ---
    # The root '.' record carries the Rock Ridge SP entry, which is what tells
    # the kernel to honour Rock Ridge and therefore the NM (real-name) entries
    # on the files below. Without this, cloud-init would see mangled uppercase
    # names like USER_DATA.;1 and never find its user-data.
    root_self = _dir_record(b"\x00", ROOT_LBA, SECTOR, True, dt, _rr_sp())
    root_parent = _dir_record(b"\x01", ROOT_LBA, SECTOR, True, dt)
    root = bytearray(root_self + root_parent)
    for name, data in files.items():
        rec = _dir_record(_iso_name(name).encode("ascii"),
                          file_lbas[name], len(data), False, dt,
                          _rr_nm(name))
        if len(root) % SECTOR + len(rec) > SECTOR:
            root += b"\x00" * (SECTOR - len(root) % SECTOR)
        root += rec
    root += b"\x00" * (SECTOR - len(root) % SECTOR)

    # --- path tables (root entry only) ---
    def path_table(be: bool) -> bytes:
        # one entry for the root directory
        rec = bytes([1, 0])  # id len 1, ext attr len 0
        rec += struct.pack(">I" if be else "<I", ROOT_LBA)
        rec += struct.pack(">H" if be else "<H", 1)  # parent dir number
        rec += b"\x00"       # identifier (0x00 for root)
        rec += b"\x00"       # pad to even
        return rec

    lpt = path_table(False)
    mpt = path_table(True)

    # --- primary volume descriptor ---
    def pad(s: str, n: int) -> bytes:
        return s.encode("ascii")[:n].ljust(n, b" ")

    pvd = bytearray(b"\x00" * SECTOR)
    pvd[0] = 1                               # type: primary
    pvd[1:6] = b"CD001"
    pvd[6] = 1                               # version
    pvd[8:40] = pad("", 32)                  # system id
    pvd[40:72] = pad(volume_id, 32)          # volume id  <-- the "cidata" label
    pvd[80:88] = _both_endian32(total_sectors)
    pvd[120:124] = _both_endian16(1) + b"\x00\x00"  # vol set size (both-endian16)
    pvd[124:128] = _both_endian16(1) + b"\x00\x00"  # vol seq nr
    pvd[128:132] = _both_endian16(SECTOR)           # logical block size
    pvd[132:140] = _both_endian32(len(lpt))         # path table size
    pvd[140:144] = struct.pack("<I", 18)            # L path table LBA
    pvd[148:152] = struct.pack(">I", 19)            # M path table LBA
    pvd[156:190] = _dir_record(b"\x00", ROOT_LBA, SECTOR, True, dt).ljust(34, b"\x00")[:34]
    pvd[190:318] = pad("", 128)              # volume set id
    pvd[318:446] = pad("Cerberus", 128)      # publisher id
    pvd[446:574] = pad("", 128)              # data preparer
    pvd[574:702] = pad("", 128)              # application id
    ts = time.strftime("%Y%m%d%H%M%S", t).encode() + b"00"
    for off in (813, 830, 847, 864):         # created / modified / expires / effective
        pvd[off:off + 16] = ts + b"\x00"
    pvd[881] = 1                             # file structure version

    # --- terminator ---
    term = bytearray(b"\x00" * SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1

    # --- assemble ---
    img = bytearray(SECTOR * total_sectors)
    img[16 * SECTOR:17 * SECTOR] = pvd
    img[17 * SECTOR:18 * SECTOR] = term
    img[18 * SECTOR:18 * SECTOR + len(lpt)] = lpt
    img[19 * SECTOR:19 * SECTOR + len(mpt)] = mpt
    img[ROOT_LBA * SECTOR:ROOT_LBA * SECTOR + len(root)] = root
    for name, data in files.items():
        off = file_lbas[name] * SECTOR
        img[off:off + len(data)] = data
    return bytes(img)
