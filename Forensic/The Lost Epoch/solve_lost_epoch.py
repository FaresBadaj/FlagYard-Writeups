#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
THE LOST EPOCH  -  FlagYard Forensics Solver

Hard / Forensics

"An internal archive server was breached; sealed v4 records were wiped
from the live tree, but the filesystem blocks were never zeroed."

The challenge is a 16 MB ext2 image (audit.ext2.img) that contains five
V4UN-sealed records: one manifest under epoch-0007 and four fragments
under epochs 0017 / 0031 / 0042 / 0073. The on-disk dir entries were
removed, but the sealed blobs themselves are still readable via the
inode table (953-byte manifest + four 201-byte fragments).

The bundled tool /usr/lib/v4_unseal defines a scrypt + AES-256-GCM
container called V4UN:

    header  : "V4UN" | passlen u32 | epoch u32 | roleflag u32
              | ctxlen u32 | bloblen u32 | password | context
    blob    : 0x9c704d1c | P u32 | nonce(12) | ciphertext | tag(16)

    role    = (roleflag == 0) ? "v4:fragment" : "v4:manifest"  (11 bytes)
    salt    = aabbccddeeff00112233445566778899 || BE32(epoch) || role || context
    key     = scrypt(password, salt, N=2^17 (131072), r=8, p=1, dklen=32)
    AAD     = LE32(epoch)
    GCM     : iv = blob[8:20], ct = blob[20:-16], tag = blob[-16:]

KEY INSIGHT (the whole puzzle): password and context are SWAPPED versus
what looks intuitive.

    password  = the record's FILENAME (basename), e.g. "manifest.sealed.v4"
    context   = the SECRET MATERIAL:
                manifest  -> rotation_token recovered from the daemon core
                             (held in-heap between "<BELL-LABS-AUDIT-...-BEGIN>>>"
                              and END sentinels, + TOKEN_HEX= env line)
                fragment  -> its KDF seed (given by the manifest plaintext)

Once the manifest decrypts it hands over fragment_kdf_seeds (basename,
epoch, seed), and every fragment decrypts to {"fragment_idx": N, "data":
"8 hex chars"}. Concatenating data by ascending fragment_idx, wrapping in
FlagY{...} and verifying SHA-256 against the manifest digest gives the
flag. A legacy v2 decoy self-validates and must be ignored.

This solver is standalone: a minimal ext2 reader (no debugfs needed)
locates every inode whose data starts with the 0x9c704d1c blob magic.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_IMAGE = Path(__file__).resolve().parent / "extracted" / "audit.ext2.img"
if not DEFAULT_IMAGE.exists():
    DEFAULT_IMAGE = Path(__file__).resolve().parent / "audit.ext2.img"

CONST16 = bytes.fromhex("aabbccddeeff00112233445566778899")
BLOB_MAGIC = b"\x1c\x4d\x70\x9c"          # u32 0x9c704d1c stored little-endian
TOKEN = ("f88cbc9f59b949a698c91756f5cad13782ae7e5d379fb8401e76d5a112b92e6e")
MANIFEST_NAMES = ("manifest.sealed.v4", "del_manifest.sealed.v4", "manifest")

# ---------------------------------------------------------------------------
# ANSI/box styling (same design as the other FlagYard solvers)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GRAY = "\033[90m"
    WHITE = "\033[97m"

def enable_vt():
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            mode = ctypes.c_uint()
            h = k32.GetStdHandle(-11)
            k32.GetConsoleMode(h, ctypes.byref(mode))
            k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def step(msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s%s%s" % (C.BOLD + color + icon + " ",
                             C.DIM, C.BOLD, msg, C.RESET), flush=True)

def ok(msg):
    step(msg, icon="\u2713", color=C.GREEN)

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("T H E   L O S T   E P O C H   S O L V E R",
              "ext2 carve -> V4UN unseal -> fragments -> flag"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

W = 58

def _row(segs):
    out = "  \u2551"
    for t, pre, post in segs:
        if pre:
            out += pre + t + (post or "") + C.RESET
        else:
            out += t
    out += " " * max(0, W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

_TG = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"

def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)

def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("General", C.BOLD + C.WHITE, "")])
    _row([("   FlagYard CTF  |  Lab Training Write-ups", C.DIM + C.CYAN, "")])
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   Telegram  \u203a  ", "", ""),
          ("@ptok3", _osc("https://t.me/ptok3", _TG), _OSC_END),
          ("      t.me/ptok3", C.DIM + C.GRAY, "")])
    _row([("   GitHub    \u203a  ", "", ""),
          ("github.com/FaresBadaj", _osc("https://github.com/FaresBadaj", "\033[1;36m"), _OSC_END)])
    _row([("   LinkedIn  \u203a  ", "", ""),
          ("linkedin.com/in/FaresBadaj", _osc("https://www.linkedin.com/in/FaresBadaj", "\033[1;34m"), _OSC_END)])
    _row([("   Credly    \u203a  ", "", ""),
          ("credly.com/users/faresbadaj", _osc("https://www.credly.com/users/faresbadaj", "\033[1;33m"), _OSC_END)])
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   Forensics  \u203a  ", "", ""),
          ("The Lost Epoch - SAFCSP", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - Windows Event Logs", C.DIM + C.GRAY, "")])
    print("  " + "\u255a" + "\u2550" * W + "\u255d")


def big_flag(flag, chrono, note):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, note):
        _row([(" " * 10, "", ""), (s, DIM := C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# minimal ext2 reader
# ---------------------------------------------------------------------------
def read_ext2_blobs(img_path: Path):
    """Return list of (inode_number, file_bytes) whose data starts with the
    V4UN blob magic. Works for small files: direct block pointers + holes
    (pointer == 0) read back as zero-fill."""
    data = img_path.read_bytes()
    sb_off = 1024
    inodes_total, = struct.unpack_from("<I", data, sb_off + 0)
    log_block, = struct.unpack_from("<I", data, sb_off + 24)
    first_data_block, = struct.unpack_from("<I", data, sb_off + 20)
    inodes_per_group, = struct.unpack_from("<I", data, sb_off + 40)
    inode_size, = struct.unpack_from("<H", data, sb_off + 88)
    block_size = 1024 << log_block
    # group descriptors start right after the superblock
    gd_off = (first_data_block + 1) * block_size
    gd_size = 32
    blobs = []
    n_tried = 0
    for ino in range(1, inodes_total + 1):
        group = (ino - 1) // inodes_per_group
        bd = gd_off + group * gd_size
        inode_table, = struct.unpack_from("<I", data, bd + 8)
        slot = ((ino - 1) % inodes_per_group) * inode_size
        ibase = inode_table * block_size + slot
        if ibase + inode_size > len(data):
            continue
        size, = struct.unpack_from("<I", data, ibase + 4)
        if size <= 0 or size > 12 * block_size:     # small direct-block files only
            continue
        direct = [struct.unpack_from("<I", data, ibase + 40 + 4 * i)[0]
                  for i in range(12)]
        if any(p >= len(data) // block_size for p in direct if p):
            continue
        out = bytearray()
        for p in direct:
            if len(out) >= size:
                break
            if p == 0:                       # sparse hole -> logical zeros
                out += b"\x00" * min(block_size, size - len(out))
            else:
                out += data[p * block_size : p * block_size +
                            min(block_size, size - len(out))]
        content = bytes(out[:size])
        n_tried += 1
        if content.startswith(BLOB_MAGIC):
            blobs.append((ino, content))
    return blobs, n_tried

# ---------------------------------------------------------------------------
# V4UN unseal
# ---------------------------------------------------------------------------
def unseal(blob: bytes, password: bytes, context: bytes,
           epoch: int, role_marker: int):
    role_s = b"v4:fragment" if role_marker == 0 else b"v4:manifest"
    salt = CONST16 + struct.pack(">I", epoch) + role_s + context
    key = hashlib.scrypt(password, salt=salt, n=0x20000, r=8, p=1,
                         dklen=32, maxmem=0x20000000)
    iv, ct, tag = blob[8:20], blob[20:-16], blob[-16:]
    return AESGCM(key).decrypt(iv, ct + tag, struct.pack("<I", epoch))


def _attempt(job):
    """worker for the parallel brute force (picklable, module-level)"""
    blob, name, cname, ctx, epoch, role = job
    try:
        pt = unseal(blob, name, ctx, epoch, role)
        return job, pt
    except Exception:
        return None


def brute_unseal(blob, names, contexts, epochs, roles):
    """scrypt is ~1s/job, so fan the candidate grid out across a pool."""
    jobs = [(blob, name.encode(), cname, ctx, ep, r)
            for name in names
            for cname, ctx in contexts
            for ep in epochs
            for r in roles]
    workers = min(8, max(1, (os.cpu_count() or 2)))
    if workers < 2 or len(jobs) < 2:
        for job in jobs:
            res = _attempt(job)
            if res:
                return res
        return None
    with multiprocessing.Pool(workers) as pool:
        for res in pool.imap_unordered(_attempt, jobs, chunksize=1):
            if res:
                return res
    return None

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(img: Path):
    step("minimal ext2 reader on %s" % img)
    blobs, n_files = read_ext2_blobs(img)
    if n_files == 0:
        fail("could not read image (wrong path?)")
        return None
    ok("blocks scanned: %d non-empty files, V4UN blobs found: %d"
       % (n_files, len(blobs)))
    if not blobs:
        fail("no 0x9c704d1c sealed blobs found")
        return None
    for ino, b in blobs:
        print("     inode %-4d size %-4d magic ok  %s"
              % (ino, len(b), C.DIM + "..." + C.RESET))
    print()

    step("recovering rotation token (daemon core sentinel + TOKEN_HEX)")
    tok_bytes = bytes.fromhex(TOKEN)
    ok("rotation_token = %s" % TOKEN)

    step("unsealing the manifest (password=filename, context=token)")
    manifest = None
    for ino, b in blobs:
        r = brute_unseal(b, MANIFEST_NAMES,
                         [("token-raw", tok_bytes), ("token-hex", TOKEN.encode())],
                         (7, 17, 31, 42, 73, 100), (1, 0))
        if r and r[1].startswith(b'{') and b'fragment_kdf_seeds' in r[1]:
            manifest = (ino, r[0][1], r[0][2], r[0][4], r[0][5], r[1])
            break
    if not manifest:
        fail("manifest did not unseal")
        return None
    m_ino, m_name, m_ctx, m_ep, m_role, m_pt = manifest
    ok("manifest inode %s: password=%r epoch=%d roleflag=%d | %d B"
       % (m_ino, m_name, m_ep, m_role, len(m_pt)))
    mj = json.loads(m_pt)

    step("checking manifest digest")
    ok("digest = %s" % mj["digest"])

    step("unsealing the four epoch fragments (password=basename, context=seed)")
    parts = []
    for i, rec in enumerate(mj["fragment_kdf_seeds"]):
        name, ep, seed = rec["basename"], rec["epoch"], rec["seed"]
        hit = None
        for ino, b in blobs:
            if ino == m_ino:
                continue
            r = brute_unseal(b, (name, "del_" + name),
                             [("seed-raw", bytes.fromhex(seed)),
                              ("seed-ascii", seed.encode())],
                             (ep,), (0, 1))
            if r:
                hit = (ino, r[1])
                break
        if not hit:
            fail("fragment %-18s epoch %d did not unseal" % (name, ep))
            return None
        fino, fpt = hit
        fj = json.loads(fpt)
        parts.append((fj.get("fragment_idx", i + 1), fj["data"], name, ep, fino))
        ok("fragment %d/%d inode %s  %-18s epoch %d  data=%s"
           % (fj["fragment_idx"], mj["fragment_count"], fino, name, ep,
              fj["data"]))

    step("assembling fragments by ascending fragment_idx")
    parts.sort(key=lambda x: x[0])
    body = "".join(p[1] for p in parts)
    flag = "FlagY{%s}" % body
    ok("body   = %s" % body)
    ok("flag   = %s" % flag)
    return mj, flag

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    img = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_IMAGE
    if not img.exists():
        fail("image not found: %s" % img)
        sys.exit(1)
    step("image %s" % img)
    res = exploit(img)
    if not res:
        sys.exit(1)
    mj, flag = res
    digest = hashlib.sha256(flag.encode()).hexdigest()
    match = digest == mj.get("digest", "")
    if flag.startswith("FlagY") and match:
        ok("SHA-256(flag) matches the manifest digest")
        big_flag(flag, time.time() - t0,
                 "manifest digest verified | fragments 1->4 | v2 decoy ignored")
        outf = Path(__file__).resolve().parent / "flag_from_lost_epoch.txt"
        outf.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outf, C.RESET))
    else:
        fail("flag not verified against manifest digest")

if __name__ == "__main__":
    main()