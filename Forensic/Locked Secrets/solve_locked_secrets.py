#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LOCKED SECRETS  -  FlagYard Forensics Solver

Hard / Forensics

"A domain-joined Windows box exposes a BitLocker-protected E: drive. The
password never travels far: it is sitting - encrypted with the well-known,
public Group Policy Preferences key - in the domain's Sysvol, on the same
disk that was seized."

The bundle is a 71 MB virtual disk encrypted with Microsoft BitLocker
(BDE/FVE) shipped as an FTK Imager E01, plus a KAPE-style triage copy of
the same Windows box. The whole recovery chain:

    1. GPP cpassword :  SYSVOL\\domain\\Policies\\...\\Groups.xml keeps a
       Group Policy Preferences password. AES-256-CBC with the public
       Microsoft GPP key (zero IV) releases it in cleartext.
    2. EWF -> raw    :  walk the E01 chunk table (bit-31 = zlib stream,
       otherwise a 32 KiB raw slot) and decompress the 74.4 MB disk image.
    3. BDE metadata  :  MBR entry 0 = NTFS/To-Go partition at LBA 128,
       139264 sectors. The plaintext "-FVE-FS-" volume header and its
       metadata copies host the key vault. The FVE metadata block header
       sits at rel +0x40 (size / version / entry-header size / etc.).
    4. stretch       :  BitLocker's double-SHA256 KDF - 2^20 iterations
       of sha256( last || initial || salt || count ) - derives the VMK
       protector key from (password, salt).
    5. AES-CCM       :  user key -> VMK (0x2000), VMK -> FVEK + TWEAK
       (0x8000 = AES-128-CBC + Elephant diffuser).
    6. Elephant      :  per-sector AES-128-CBC decrypt, then the two
       Elephant diffusers (B then A, dislocker port) undo the whitening,
       then the 32-byte per-sector TWEAK-derived key is XOR-ed back.
    7. $MFT          :  the NTFS VBR copy at rel 0x27da000 reveals $MFT
       (LCN 5802). The resident $DATA of the flag file holds the flag.

Target is the challenge folder (default: the folder of this script).
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct
import sys
import time
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)
GPP_INITIALIZER = b"\x00" * 16
E01_SIG = b"EVF\x09\x0d\x0a\xff\x00"
_DISK_SIG = b"disk" + b"\x00" * 12
_TABLE_SIG = b"table" + b"\x00" * 11

# ---------------------------------------------------------------------------
# coloured output (same design as the other FlagYard solvers)
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


def bar(frac):
    w = 20
    f = max(0.0, min(1.0, frac))
    full = int(round(f * w))
    return "[%s%s] %5.1f%%" % ("\u2588" * full, "\u2591" * (w - full), f * 100.0)


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
    for t in ("L O C K E D   S E C R E T S   S O L V E R",
              "Sysvol cpassword -> BitLocker -> flag"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)


# ---------------------------------------------------------------------------
# result panel + author credits
# ---------------------------------------------------------------------------
W = 58
_TG = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"


def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)


def _row(segs):
    out = "  \u2551"
    for t, pre, post in segs:
        if pre:
            out += pre + t + (post or "") + C.RESET
        else:
            out += t
    out += " " * max(0, W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)


def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("General", C.BOLD + C.WHITE, "")])
    _row([("   FlagYard CTF  |  Lab Training Write-ups  ", C.DIM + C.CYAN, "")])
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
          ("Locked Secrets - SAFCSP", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - BitLocker / BDE-FVE", C.DIM + C.GRAY, "")])
    print("  " + "\u255a" + "\u2550" * W + "\u255d")


def big_flag(flag, chrono):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono,
              "gpp -> stretch -> vmk -> fvek -> $MFT"):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()


# ---------------------------------------------------------------------------
# 1) artifact discovery
# ---------------------------------------------------------------------------
def find_artifacts(folder: Path):
    gpp_xml = None
    for p in folder.rglob("*"):
        if not p.is_file() or p.name.lower() != "groups.xml":
            continue
        try:
            if b"cpassword" in p.read_bytes():
                gpp_xml = p
                break
        except OSError:
            continue
    e01 = None
    for p in folder.rglob("*"):
        if p.is_file() and p.suffix.lower() == ".e01":
            e01 = p
            break
    return gpp_xml, e01


# ---------------------------------------------------------------------------
# 2) Group Policy Preferences password
# ---------------------------------------------------------------------------
def gpp_password(xml_path: Path):
    m = re.search(rb'cpassword="([A-Za-z0-9+/=]+)"', xml_path.read_bytes())
    if not m:
        return None
    ct = base64.b64decode(m.group(1))
    dec = Cipher(algorithms.AES(GPP_AES_KEY), modes.CBC(GPP_INITIALIZER)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1] if pt else 0
    if 1 <= pad <= 16:
        pt = pt[:-pad]
    return pt.decode("utf-16-le", errors="replace").strip("\x00")


# ---------------------------------------------------------------------------
# 3) EWF E01 -> raw disk image
# ---------------------------------------------------------------------------
def rebuild_disk(e01: Path):
    data = e01.read_bytes()
    if not data.startswith(E01_SIG):
        raise ValueError("%s: not an E01 image" % e01.name)
    dk = data.find(_DISK_SIG)
    tb = data.find(_TABLE_SIG)
    if dk < 0 or tb < 0:
        raise ValueError("E01 section signatures not found")
    sectors = struct.unpack_from("<I", data, dk + 0x5C)[0]
    chunks = struct.unpack_from("<I", data, dk + 0x50)[0]
    if chunks * 0x8000 != sectors * 512:
        raise ValueError("E01 geometry mismatch (sectors=%d chunks=%d)" % (sectors, chunks))

    disk = bytearray(chunks * 0x8000)
    ent0 = tb + 0x64
    use = 0
    for k in range(chunks):
        v = struct.unpack_from("<I", data, ent0 + k * 4)[0]
        if v == 0:
            continue
        if v & 0x80000000:
            zo = zlib.decompressobj()
            r = zo.decompress(data[(v & 0x7fffffff):(v & 0x7fffffff) + 0x20000])
            if len(r) >= 0x8000:
                disk[k * 0x8000:(k + 1) * 0x8000] = r[:0x8000]
                use += 1
        else:
            b = data[v:v + 0x8000]
            if len(b) == 0x8000:
                disk[k * 0x8000:(k + 1) * 0x8000] = b
                use += 1
    return bytes(disk), chunks, use


# ---------------------------------------------------------------------------
# 4) BitLocker key schedule (double-sha256 stretch + AES-CCM wrapper)
# ---------------------------------------------------------------------------
def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _stretch(password, salt):
    pw = password.encode("utf-16-le")
    initial = hashlib.sha256(hashlib.sha256(pw).digest()).digest()
    last = b"\x00" * 32
    for i in range(0x100000):
        last = hashlib.sha256(last + initial + salt + struct.pack("<Q", i)).digest()
    return last


def _walk_entries(vol, base_rel, msz, mhsz):
    buf = vol[base_rel + 0x40 + mhsz: base_rel + 0x40 + msz]
    off = 0
    while off + 8 <= len(buf):
        size, et, vt, ver = struct.unpack_from("<4H", buf, off)
        if size < 8 or off + size > len(buf):
            break
        yield et, vt, buf[off + 8:off + size]
        off += size


def _unlock_vmk(password, vmk_data):
    """Try every protector in one VMK entry; return (salt, user_key, vmk)."""
    props = vmk_data[28:]
    plist = []
    off = 0
    while off + 8 <= len(props):
        psize, pt, pvt, pver = struct.unpack_from("<4H", props, off)
        plist.append((pvt, props[off + 8:off + psize]))
        if psize < 8 or off + psize > len(props):
            break
        off += psize
    standalone = [v for t, v in plist if t == 0x0005 and len(v) >= 24]
    for pvt, value in plist:
        if pvt != 0x0003 or len(value) < 24:
            continue
        salt = value[4:20]
        blobs = list(standalone)
        rest = value[20:]
        if len(rest) >= 8:
            ssize, st, svt, sver = struct.unpack_from("<4H", rest, 0)
            if 8 <= ssize <= len(rest):
                blobs.append(rest[8:8 + ssize - 8])
        user_key = _stretch(password, salt)
        for blob in dict.fromkeys(blobs):
            try:
                vm = AESCCM(user_key).decrypt(blob[0:12], blob[28:] + blob[12:28], None)
            except Exception:
                continue
            if len(vm) == 44 and _u32(vm, 8) == 0x2003:
                return salt, user_key, vm[12:44]
    return None


def recover_keys(disk, volbase, volsize, password):
    vol = disk[volbase:volbase + volsize]
    metas = sorted({p for p in _scan(vol, b"-FVE-FS-") if p})
    if not metas:
        raise ValueError("no BDE metadata copies found")
    for mrel in metas:
        if mrel + 0x40 + 0x40 > volsize:
            continue
        msz = _u32(vol, mrel + 0x40)
        mhsz = _u32(vol, mrel + 0x48)
        if not (0x40 <= msz <= 0x4000) or mhsz < 0x30:
            continue
        entries = list(_walk_entries(vol, mrel, msz, mhsz))
        fvek = next((d for t, v, d in entries if t == 0x0003 and v == 0x0005), None)
        if fvek is None:
            continue

        unlocked = None
        for t, vt, d in entries:
            if t == 0x0002:
                unlocked = _unlock_vmk(password, d)
                if unlocked:
                    break
        if unlocked is None:
            continue
        salt, user_key, vmk = unlocked

        fb = fvek
        plain = AESCCM(vmk).decrypt(fb[0:12], fb[28:] + fb[12:28], None)
        keydata = plain[12:76]
        fvek16 = keydata[0:16]
        tweak16 = keydata[32:48]
        vh_rel = _u64(vol, mrel + 0x78)
        vh_size = _u64(vol, mrel + 0x80)
        return mrel, salt, user_key, vmk, fvek16, tweak16, vh_rel, vh_size
    raise ValueError("key recovery failed for every metadata copy")


def _scan(haystack, needle):
    pos = 0
    while True:
        pos = haystack.find(needle, pos)
        if pos < 0:
            break
        yield pos
        pos += 1


# ---------------------------------------------------------------------------
# 5) Elephant-diffuser sector decryption (AES-128-CBC, method 0x8000)
# ---------------------------------------------------------------------------
def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xffffffff


def _diffA(w):
    N = len(w); Ra = [9, 0, 13, 0]
    for _ in range(5):
        for i in range(N):
            w[i] = (w[i] + (w[(i - 2 + N) % N] ^ _rotl(w[(i - 5 + N) % N], Ra[i % 4]))) & 0xffffffff
    return w


def _diffB(w):
    N = len(w); Rb = [0, 10, 0, 25]
    for _ in range(3):
        for i in range(N):
            w[i] = (w[i] + (w[(i + 2) % N] ^ _rotl(w[(i + 5) % N], Rb[i % 4]))) & 0xffffffff
    return w


def _ecb(key, blk):
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(blk)


def decrypt_sector(buf, addr, fvek16, tweak16):
    iv = struct.pack("<Q", addr) + b"\x00" * 8
    sk = bytearray(32)
    sk[0:16] = _ecb(tweak16, iv)
    iv2 = bytearray(iv); iv2[15] = 0x80
    sk[16:32] = _ecb(tweak16, bytes(iv2))
    ct = _ecb(fvek16, iv)
    pt = Cipher(algorithms.AES(fvek16), modes.CBC(ct)).decryptor().update(buf)
    w = list(struct.unpack("<%dI" % (len(pt) // 4), pt))
    w = _diffB(w)
    w = _diffA(w)
    out = struct.pack("<%dI" % len(w), *w)
    return bytes(a ^ sk[i % 32] for i, a in enumerate(out))


def decrypt_region(disk, volbase, rel, length, fvek16, tweak16):
    start = rel - (rel % 0x200)
    end = min(rel + length, len(disk) - volbase)
    end = end - (end % 0x200)
    out = bytearray()
    for a in range(start, end, 0x200):
        out += decrypt_sector(disk[volbase + a:volbase + a + 0x200], a, fvek16, tweak16)
    return bytes(out)


# ---------------------------------------------------------------------------
# 6) NTFS $MFT -> the flag.txt resident data
# ---------------------------------------------------------------------------
def _file_names(rec):
    names = []
    ao = struct.unpack_from("<H", rec, 0x14)[0]
    while ao + 8 <= len(rec):
        atype, asize = struct.unpack_from("<II", rec, ao)
        if atype == 0xFFFFFFFF or asize < 8 or ao + asize > len(rec):
            break
        if atype == 0x30 and asize >= 0x42:
            buf = rec[ao:ao + asize]
            nlen = buf[0x40] if len(buf) > 0x40 else 0
            ntype = buf[0x41] if len(buf) > 0x41 else 0
            if nlen and nlen * 2 + 0x42 <= len(buf):
                names.append(buf[0x42:0x42 + nlen * 2].decode("utf-16-le", errors="replace"))
        ao += asize
    return names


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    step("challenge folder %s" % base)

    gpp_xml, e01 = find_artifacts(base)
    if gpp_xml is None or e01 is None:
        fail("need Groups.xml (cpassword) + *.E01 under %s" % base)
        return
    ok("Groups.xml %s" % gpp_xml.parent)
    ok("drive image   %s" % e01)

    password = gpp_password(gpp_xml)
    if not password:
        fail("no cpassword recovered from Groups.xml")
        return
    ok("GPP cpassword -> %s" % password)

    step("rebuilding raw image from E01 chunk table")
    disk, chunks, use = rebuild_disk(e01)
    md = hashlib.md5(disk).hexdigest()
    ok("disk image %d bytes (%d chunks, %d stored)" % (len(disk), chunks, use))
    if md == "a14dbeedbbe755d96f587c29b0447f9c":
        ok("image integrity verified (MD5 %s)" % md)

    mbr = disk[0x1BE:0x1FE]
    volbase = volsize = None
    for i in range(4):
        e = mbr[i * 16:(i + 1) * 16]
        st = struct.unpack_from("<I", e, 8)[0]
        if st:
            volbase = st * 512
            volsize = struct.unpack_from("<I", e, 12)[0] * 512
            break
    if volbase is None or disk[volbase + 3:volbase + 11] != b"-FVE-FS-":
        fail("FVE volume not found (expected -FVE-FS- at LBA 128)")
        return
    ok("FVE volume at LBA %d (%d bytes)" % (volbase // 512, volsize))

    step("double-sha256 stretch (2^20) + AES-CCM -> VMK -> FVEK")
    mrel, salt, user_key, vmk, fvek16, tweak16, vh_rel, vh_size = \
        recover_keys(disk, volbase, volsize, password)
    ok("metadata block @ rel %#x" % mrel)
    ok("VMK  %s" % vmk.hex())
    ok("FVEK %s" % (fvek16 + tweak16).hex())

    step("AES-128-CBC + Elephant diffuser -> NTFS sector %#x" % vh_rel)
    vbr = decrypt_region(disk, volbase, vh_rel, 512, fvek16, tweak16)
    if vbr[3:11] != b"NTFS    ":
        fail("stored VBR does not carry an NTFS signature")
        return
    bps = struct.unpack_from("<H", vbr, 11)[0]
    spc = vbr[13]
    mft_lcn = struct.unpack_from("<Q", vbr, 48)[0]
    rec = struct.unpack_from("<h", vbr, 64)[0]
    rec = (1 << -rec) if rec < 0 else rec
    mft_rel = mft_lcn * spc * bps
    ok("NTFS  bps=%d spc=%d $MFT LCN=%d (rel %#x, rec %d B)"
       % (bps, spc, mft_lcn, mft_rel, rec))

    step("decrypting $MFT region and extracting the flag file")
    flag = None
    fname = None
    WIN = 0x100000
    rel = mft_rel - (mft_rel % 0x200)
    while rel < volsize and flag is None:
        pt = decrypt_region(disk, volbase, rel, min(WIN, volsize - rel), fvek16, tweak16)
        for m in re.finditer(rb"FlagY\{[0-9a-fA-F]{32}\}", pt):
            flag = m.group(0).decode()
            rec_off = (m.start() // rec) * rec
            fname = _file_names(pt[rec_off:rec_off + rec]) or None
            break
        rel += WIN
        if flag is None:
            print("     %s" % bar(rel / volsize), flush=True)
    if flag is None:
        fail("flag not recovered")
        return
    if fname:
        ok("flag in MFT record of %s" % fname)

    ok("FLAG = %s" % flag)
    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_locked_secrets.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()