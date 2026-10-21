#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM  -  FlagYard Forensics solver  (deleted-image recovery from the
Windows thumbnail cache)

Easy / Forensics

"Even when a file is gone, a picture might still hold the truth.
 Dig deep into the cache."

The box ships a Windows user profile (Local\\AppData).  Somewhere under
Local\\Microsoft\\Windows\\Explorer the file

    thumbcache_1280.db

still holds the THUMBNAIL of a "deleted" image.  Windows caches file
thumbnails in these .db blobs; the thumbnail outlives the original file.
The cache file is a sequence of "CMMM" cache entries; each entry stores
the encoded thumbnail plus, in its header, the pixel dimensions of the
original image:

    entry header                       file
    +0x00  "CMMM"                      thumbcache_1280.db
    +0x18  data size = 108691          0x70  FF D8 FF ...  (JPEG payload)
    +0x1c  width     = 902             902 x 1280 pixels
    +0x20  height    = 1280

In thumbcache_1280.db there is exactly ONE cache entry with a single
embedded 902x1280 JPEG.  Carving it out of the blob and OCR'ing it
leaks the hidden message and the flag.

Solver pipeline:

    1. locate Explorer\\thumbcache_*.db inside the challenge folder
    2. parse the "CMMM" entries; extract width/height from the headers
    3. carve every embedded JPEG/PNG out of each db
    4. OCR each carved image (tesseract CLI if available) and keep the
       text that contains  FlagY{...}
    5. print the flag box and save flag_from_phantom.txt

The flag is painted INSIDE the picture (real text), so an OCR engine is
required: tesseract from UB-Mannheim (C:\\Program Files\\Tesseract-OCR).
If tesseract is missing the solver still carves the image and tells you
where it was saved so the flag can be read by eye.

Default target folder = the folder next to this solver.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# colored output (same design as the other FlagYard solvers)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GRAY = "\033[90m"
    WHITE = "\033[97m"

def enable_vt():
    if os.name == "nt":
        try:
            import ctypes as _c
            k32 = _c.windll.kernel32
            mode = _c.c_uint()
            h = k32.GetStdHandle(-11)
            k32.GetConsoleMode(h, _c.byref(mode))
            k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def pct(frac):
    return "[%5.1f%%]" % (frac * 100.0)

def status(frac, msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s%s%s %s%s%s" % (C.DIM, pct(frac), C.BOLD + color + icon + " ",
                                    C.RESET, C.DIM, C.BOLD, msg, C.RESET), flush=True)

def ok(frac, msg):
    status(frac, msg, icon="\u2713", color=C.GREEN)

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("P H A N T O M   S O L V E R",
              "Windows thumbcache  |  deleted image -> OCR flag"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel (fixed-width frame) + author credits
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
    out += " " * (W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("Fares Badaj", C.BOLD + C.WHITE, "")])
    _row([("   Red Team Operator | Penetration Tester Specialist", C.DIM + C.CYAN, "")])
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
    print("  " + "\u255a" + "\u2550" * W + "\u255d")

def big_flag(flag, chrono, extra):
    line = flag.strip().splitlines()[0]
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# thumbcache parsing + carving
# ---------------------------------------------------------------------------
JPEG_SIG = b"\xff\xd8\xff"
PNG_SIG = b"\x89PNG\r\n\x1a\n"

def find_tesseract():
    """Resolve the tesseract executable (install path or PATH)."""
    cands = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        r"C:\Users\General\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
    ]
    exe = shutil.which("tesseract")
    if exe:
        cands.insert(0, exe)
    for c in cands:
        if os.path.isfile(c):
            return c
    return None

def u32le(b, o):
    return int.from_bytes(b[o:o + 4], "little")

def parse_entries(data: bytes):
    """Return every (offset, width, height, data_size) parsed from the
    'CMMM' cache-entry headers found in a thumbcache blob."""
    rows = []
    pos = 0
    while True:
        i = data.find(b"CMMM", pos)
        if i == -1 or i + 0x21 > len(data):
            break
        # thumbcache entry header (thin variant): width/height live at +0x1c/+0x20
        if u32le(data, i) == 0x4d4d4d43:
            size = u32le(data, i + 0x18) if i + 0x1c <= len(data) else None
            w = u32le(data, i + 0x1c) if i + 0x20 <= len(data) else None
            h = u32le(data, i + 0x20) if i + 0x24 <= len(data) else None
            # sanity: a real thumbnail header has plausible dimensions
            if w is not None and h is not None and 1 <= w <= 20000 and 1 <= h <= 20000:
                rows.append((i, w, h, size))
        pos = i + 4
    return rows

def carve_jpegs(data: bytes):
    """Yield (start, blob) for every complete JPEG inside a byte buffer."""
    i = 0
    while True:
        s = data.find(JPEG_SIG, i)
        if s == -1:
            return
        e = data.find(b"\xff\xd9", s + 2)
        if e == -1:
            return
        yield s, data[s:e + 2]
        i = e + 2

def carve_pngs(data: bytes):
    """Yield (start, blob) for every complete PNG inside a byte buffer."""
    i = 0
    while True:
        s = data.find(PNG_SIG, i)
        if s == -1:
            return
        e = data.find(b"IEND", s + 8)
        if e == -1:
            return
        yield s, data[s:e + 8]
        i = e + 8

def ocr_image(tesseract, img: Path):
    """Run tesseract on a carved image and return its text."""
    try:
        r = subprocess.run([tesseract, str(img), "stdout"],
                           capture_output=True, timeout=120)
        return r.stdout.decode("utf-8", "replace")
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
FLAG_RE = re.compile(r"[Ff]lag[Yy]\{[0-9a-fA-F]{32}\}")

def normalize(text: str):
    return re.sub(r"\s+", "", text)

def exploit(folder: Path):
    tesseract = find_tesseract()
    if tesseract:
        ok(0.08, "tesseract found: %s" % tesseract)
    else:
        fail("tesseract NOT found - will carve the image and print its path")

    thumbs = sorted(folder.rglob("thumbcache_*.db"))
    if not thumbs:
        fail("no thumbcache_*.db under %s" % folder)
        return None
    ok(0.16, "thumbcache databases: %d" % len(thumbs))

    key = None
    with tempfile.TemporaryDirectory(prefix="phantom_carve_") as td:
        tmp = Path(td)
        n_carved = 0
        for db in thumbs:
            data = db.read_bytes()
            status(0.24, "parsing %s" % db.relative_to(folder))
            rows = parse_entries(data)
            if rows:
                for off, w, h, dsize in rows:
                    if not (w and h):
                        continue
                    print("   %s  w=%4d h=%4d data_size=%s"
                          % (db.relative_to(folder), w, h, dsize))
            for j_idx, (start, blob) in enumerate(carve_jpegs(data)):
                img = tmp / ("%s_%d_0.jpg" % (db.stem, start))
                img.write_bytes(blob)
                n_carved += 1
                if not tesseract:
                    continue
                text = ocr_image(tesseract, img)
                m = FLAG_RE.search(normalize(text))
                if m:
                    key = m.group(0)
                    print("   %s  <%s>  OCR: %s"
                          % (img.name, blob[:8].hex(" "), m.group(0)))
                    break
            for p_idx, (start, blob) in enumerate(carve_pngs(data)):
                img = tmp / ("%s_%d_1.png" % (db.stem, start))
                img.write_bytes(blob)
                n_carved += 1
                if not tesseract:
                    continue
                text = ocr_image(tesseract, img)
                m = FLAG_RE.search(normalize(text))
                if m:
                    key = m.group(0)
                    print("   %s  <%s>  OCR: %s"
                          % (img.name, blob[:8].hex(" "), m.group(0)))
                    break
            if key:
                break
        ok(0.52, "carved %d images from %d database(s)" % (n_carved, len(thumbs)))

        if not key:
            # keep the biggest carved jpeg for manual reading
            keep = None
            for p in sorted(tmp.glob("*.jpg"), key=lambda p: p.stat().st_size, reverse=True):
                keep = p
                break
            if keep is None:
                for p in sorted(tmp.glob("*.png"), key=lambda p: p.stat().st_size, reverse=True):
                    keep = p
                    break
            if keep:
                dst = folder / keep.name
                dst.write_bytes(keep.read_bytes())
                fail("no OCR hit - largest carved image saved to %s" % dst)
            return None
    return key

def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    ap = argparse.ArgumentParser(description="Phantom flag solver")
    ap.add_argument("folder", nargs="?", default=None, help="path to the challenge folder")
    args = ap.parse_args()
    if args.folder:
        folder = Path(args.folder)
    else:
        folder = Path(__file__).resolve().parent
    if not folder.is_dir():
        fail("cannot open %s" % folder)
        return
    status(0.04, "challenge folder %s" % folder)

    flag = exploit(folder)
    if not flag:
        return
    ok(0.72, "flag recovered: %s" % flag)

    status(0.80, "saving flag_from_phantom.txt")
    out = folder / "flag_from_phantom.txt"
    out.write_text(flag + "\n")
    ok(0.90, "saved to %s" % out)

    big_flag(flag, time.time() - t0, "thumbcache_1280.db @ 0x70 | OCR via tesseract")

if __name__ == "__main__":
    main()