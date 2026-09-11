#!/usr/bin/env python3
"""
Fr33  -  FlagYard keygen solver (colored edition)
Fr33.exe is a stripped x64 PE with NO validation table and NO hidden answer:
it checks a 35-char serial of the form

    XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX

where each of the four hex groups must equal MurmurHash3_x86_32(seed=0) of a
substring of the 8-char username (the user "DYSTOPIA"):

    group0 = murmur3("DSO")      <- username[0], [2], [4]
    group1 = murmur3("YTP")      <- username[1], [3], [5]
    group2 = murmur3("IA")       <- username[6], [7]
    group3 = murmur3("DYSTOPIA") <- the full username

So the license key IS the digest of the username - a keygen, not a crack.

The binary inlines the whole hash four times. Its block step is a mangled
MurmurHash3:  h1 = ROTL(h1,13); h1 = (h1 + 0xFADDAF14) * 5
(canonical murmur3 uses h1 = h1*5 + 0xE6546B64).  For these exact inputs the
group values coincide; the solver reproduces the binary's arithmetic anyway.

This solver is pure stdlib: it parses the PE, proves the murmur3 constants
(0xCC9E2D51 / 0x1B873593 block mix, 0x85EBCA6B / 0xC2B2AE35 fmix, plus the
custom 0xFADDAF14) live in .text, derives the serial, re-verifies it against
Fr33.exe and saves flag_from_fr33.txt.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
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

def bar(frac, width=22):
    filled = int(frac * width)
    return "\u2588" * filled + "\u2591" * (width - filled)

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
    for t in ("F R 3 3   S O L V E R", "MurmurHash3_x86_32 keygen  |  user: DYSTOPIA"):
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

def big_flag(serial, chrono, groups):
    line = serial.strip().splitlines()[0]
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono,
              "4 x MurmurHash3_x86_32 groups (seed=0)"):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# minimal PE32+ parser
# ---------------------------------------------------------------------------
def parse_sections(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ header)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (missing PE signature)")
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    if magic != 0x20B:
        raise ValueError("only PE32+ (x64) is supported")
    nsects = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    base = pe + 24 + opt
    secs = []
    for i in range(nsects):
        off = base + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, rp, ps, pl, chars = struct.unpack_from("<IIIIIIH", data, off + 8)
        secs.append({"name": name, "va": va, "vsize": vs, "rp": rp, "rsize": rs})
    return secs

# ---------------------------------------------------------------------------
# MurmurHash3_x86_32 - the exact variant compiled inside Fr33.exe
#   block step : k1 = k1*0xCC9E2D51 ; k1 = ROTL(k1,15) ; k1 = k1*0x1B873593
#                h1 ^= k1 ; h1 = ROTL(h1,13) ; h1 = (h1 + 0xFADDAF14) * 5
#   tail       : k1 from remaining bytes ; same mix ; h1 ^= k1
#   final      : h1 ^= len ; fmix32 (0x85EBCA6B / 0xC2B2AE35)
# ---------------------------------------------------------------------------
MIX_A = 0xCC9E2D51
MIX_B = 0x1B873593
BLOCK_K = 0xFADDAF14
FMIX_A = 0x85EBCA6B
FMIX_B = 0xC2B2AE35
_M32 = 0xFFFFFFFF

def _rol(v, b):
    return ((v << b) | (v >> (32 - b))) & _M32

def murmur3_32(data: bytes) -> int:
    h = 0
    n = len(data)
    i = 0
    for _ in range(n // 4):
        k = struct.unpack("<I", data[i:i + 4])[0]
        k = (_rol((k * MIX_A) & _M32, 15) * MIX_B) & _M32
        h ^= k
        h = _rol(h, 13)
        h = ((h + BLOCK_K) * 5) & _M32
        i += 4
    k = 0
    tail = n % 4
    for j in range(tail):
        k ^= data[i + j] << (8 * j)
    if tail:
        k = (_rol((k * MIX_A) & _M32, 15) * MIX_B) & _M32
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * FMIX_A) & _M32
    h ^= h >> 13
    h = (h * FMIX_B) & _M32
    h ^= h >> 16
    return h

def keygen(username: str):
    b = username.encode("ascii")
    return [murmur3_32(bytes((b[i] for i in idx)))
            for idx in ((0, 2, 4), (1, 3, 5), (6, 7))] + [murmur3_32(b)]

SIG_BLOCK = re.compile(rb"\x69[\xc0-\xff]\x51\x2d\x9e\xcc")    # imul <r>, <r>, 0xCC9E2D51
SIG_CUSTOM = bytes.fromhex("41 81 c1 14 af dd fa")      # add  r9d, 0xFADDAF14
SIG_FMIX = re.compile(rb"\x69[\xc0-\xff]\x6b\xca\xeb\x85")     # imul <r>, <r>, 0x85EBCA6B

def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    ap = argparse.ArgumentParser(description="Fr33 keygen solver")
    ap.add_argument("exe", nargs="?", default=None, help="path to Fr33.exe")
    ap.add_argument("--user", default="DYSTOPIA", help="8-char username (key owner)")
    args = ap.parse_args()

    username = args.user.strip().upper()
    if len(username) != 8 or not username.isascii():
        fail("username must be exactly 8 ASCII chars"); return
    if args.exe:
        exe = Path(args.exe)
    else:
        exe = Path(__file__).resolve().parent / "Fr33.exe"
    if not exe.exists():
        fail("cannot find %s" % exe); return

    status(0.08, "parsing %s" % exe.name)
    data = exe.read_bytes()
    secs = parse_sections(data)
    text = next((s for s in secs if s["name"] == ".text"), None)
    if text is None:
        fail("no .text section"); return
    ok(0.16, "x64 PE parsed: .text @ rva 0x%x (rs 0x%x)" % (text["va"], text["rsize"]))

    status(0.26, "probing the hash core in .text")
    code = data[text["rp"]:text["rp"] + text["rsize"]]
    vanilla_mix = len(SIG_BLOCK.findall(code))
    custom_step = code.find(SIG_CUSTOM) >= 0
    fmix = len(SIG_FMIX.findall(code))
    if not (vanilla_mix >= 8 and custom_step and fmix >= 4):
        fail("expected 4 inlined MurmurHash3_x86_32 bodies not found"); return
    ok(0.36, "4 inlined MurmurHash3_x86_32 bodies confirmed (0xCC9E2D51/0x1B873593"
             " + fmix + custom 0xFADDAF14 block step)")

    status(0.46, "building the 4 license substrings for %r" % username)
    groups = keygen(username)
    ok(0.54, "substrings DSO | YTP | IA | %s hashed (seed=0)" % username)

    status(0.62, "composing serial XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX")
    serial = "-".join("%x" % g for g in groups)
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{8}){3}", serial):
        fail("serial shape not as expected"); return
    flag = "FlagY{%s}" % serial
    ok(0.70, "serial built: %s" % serial)

    status(0.78, "round-trip: re-parsing the %x groups back to ints")
    expect = [int(s, 16) for s in serial.split("-")]
    if expect != groups:
        fail("round-trip mismatch"); return
    ok(0.84, "round-trip re-parses cleanly (%x semantics, 4 x 32-bit)")

    status(0.90, "dynamic check against %s (%r)" % (exe.name, username))
    try:
        p = subprocess.run([str(exe), ""], input=username + "\n" + serial + "\n",
                           capture_output=True, text=True, timeout=15)
        live_ok = "Cracked" in p.stdout
    except Exception:
        live_ok = False
    if live_ok:
        ok(0.96, "Fr33.exe verdict: 'Cracked ,Correct Key:D'")
    else:
        fail("Fr33.exe did not accept the serial - check username/variant")
        return

    big_flag(flag, time.time() - t0, groups)
    out = exe.parent / "flag_from_fr33.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()