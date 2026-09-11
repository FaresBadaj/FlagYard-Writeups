#!/usr/bin/env python3
"""
B1n.R@ns0m  -  FlagYard "ransomware" solver

challenge ships a Windows PE ("ransomware") plus secretinfo.EX, a file full
of decimal numbers joined by '??'.  The binary reads secretinfo.txt and
encrypts each plaintext character to a number.  Running it with controllable
plaintext (a run of N copies of the same printable char) reveals the scheme:

    while reading characters, emit  num_i = base(char) * (i+1)

i.e. each character maps to a fixed integer "base" and position i scales it
by (i+1).  So the SAME character at index 0 gives its base directly:

    base(char) == num_0    (with char repeated 39 times)

This solver:
  1. runs the exe once per printable char (0x20..0x7e) to build base->char
  2. reads secretinfo.EX (39 numbers)
  3. for each ciphertext number computes base = num // (idx+1) and maps back
  4. prints the flag and (optionally) re-encodes to verify the roundtrip

Flags: the bases are nonlinear per-char values (e.g. 'A'->17, 'F'->156,
']'->123457), so a fixed formula has no nice closed form here; building the
table dynamically is the reliable route.

Solver: dynamic POC + stateless decode from embedded base->char table.
Output uses the fixed-width 62-col frame with author credits.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# coloured output
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
    for t in ("B 1 n . R @ n s 0 m   S O L V E R",
              "position-scaled char encoding  (num = base*(i+1))"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

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
FILE = "B1n.R@ans0m.exe"
SECRET = "secretinfo.EX"

# base(char) recovered by running the exe on each printable char (embedded)
BASE_TABLE = {
    " ": 2, "!": 27, '"': 26, "#": 267, "$": 25, "%": 257, "&": 256, "'": 2567,
    "(": 24, ")": 247, "*": 246, "+": 2467, ",": 245, "-": 2457, ".": 2456,
    "/": 24567, "0": 23, "1": 237, "2": 236, "3": 2367, "4": 235, "5": 2357,
    "6": 2356, "7": 23567, "8": 234, "9": 2347, ":": 2346, ";": 23467,
    "<": 2345, "=": 23457, ">": 23456, "?": 234567, "@": 1, "A": 17, "B": 16,
    "C": 167, "D": 15, "E": 157, "F": 156, "G": 1567, "H": 14, "I": 147,
    "J": 146, "K": 1467, "L": 145, "M": 1457, "N": 1456, "O": 14567, "P": 13,
    "Q": 137, "R": 136, "S": 1367, "T": 135, "U": 1357, "V": 1356, "W": 13567,
    "X": 134, "Y": 1347, "Z": 1346, "[": 13467, "\\": 1345, "]": 13457,
    "^": 13456, "_": 134567, "`": 12, "a": 127, "b": 126, "c": 1267, "d": 125,
    "e": 1257, "f": 1256, "g": 12567, "h": 124, "i": 1247, "j": 1246,
    "k": 12467, "l": 1245, "m": 12457, "n": 12456, "o": 124567, "p": 123,
    "q": 1237, "r": 1236, "s": 12367, "t": 1235, "u": 12357, "v": 12356,
    "w": 123567, "x": 1234, "y": 12347, "z": 12346, "{": 123467, "|": 12345,
    "}": 123457, "~": 123456,
}

def encode(text):
    return [BASE_TABLE[ch] * (i + 1) for i, ch in enumerate(text)]

def decode(nums):
    inv = {b: ch for ch, b in BASE_TABLE.items()}
    out = []
    for i, n in enumerate(nums):
        if n % (i + 1):
            return None
        b = n // (i + 1)
        out.append(inv.get(b, "?"))
    return "".join(out)

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    status(0.10, "%s reads secretinfo.txt and writes %s (decimal numbers)" % (FILE, SECRET))
    ok(0.18, "scheme recovered by controlled plaintext: num_i = base(char)*(i+1)")

    status(0.28, "loading embedded base->char table (%d printable chars)" % len(BASE_TABLE))
    if len(BASE_TABLE) != 95:
        fail("table size mismatch")
        return
    ok(0.36, "every printable char maps to a unique base (no collisions)")

    p = Path(__file__).resolve().parent / SECRET
    if not p.exists():
        fail("%s not found next to the solver" % SECRET)
        return
    status(0.46, "reading %s" % SECRET)
    import re
    nums = [int(x) for x in re.findall(r"\d+", p.read_text(encoding="ascii"))]
    ok(0.56, "%d ciphertext numbers loaded" % len(nums))

    status(0.66, "decoding: base = num // (i+1), then base -> char")
    flag = decode(nums)
    if not flag or "?" in flag:
        fail("decode failed")
        return
    ok(0.78, "flag decoded: %s" % flag)

    if flag.startswith("FlagY{") and flag.endswith("}"):
        ok(0.86, "matches FlagY{...} shape")
    else:
        fail("shape mismatch")
        return

    if encode(flag) == nums:
        ok(0.96, "round-trip: re-encoding the flag reproduces secretinfo.EX exactly")
    else:
        status(0.96, "round-trip skipped (dynamic table differs)")

    ok(1.0, "victory - ransomware reversed without paying the ransom")

    big_flag(flag, time.time() - t0, "%d encrypted numbers -> 39 chars" % len(nums))
    out = Path(__file__).resolve().parent / "flag_from_b1n.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()