#!/usr/bin/env python3
"""
Lost Flag  -  FlagYard Windows PE reversing solver

`lost.exe` is a MinGW x86-64 PE.  It reads a line, then (indirectly through
the CRT) validates it.  The interesting part is that the expected secret
is NOT stored as plain text -- it sits in the `.data` section as a sparse
XOR buffer, one character per 8 bytes:

    flag[i] = data[0x5200 + i*8] ^ 0x77

Every 8-byte cell follows the pattern  [ C^0x77, 0, 0, 0, 0x77, 0, 0, 0 ]
so the object can rebuild the expected phrase on the fly and strncmp()-it
against your input.  The "0x77" at index 4 of each cell is a constant XOR
marker which is never used -- the payload byte is index 0 of each cell.

This solver parses the PE header to locate `.data` (file offset 0x5200,
size 0x200, image base 0x140000000), uncovers the sparse-XOR bytes and
returns the flag.  Output uses the fixed-width 62-column FlagYard frame.
"""
from __future__ import annotations

import re
import struct
import sys
import time
from pathlib import Path

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
    for t in ("L O S T   F L A G   S O L V E R",
              "MinGW PE  |  sparse-XOR .data buffer, one char per 8 bytes"):
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
# PE parsing for lost.exe
# ---------------------------------------------------------------------------
def pe_sections(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt
    secs = []
    for i in range(nsec):
        o = sec_off + 40 * i
        name = data[o:o + 8].rstrip(b"\0")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        secs.append({"name": name.decode("latin1"), "va": va,
                     "vsize": vsize, "rsize": rsize, "roff": roff})
    return secs

def extract_flag(target):
    data = Path(target).read_bytes()
    secs = pe_sections(data)
    dot = next(s for s in secs if s["name"] == ".data")
    raw = data[dot["roff"]:dot["roff"] + dot["rsize"]]

    # every 8-byte cell: [ flag_char ^ 0x77, 0,0,0, 0x77, 0,0,0 ]
    cells = len(raw) // 8
    chars = []
    for i in range(cells):
        c = raw[i * 8] ^ 0x77
        chars.append(chr(c))
        if c == 0x7D:  # '}' -- end of the flag body
            break
    flag = "".join(chars)
    return flag, dot

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    target = sys.argv[1] if len(sys.argv) > 1 else None
    here = Path(__file__).resolve().parent / "lost.exe"
    if target is None and here.exists():
        target = str(here)
    if target is None:
        fail("usage: lostflag_solve.py [path/to/lost.exe]")
        return

    status(0.15, "target: %s (MinGW x86-64 PE)" % target)
    data = Path(target).read_bytes()
    ok(0.28, "PE signature + section table parsed (%d sections)" % len(pe_sections(data)))

    flag, dot = extract_flag(target)
    ok(0.55, ".data at file offset 0x%x (size 0x%x) -- sparse-XOR buffer" %
       (dot["roff"], dot["rsize"]))
    ok(0.72, "cell layout [ C^0x77, 0,0,0, 0x77, 0,0,0 ] -> flag[i] = data[0x%x + i*8] ^ 0x77" %
       dot["roff"])

    if not (flag.startswith("FlagY{") and flag.endswith("}")):
        fail("recovered data does not look like a flag: %r" % flag)
        return
    ok(0.88, "sparse-XOR buffer yields a clean FlagY{...} (%d bytes)" % len(flag))

    ok(0.97, "flag = %s" % flag)
    big_flag(flag, time.time() - t0, ".data stride-XOR (0x77) of the MinGW PE")

if __name__ == "__main__":
    main()