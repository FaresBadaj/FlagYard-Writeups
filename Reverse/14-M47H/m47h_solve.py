#!/usr/bin/env python3
"""
M47H  -  FlagYard Rust reversing solver

M47H.exe is a Rust (cargo) x64 PE that reads one line from stdin, requires
exactly 39 characters, then checks:

    for i in 0..39:
        if (input[i] * 52) % 123 != target[i]: fail

The 39 target bytes live in .rdata at 0x402020.  Because 123 and 52 are
coprime, each target byte has a unique residue class mod 123:

    input[i] = target[i] * invert(52, mod 123)   (mod 123)

and we pick the printable solution (0x20..0x7e).  All 39 positions fall
uniquely in the printable band and match the FlagY{...} shape.

Verified: piping the recovered flag into the exe prints "Correct flag".

Solver: hard-coded target table + closed-form modular inverse.
Output uses a fixed-width 62-column frame with author credits.
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
    for t in ("M 4 7 H   S O L V E R", "Rust x64 PE  |  modulo-123 cryptosystem (c*52 % 123 == t)"):
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
FILE = "M47H.exe"

# 39 target bytes extracted from .rdata @ 0x402020 (lea r9,[rip+0xcff] @ 0x40131a)
TARGET = bytes([
    0x49, 0x51, 0x01, 0x43, 0x4d, 0x00, 0x66, 0x53, 0x32, 0x0f,
    0x22, 0x0f, 0x58, 0x24, 0x11, 0x45, 0x58, 0x69, 0x69, 0x58,
    0x24, 0x58, 0x45, 0x69, 0x01, 0x24, 0x22, 0x58, 0x0c, 0x0f,
    0x66, 0x66, 0x01, 0x32, 0x66, 0x53, 0x66, 0x32, 0x68,
])

def modular_roots(target):
    inv = pow(52, -1, 123)
    roots = []
    for t in target:
        base = (t * inv) % 123
        cands = [c for c in range(0x20, 0x7f) if (c * 52) % 123 == t]
        roots.append((base, cands))
    return roots

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    status(0.10, "M47H.exe is a Rust x64 PE (MZ/\u2026, .pdata/.reloc, Rust error tables)")
    ok(0.22, "found check loop @0x40130f-0x401347: len==39, then (c*52)%123 == t")

    status(0.34, "recovering target[] from .rdata @ 0x402020")
    if len(TARGET) != 39:
        fail("target table has %d bytes, expected 39" % len(TARGET))
        return
    ok(0.46, "target[] = %s" % TARGET.hex())

    status(0.58, "gcd(52,123)==1 \u2192 modular inverse exists; digitising residues")
    inv = pow(52, -1, 123)
    roots = modular_roots(TARGET)
    if any(not c for _, c in roots):
        fail("some byte has no printable solution")
        return
    ok(0.68, "invert(52,123)=%d \u2014 each residue has 1 printable char" % inv)

    status(0.78, "reconstructing the 39 printable characters")
    chars = [chr(c[0]) for _, c in roots]
    flag = "".join(chars)
    ok(0.86, "flag = %s" % flag)

    if not (flag.startswith("FlagY{") and flag.endswith("}")):
        fail("flag does not match FlagY{} shape: %r" % flag)
        return
    ok(0.94, "matches FlagY{...} \u2014 %d clean hex chars in payload" % (len(flag) - 7))

    # verify against the real binary if present
    exe = Path(__file__).resolve().parent / FILE
    verified = False
    if exe.exists():
        try:
            import subprocess
            r = subprocess.run([str(exe)], input=(flag + "\r\n").encode(),
                               capture_output=True, timeout=15)
            verified = (b"Correct flag" in r.stdout or b"Correct flag" in r.stderr)
        except Exception:
            verified = False
    if verified:
        ok(1.0, "live check: piping flag into %s prints 'Correct flag'" % FILE)
    else:
        status(1.0, "live check skipped (exe unavailable), static reconstruction only")

    big_flag(flag, time.time() - t0, "%s modular check (c*52 mod 123)" % FILE)
    out = Path(__file__).resolve().parent / "flag_from_m47h.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()