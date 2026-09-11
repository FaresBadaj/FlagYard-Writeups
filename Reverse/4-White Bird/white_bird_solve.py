#!/usr/bin/env python3
"""
White Bird  -  FlagYard reversing solver (colored edition)
A tiny stripped x64 PE whose checker (0x1400012b1) validates the flag
per-character against a 40-dword expected table baked inline into .text
(40 x `mov dword ptr [rbp + i*4 - 0x79], imm`).

The per-char gate is an invertible affine map over GF(2^32) flavored with
FNV-1a constants:

    edx = ((flag[i] ^ 0x811c9dc5) * 0x1000193) ^ 0x13333337
    cmp edx, table[i]                       ; i in 0..0x27

Because the map is bijective, the flag is:

    c = ((table[i] ^ 0x13333337) * inv(0x1000193 mod 2^32)) ^ 0x811c9dc5   (low byte)

The 40th entry decodes to 0x00 (39 characters + NUL terminator).

Success / failure strings live encrypted in .data (XOR 0x44):
"Enter the flag:", "Correct Flag :D", "Wrong Flag :(".

This solver self-extracts everything from White Bird.exe (no external
libraries, no disassembler). Pure Python + stdlib only.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# colored output (same design as the hasher / giyu / cryp70 solvers)
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
    for t in ("W H I T E   B I R D   S O L V E R",
              "FNV-1a per-char gate  |  inline 40-dword table"):
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

def big_flag(flag, chrono):
    line = flag.strip().splitlines()[0]
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, "40 dwords lifted, inverted & re-verified"):
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

FNV_BASIS = 0x811C9DC5
FNV_PRIME = 0x1000193
MYSTERY = 0x13333337
INV_PRIME = pow(FNV_PRIME, -1, 1 << 32)

def extract_gate(table_code: bytes):
    """Locate the checker loop and the 40-entry inline table in .text bytes."""
    # movzx ecx, byte [rbp+rax+0x27]; xor ecx, 0x811C9DC5
    # imul edx, ecx, 0x1000193; xor edx, 0x13333337
    # cmp edx, [rbp+rax*4-0x79]; jne
    sig = bytes.fromhex("0f b6 4c 05 27 81 f1 c5 9d 1c 81"
                        "69 d1 93 01 00 01 81 f2 37 33 33 13"
                        "3b 54 85 87 75")
    a = table_code.find(sig)
    if a < 0:
        raise ValueError("checker signature not found")
    # the table: 40 x 'mov dword ptr [rbp+disp8], imm32' with disp == -0x79 + 4*i
    valid = set((0x87 + 4*i) & 0xFF for i in range(40))
    table = {}
    for m in re.finditer(rb"\xc7\x45(.)(....)", table_code):
        d = m.group(1)[0]
        if d in valid:
            table[((d - 0x87) & 0xFF) // 4] = struct.unpack("<I", m.group(2))[0]
    if len(table) != 40:
        raise ValueError("expected table incomplete: got %d/40" % len(table))
    return table

def forward(c: int) -> int:
    ecx = c ^ FNV_BASIS
    edx = (ecx * FNV_PRIME) & 0xFFFFFFFF
    return edx ^ MYSTERY

def decode(e: int) -> int:
    c = (((((e ^ MYSTERY) & 0xFFFFFFFF) * INV_PRIME) & 0xFFFFFFFF) ^ FNV_BASIS)
    return c & 0xFF

def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    ap = argparse.ArgumentParser(description="White Bird solver")
    ap.add_argument("exe", nargs="?", default=None, help="path to White Bird.exe")
    args = ap.parse_args()

    if args.exe:
        exe = Path(args.exe)
    else:
        exe = Path(__file__).resolve().parent / "White Bird.exe"
    if not exe.exists():
        fail("cannot find %s" % exe)
        return

    status(0.08, "parsing %s" % exe.name)
    data = exe.read_bytes()
    secs = parse_sections(data)
    text = next((s for s in secs if s["name"] == ".text"), None)
    if text is None:
        fail("no .text section"); return
    ok(0.18, "x64 PE parsed: .text @ rva 0x%x (rs 0x%x)" % (text["va"], text["rsize"]))

    status(0.30, "locating the per-char gate in .text")
    table_code = data[text["rp"]:text["rp"] + text["rsize"]]
    try:
        table = extract_gate(table_code)
    except ValueError as e:
        fail(str(e)); return
    ok(0.45, "checker gate confirmed: xor ^0x811C9DC5 -> imul 0x1000193 -> xor ^0x13333337")

    status(0.55, "lifting the 40-dword expected table (rbp-0x79 .. +0x23)")
    ok(0.62, "40 dwords recovered from the inline mov block")

    status(0.72, "inverting FNV-1a affine map per byte (GF(2^32))")
    inv = decode   # alias
    chars = [inv(table[i]) for i in sorted(table)]
    if chars[-1] != 0:
        fail("expected NUL terminator at entry 39"); return
    flag = "".join(chr(c) for c in chars[:-1])
    ok(0.82, "affine inverse applied; 39 chars + NUL decoded")

    status(0.88, "re-verifying round-trip (flag[i] -> gate -> table[i])")
    for i in sorted(table):
        if forward(chars[i]) != table[i]:
            fail("round-trip mismatch at entry %d" % i); return
    ok(0.95, "round-trip re-encodes cleanly across all 40 entries")

    big_flag(flag, time.time() - t0)
    out = exe.parent / "flag_from_white_bird.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()