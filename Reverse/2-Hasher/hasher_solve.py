#!/usr/bin/env python3
"""
Hasher  -  FlagYard reversing solver (colored edition)
Bob Jenkins "one-at-a-time" hash, applied to each flag byte *individually*
(1-byte NUL-terminated string, seed 0), compared against a 39-dword table
baked inline into main().

The solver self-extracts the 39 dwords straight from Hasher.exe (no external
library, no disassembler), builds a 256-entry LUT of hash(byte), and decodes
every slot. Pure Python + stdlib only.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# colored output (same design as the cryp70 / mra / NOSJ / phone_book solvers)
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
    print("  \u2551             H A S H E R   S O L V E R           \u2551")
    print("  \u2551  Bob Jenkins one-at-a-time, per-char | Reversing \u2551")
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
    for s in ("elapsed %.1f s" % chrono, "%d slots decoded" % len(flag)):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# core solver
# ---------------------------------------------------------------------------
EXPECTED_LEN = 0x27            # cmp rax, 0x27  -> "Wrong length!"
TABLE_RVA_LO = 0x1139          # first   mov dword ptr [rsp + 0x20], imm
TABLE_RVA_HI = 0x1262 + 8      # last    mov dword ptr [rbp - 0x48], imm (+1 instr)


def find_section(data: bytes, target: str):
    """Parse the PE headers and return (rva, vsize, rawptr, rawsize) of a section."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ header)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (missing PE signature)")
    opt_magic = struct.unpack_from("<H", data, pe + 24)[0]  # Magic at PE+0x18
    if opt_magic != 0x20B:
        raise ValueError("only PE32+ (x64) is supported")
    nsecs = struct.unpack_from("<H", data, pe + 6)[0]
    secoff = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    for i in range(nsecs):
        off = secoff + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        if name == target:
            return va, vsize, rawptr, rawsize
    raise ValueError("section %r not found" % target)


def extract_table(data: bytes) -> list:
    """Grab the 39 dwords from the inline stores of main(), in load order."""
    va, _, rawptr, rawsize = find_section(data, ".text")
    lo = rawptr + (TABLE_RVA_LO - va)
    hi = rawptr + (TABLE_RVA_HI - va)
    seg = data[lo:hi]

    table = []
    i = 0
    while i < len(seg) - 7:
        # C7 44 24 disp8  imm32   -> mov dword ptr [rsp + disp8], imm32
        # C7 45 disp8      imm32   -> mov dword ptr [rbp +/- disp8], imm32
        if seg[i] == 0xC7 and seg[i + 1] == 0x44 and seg[i + 2] == 0x24:
            table.append(struct.unpack_from("<I", seg, i + 4)[0])
            i += 7
        elif seg[i] == 0xC7 and seg[i + 1] == 0x45:
            table.append(struct.unpack_from("<I", seg, i + 3)[0])
            i += 7
        else:
            i += 1
    if len(table) != EXPECTED_LEN:
        raise ValueError("expected %d table dwords, extracted %d" % (EXPECTED_LEN, len(table)))
    return table


def jenkins(byte: int) -> int:
    """Bob Jenkins one-at-a-time over a single byte, seed 0. All 32-bit."""
    a = byte & 0xFFFFFFFF
    a = (a ^ ((a << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 1)) & 0xFFFFFFFF
    a = (a ^ ((a << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 5)) & 0xFFFFFFFF
    a = (a ^ ((a << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 17)) & 0xFFFFFFFF
    a = (a ^ ((a << 25) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 6)) & 0xFFFFFFFF
    return a


def solve(table: list, progress=None) -> str:
    lut = {}
    for c in range(256):
        lut.setdefault(jenkins(c), []).append(c)

    chars = []
    total = len(table)
    for i, want in enumerate(table):
        if progress is not None:
            progress((i + 1) / total, "slot %02d/%02d  hash=%08x" % (i + 1, total, want))
        cands = lut.get(want, [])
        if len(cands) != 1:
            raise ValueError("slot %d has %d candidates (ambiguous)" % (i, len(cands)))
        chars.append(chr(cands[0]))
    return "".join(chars)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    enable_vt()
    banner()

    parser = argparse.ArgumentParser(
        description="Solve FlagYard Hasher (Bob Jenkins one-at-a-time, per-char)")
    parser.add_argument("exe", type=Path, nargs="?", default=None,
                        help="path to Hasher.exe (default: next to this script)")
    args = parser.parse_args()

    exe = args.exe or (Path(__file__).resolve().parent / "Hasher.exe")
    print("  %s[ target : %s%s%s ]%s\n" % (C.GRAY, C.CYAN, exe.name, C.RESET, C.RESET))
    t0 = time.time()

    try:
        data = exe.read_bytes()
    except Exception as exc:
        fail("cannot read binary: %s" % exc); return
    ok(0.08, "binary loaded (%d bytes)" % len(data))

    try:
        table = extract_table(data)
    except Exception as exc:
        fail(str(exc)); return
    ok(0.3, "hash table self-extracted from .text (%d dwords)" % len(table))

    print()
    sys.stdout.write("\r%s  %s%5.1f%%%s %s  " % (C.CYAN + bar(0, 22) + C.RESET,
                     C.DIM, 0.0, C.RESET, C.GRAY + "decoding 39 slots" + C.RESET))
    sys.stdout.flush()

    done = [0.0]

    def progress(frac, label):
        sys.stdout.write("\r%s  %s%5.1f%%%s %s%s  %s   " %
                         (C.CYAN + bar(frac, 22) + C.RESET, C.DIM, frac * 100.0,
                          C.DIM, C.GRAY, label, C.RESET))
        sys.stdout.flush()
        done[0] = frac

    try:
        flag = solve(table, progress=progress)
    except Exception as exc:
        print()
        fail(str(exc)); return
    print()
    ok(0.98, "all %d slots decoded unambiguously (re-verified H(c)==table[i])" % len(flag))

    expected = len("FlagY{" + "a" * 32 + "}")
    if len(flag) != EXPECTED_LEN:
        fail("decoded length %d != expected %d" % (len(flag), EXPECTED_LEN)); return

    big_flag(flag, time.time() - t0)
    out = Path(exe.parent) / "flag_from_hasher.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))


if __name__ == "__main__":
    main()