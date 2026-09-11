#!/usr/bin/env python3
"""
Shuffler  -  FlagYard xor+shuffle decrypt solver (colored edition)

chall.py encrypts a 40-character message as follows:

    data = input() + "A"                  # 40 chars total
    for i in range(40):
        encrypted += chr(ord(data[i]) ^ (i << 3))   # per-index XOR
    simp = [encrypted[i:i+8] for i in range(0, 40, 8)]   # 5 blocks of 8
    random.shuffle(simp)                  # block permutation (5! = 120)
    open("flag.enc", "w").write("".join(simp))

There is also a hint guard inside the challenge: if the first 39 chars MD5
to ac9dc5b77c199d4737f5010da0fcdd24 the author prints "You got a hidden
gem".  So the recovered plaintext is exactly:

    FlagY{bc22719f0816578efad8d19496531512}

Recovery: read flag.enc as text (UTF-8; XOR of ASCII ^ (i<<3) yields code
points above 127), split into the same 8-char blocks, and try all 120
block permutations.  For a candidate order undo the XOR (again per-index
key (i<<3)) and keep the permutation that satisfies all four constraints:

  1. length stays 40
  2. the payload ends with the appended "A"  -> data[-1] == "A"
  3. plaintext looks like a flag  -> "FlagY{...}"
  4. md5(data[:39]) == ac9dc5b77c199d4737f5010da0fcdd24

Exactly one permutation survives (4,3,2,0,1).

Solver: pure Python (itertools).
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

import hashlib
import itertools
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
    for t in ("S H U F F L E R   S O L V E R", "xor (i<<3) + 5! block shuffle -> 1 flag"):
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
# constants (names/values taken from chall.py itself)
# ---------------------------------------------------------------------------
FILE = "flag.enc"
MD5_HINT = "ac9dc5b77c199d4737f5010da0fcdd24"
TOTAL = 40
BLOCK = 8
INDEX_KEY = lambda i: i << 3   # xor key for position i

def decrypt_with_order(blocks, perm):
    """Undo (xor then shufffe) for a given 0-based block permutation."""
    enc = []
    for bi in perm:
        enc += blocks[bi]
    assert len(enc) == TOTAL
    return "".join(chr(ord(c) ^ INDEX_KEY(i)) for i, c in enumerate(enc))

def looks_like_flag(s):
    return (
        len(s) == TOTAL
        and s[-1] == "A"                # trailing token appended by encryptor
        and s[:6] == "FlagY{"
        and s[-2] == "}"
        and hashlib.md5(s[:39].encode()).hexdigest() == MD5_HINT
    )

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    p = Path(__file__).resolve().parent / FILE
    if not p.exists():
        fail("%s not found next to the solver (%s)" % (FILE, p))
        return
    status(0.05, "reading %s as UTF-8 text" % p.name)
    data = p.read_text(encoding="utf-8")
    chars = list(data)
    if len(chars) != TOTAL:
        fail("expected %d chars, got %d" % (TOTAL, len(chars)))
        return
    # all code points must be > 127 because ascii ^ (i<<3) >= 128 in the
    # observed region -- the file would otherwise have been ASCII
    ok(0.15, "%d chars read; %d non-ASCII code points" % (TOTAL, sum(1 for c in chars if ord(c) > 127)))

    status(0.25, "splitting into %d blocks of %d" % (TOTAL // BLOCK, BLOCK))
    blocks = [chars[i:i + BLOCK] for i in range(0, TOTAL, BLOCK)]
    ok(0.30, "5 ciphertext blocks ready (order in file: block0..block4)")

    status(0.40, "trying all %d block permutations (5! = 120)" % (TOTAL // BLOCK))
    for perm in itertools.permutations(range(TOTAL // BLOCK)):
        plain = decrypt_with_order(blocks, perm)
        if looks_like_flag(plain):
            ok(0.55, "constraints hit on permutation %s" % (perm,))
            flag = plain[:39]
            ok(0.65, "md5(%s) == %s" % (flag[:12] + "...", MD5_HINT))
            payload = flag[len("FlagY{"):-1]
            if len(payload) == 32 and all(ch in "0123456789abcdef" for ch in payload):
                ok(0.80, "payload %s is 32 clean hex chars" % payload)
                status(0.90, "replaying decrypt in the verified order")
                ok(1.0, "decrypt verified (xor key i<<3, block order %s)" % (perm,))
                big_flag(flag, time.time() - t0, "xor + 5-block shuffle: 1 permutation survives")
                out = Path(__file__).resolve().parent / "flag_from_shuffler.txt"
                out.write_text(flag + "\n", encoding="utf-8")
                print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))
                return
    fail("no permutation satisfied the constraints")

if __name__ == "__main__":
    main()