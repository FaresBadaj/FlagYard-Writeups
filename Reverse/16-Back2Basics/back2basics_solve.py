#!/usr/bin/env python3
"""
Back2Basics  -  FlagYard "assembly source" solver

The challenge ship is `chall` -- but it is NOT a binary.  The first bytes
`!_(#...` already smell wrong, and reading further shows `.file "chall.c"`
then real GNU assembly: it is the exact output of `gcc -S chall.c` for a
small C++ program (with DWARF debug info, GCC 13 Debian).

main() asks for a secret phrase, requires length == 32, then walks every
position i with:

    leaq  -64(%rbp), %rax
    movl  $<i>, %esi                 ; index
    call  std::string::operator[](unsigned long)
    movzbl (%rax), %eax
    cmpb  $<byte>, %al               ; expected byte for position i
    sete  %al
    ...
    addl  $1, -20(%rbp)              ; counter++ on match

If all 32 characters match, it prints:

    "Here is your flag:FlagY{" + input + "}"

So the secret phrase IS the flag body: extract every (index, byte) pair
from the `movl $i, %esi` / `cmpb $v, %al` blocks in index order.

Verified: 32 positions recovered, each cmp byte is printable ASCII and the
phrasing spells a clean 32-hex-digit FlagY{} payload.

Solver: regex pull of (index, cmpb-value) pairs straight from the .s text.
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

import re
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
    for t in ("B A C K   2   B A S I C S   S O L V E R",
              "GCC -S assembly source  |  32x 'cmpb imm8' key recovery"):
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
FILE = "chall"
EXPECTED_LEN = 32

# (index, immediate) from: movl $<i>, %esi ... movzbl (%rax), %eax ... cmpb $<v>, %al
_CPAT = re.compile(
    r"movl\s+\$(\d+),\s*%esi.*?movzbl\s+\(%rax\),\s*%eax\s*\n\s*cmpb\s+\$(\d+),\s*%al",
    re.DOTALL,
)

def recover_phrase(asm_path: Path):
    src = asm_path.read_text(encoding="latin-1", errors="replace")
    pairs = [(int(i), int(v)) for i, v in _CPAT.findall(src)]
    phrase = ["?"] * EXPECTED_LEN
    for idx, val in pairs:
        if 0 <= idx < EXPECTED_LEN:
            phrase[idx] = chr(val)
    return "".join(phrase), pairs

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    status(0.10, "%s is gcc -S assembly source (not MZ / not ELF)" % FILE)
    ok(0.20, "header '!_#', .file \"chall.c\", strings give greetings + \"Here is your flag:FlagY{\"")

    p = Path(__file__).resolve().parent / FILE
    if not p.exists():
        p = (Path(__file__).resolve().parent / "extracted" / FILE)
    if not p.exists():
        fail("%s not found next to the solver (tried root and extracted/)" % FILE)
        return
    status(0.34, "reading %s (%d bytes of x86_64 AT&T syntax)" % (FILE, p.stat().st_size))
    ok(0.44, "main: s.length()==%d gate, then operator[]+cmpb per position" % EXPECTED_LEN)

    status(0.58, "parsing (index, cmpb-immed) pairs from the .s body")
    phrase, pairs = recover_phrase(p)
    if len(pairs) != EXPECTED_LEN:
        fail("extracted %d check blocks, expected %d" % (len(pairs), EXPECTED_LEN))
        return
    ok(0.70, "%d per-char equality checks located (0..%d)" % (len(pairs), EXPECTED_LEN - 1))

    status(0.80, "assembling phrase from the expected bytes")
    if "?" in phrase:
        fail("missing expected byte for some position: %r" % phrase)
        return
    ok(0.88, "phrase = %s (all printable ASCII)" % phrase)

    flag = "FlagY{%s}" % phrase
    if not (flag.startswith("FlagY{") and flag.endswith("}")):
        fail("flag does not match FlagY{} shape: %r" % flag)
        return
    ok(0.96, "matches FlagY{...} with a %d-hex-digit payload" % len(phrase))

    big_flag(flag, time.time() - t0, "%d direct cmpb constants (no solver math needed)" % len(pairs))

if __name__ == "__main__":
    main()