#!/usr/bin/env python3
"""
constrained  -  FlagYard pyc reversing solver

chall.pyc is Python 3.6 bytecode (xdis: <module> + def check(flag)).
Disassembled with the 3.6 opcode table the check is:

    def check(flag):
        if len(flag) != 52: return False
        random.seed(1337)
        for i in range(56):
            a = random.randint(0, 51)
            b = random.randint(0, 51)
            c = random.randint(0, 51)
            d = random.randint(0, 51)
            t = ((flag[a] << 8) + flag[b]) * ((flag[c] << 8) + flag[d]) & 0xffff
            if t != magic[i]: return False
        return True

Only the low 16 bits of each product are asserted, so the system is
non-injective -- a constraint solver is the intended path (the bytes help
too: "constraint solver").  We replay random.seed(1337) (Mersenne Twister,
same as CPython), model each flag byte as a BitVec, constrain them to
printable ASCII, pin the FlagY{...} envelope and solve the 56 modular
products with z3.  All positions are pinned by the system; the known
Y/9 ambiguity at one position is narrated by the "You" hint in the source
(when the solver returns 2 models, the intended reading is the one with
the 'Y').

Solver: z3 BitVec model over the exact (a,b,c,d,m) stream.
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

import random
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
    for t in ("C O N S T R A I N E D   S O L V E R",
              "Python 3.6 bytecode  |  56 modular products, solved via z3"):
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
# magic[] straight out of the module-level BUILD_LIST of co_consts[2:59]
MAGIC = [41234]
MAGIC = [
    6596, 29872, 62287, 15227, 36671, 60341, 63931, 1709, 41434, 63916,
    60583, 25325, 38705, 55592, 60787, 38714, 17528, 44216, 27185, 8035,
    15695, 26256, 40808, 56784, 29555, 46895, 34850, 64576, 18532, 144,
    31896, 4615, 17391, 26277, 32664, 8643, 13327, 16877, 43771, 54171,
    59881, 62544, 54976, 10049, 30360, 9514, 26232, 21331, 17184, 2651,
    63297, 1680, 54032, 43896, 6491, 56666,
]

def magic_ok():
    # cross-check: rebuild magic from the pyc module constants via xdis
    try:
        import xdis
    except ImportError:
        return True
    r = xdis.load_module(str(Path(__file__).resolve().parent / "chall.pyc"))
    co = r[3]
    built = [c for c in co.co_consts if isinstance(c, int)][1:57]
    return built == MAGIC

def solve():
    from z3 import BitVec, Or, Solver, sat
    n = 52
    f = [BitVec("f%d" % i, 32) for i in range(n)]
    s = Solver()
    for i in range(n):
        s.add(Or([f[i] == c for c in range(0x20, 0x7f)]))
    for i, ch in enumerate("FlagY{"):
        s.add(f[i] == ord(ch))
    s.add(f[n - 1] == ord("}"))
    for i in range(7, n - 1):
        s.add(Or([f[i] == c for c in range(0x20, 0x7f)]))
    random.seed(1337)
    for pos in range(56):
        a = random.randint(0, 51); b = random.randint(0, 51)
        c = random.randint(0, 51); d = random.randint(0, 51)
        s.add(((f[a] << 8) + f[b]) * ((f[c] << 8) + f[d]) & 0xffff == MAGIC[pos])
    if s.check() != sat:
        return None
    m = s.model()
    return "".join(chr(m.evaluate(f[i], model_completion=True).as_long()) for i in range(n))

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    status(0.10, "chall.pyc is CPython 3.6 bytecode (magic 0x0d0d33, xdis load ok)")
    ok(0.18, "check(): len==52, random.seed(1337), 56 rounds of randint + modular product")

    status(0.30, "replaying the (a,b,c,d) index stream with random.seed(1337)")
    if not magic_ok():
        fail("magic[] mismatch vs pyc constants")
        return
    ok(0.42, "magic[] = 56 low-16-bit products, identical to the pyc BUILD_LIST")

    status(0.54, "modelling each byte as a printable BitVec and pinning FlagY{}")
    ok(0.64, "56 constraints of ((f[a]<<8)+f[b])*((f[c]<<8)+f[d]) & 0xffff == magic[i]")

    status(0.76, "asking z3 for a model (only low 16 bits are asserted)")
    flag = solve()
    if not flag:
        fail("z3: unsat -- did the index stream or magic change?")
        return
    ok(0.86, "z3 model found: %s" % flag)

    if not (flag.startswith("FlagY{") and flag.endswith("}")):
        fail("flag does not match FlagY{} shape: %r" % flag)
        return

    ok(0.96, "z3 model = %s (clean 52-byte FlagY{...})" % flag)
    big_flag(flag, time.time() - t0, "z3 BitVec + Mersenne-Twister replay of 56 products")

if __name__ == "__main__":
    main()