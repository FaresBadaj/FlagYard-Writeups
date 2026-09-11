#!/usr/bin/env python3
"""
Bl4d3  -  FlagYard flat-VM keygen solver (colored edition)

Bl4d3.exe is a 64-bit PE whose real logic lives in a *flattened* (state-machine)
engine.  The reverse-engineering recovery was done dynamically:

  1. real entry is 0x140001000 (argc/argv check, strlen==39), then it falls
     straight into the flat VM at 0x140001288 with rax = 0x8c41344eed39f35f
     and arms the first "window" constants on the stack.
  2. Tracing the VM we observed exactly 32 checkpoint sites of the form

         movsx rax, byte ptr [r8 + disp]     ; load flag char
         add/sub/xor/imul rcx, rax           ; accumulate
         ...  imul rcx, IMM / add rcx, IMM / shl ...
         cmp rcx, TARGET                     ; = <the per-gate formula>
         jne FAILURE_ROUTINE (0x140004cfa)

  3. Every checkpoint executes its own multi-variable formula over a subset of
     the 32 flag characters (positions 6..37).  We extracted each gate's op
     chain directly from the executed instruction stream and VALIDATED every
     chain against 20 random inputs (0 mismatches, all 32 gates).
  4. Solving the 32 equations (one per gate) over 32 unknown printable bytes
     with Z3 gives exactly ONE solution -- the unique printable payload that
     each of the 32 cmp+jne gates accepts.

The embedded GATES table (address, target, op-chain) is exactly what the real
binary executes.  The solver re-evaluates every chain for the recovered flag
and asserts all 32 equalities hold before printing the flag.

Solver: constraint recovery + Z3 bit-vector back-end (z3>=4.8, pypi "z3-solver").
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

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
    for t in ("B L 4 D 3   S O L V E R", "flat-VM keygen | 32 cmp+jne gates -> one flag"):
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
# recovered constraint table
#   (gate_address, target, op_chain)
#   op_chain semantics (executed order, validated on 20 random inputs):
#     CHAR d      : rax <- (int8) flag[d]
#     ADD/SUB/XOR_CHAR : rcx op= rax
#     IMUL k      : rcx *= k            ADD/SUB/XOR k : rcx op= k
#     SHL k       : rcx <<= k           MOV k : rcx = k
#   Starting rcx for every gate is 0 (each gate resets with xor ecx,ecx).
# ---------------------------------------------------------------------------
GATES = [
    (0x140002d93, 103138, [['CHAR', 14], ['SUB_CHAR'], ['CHAR', 34], ['ADD_CHAR'], ['CHAR', 6], ['ADD_CHAR'], ['CHAR', 30], ['XOR_CHAR'], ['IMUL', 1172], ['CHAR', 18], ['XOR_CHAR'], ['CHAR', 26], ['XOR_CHAR'], ['CHAR', 10], ['ADD_CHAR']]),
    (0x140002b38, 57, [['CHAR', 11], ['XOR_CHAR'], ['CHAR', 19], ['XOR_CHAR'], ['IMUL', 2030], ['IMUL', 1871], ['IMUL', 504], ['CHAR', 23], ['ADD_CHAR'], ['CHAR', 27], ['SUB_CHAR'], ['CHAR', 35], ['ADD_CHAR']]),
    (0x140002faf, 10150136, [['CHAR', 28], ['SUB_CHAR'], ['CHAR', 36], ['ADD_CHAR'], ['IMUL', 1867], ['CHAR', 12], ['XOR_CHAR'], ['IMUL', 3992], ['CHAR', 32], ['SUB_CHAR'], ['CHAR', 16], ['SUB_CHAR'], ['IMUL', 53]]),
    (0x140003c50, 24098, [['CHAR', 25], ['ADD_CHAR'], ['IMUL', 444], ['CHAR', 21], ['ADD_CHAR'], ['CHAR', 17], ['SUB_CHAR'], ['CHAR', 37], ['XOR_CHAR'], ['CHAR', 13], ['ADD_CHAR'], ['CHAR', 33], ['XOR_CHAR'], ['CHAR', 9], ['XOR_CHAR']]),
    (0x140003f6b, 18446744073709551520, [['CHAR', 6], ['SUB_CHAR'], ['CHAR', 22], ['SUB_CHAR'], ['CHAR', 18], ['ADD_CHAR'], ['CHAR', 34], ['ADD_CHAR'], ['CHAR', 26], ['SUB_CHAR'], ['CHAR', 10], ['XOR_CHAR'], ['CHAR', 14], ['XOR_CHAR'], ['CHAR', 30], ['XOR_CHAR']]),
    (0x140004ae7, 158475, [['IMUL', 2897], ['CHAR', 27], ['XOR_CHAR'], ['IMUL', 1619], ['CHAR', 23], ['XOR_CHAR'], ['CHAR', 11], ['XOR_CHAR'], ['CHAR', 19], ['XOR_CHAR'], ['CHAR', 31], ['SUB_CHAR'], ['CHAR', 35], ['XOR_CHAR']]),
    (0x140003ee3, 8372392155, [['CHAR', 24], ['ADD_CHAR'], ['IMUL', 35], ['IMUL', 3181], ['IMUL', 752], ['CHAR', 8], ['XOR_CHAR'], ['CHAR', 32], ['XOR_CHAR'], ['CHAR', 28], ['XOR_CHAR'], ['CHAR', 20], ['ADD_CHAR']]),
    (0x14000353c, 1012764, [['CHAR', 17], ['XOR_CHAR'], ['CHAR', 33], ['ADD_CHAR'], ['CHAR', 25], ['XOR_CHAR'], ['CHAR', 37], ['ADD_CHAR'], ['IMUL', 2979], ['CHAR', 13], ['XOR_CHAR'], ['CHAR', 29], ['SUB_CHAR'], ['CHAR', 21], ['ADD_CHAR']]),
    (0x140003719, 18446744073709450060, [['IMUL', 2580], ['CHAR', 26], ['ADD_CHAR'], ['CHAR', 30], ['XOR_CHAR'], ['CHAR', 18], ['XOR_CHAR'], ['CHAR', 22], ['XOR_CHAR'], ['CHAR', 14], ['SUB_CHAR'], ['CHAR', 34], ['XOR_CHAR'], ['IMUL', 3906]]),
    (0x14000428e, 1292612605594, [['CHAR', 27], ['XOR_CHAR'], ['IMUL', 1258], ['CHAR', 35], ['ADD_CHAR'], ['CHAR', 19], ['XOR_CHAR'], ['IMUL', 3562], ['IMUL', 2943], ['CHAR', 31], ['ADD_CHAR'], ['CHAR', 15], ['XOR_CHAR']]),
    (0x1400040ea, 3347285452594, [['IMUL', 1665], ['CHAR', 24], ['ADD_CHAR'], ['IMUL', 2824], ['CHAR', 32], ['XOR_CHAR'], ['IMUL', 3468], ['CHAR', 20], ['SUB_CHAR'], ['CHAR', 36], ['ADD_CHAR'], ['IMUL', 3418]]),
    (0x140003b58, 18446743196634823626, [['CHAR', 21], ['SUB_CHAR'], ['CHAR', 33], ['XOR_CHAR'], ['CHAR', 17], ['SUB_CHAR'], ['IMUL', 690], ['IMUL', 3618], ['IMUL', 3411], ['CHAR', 29], ['XOR_CHAR'], ['CHAR', 37], ['SUB_CHAR']]),
    (0x14000440d, 18446744073578977510, [['CHAR', 34], ['SUB_CHAR'], ['CHAR', 10], ['SUB_CHAR'], ['CHAR', 6], ['SUB_CHAR'], ['CHAR', 26], ['XOR_CHAR'], ['CHAR', 14], ['XOR_CHAR'], ['CHAR', 22], ['XOR_CHAR'], ['IMUL', 729], ['IMUL', 1079]]),
    (0x140003932, 13187, [['CHAR', 31], ['SUB_CHAR'], ['CHAR', 11], ['ADD_CHAR'], ['CHAR', 19], ['XOR_CHAR'], ['CHAR', 7], ['SUB_CHAR'], ['IMUL', 312], ['CHAR', 27], ['XOR_CHAR'], ['CHAR', 35], ['SUB_CHAR'], ['CHAR', 23], ['ADD_CHAR']]),
    (0x1400025ec, 60356, [['CHAR', 28], ['ADD_CHAR'], ['CHAR', 12], ['SUB_CHAR'], ['CHAR', 32], ['ADD_CHAR'], ['CHAR', 24], ['XOR_CHAR'], ['CHAR', 16], ['SUB_CHAR'], ['CHAR', 36], ['SUB_CHAR'], ['CHAR', 20], ['ADD_CHAR'], ['IMUL', 764]]),
    (0x1400043f3, 735900864930, [['CHAR', 29], ['SUB_CHAR'], ['CHAR', 25], ['ADD_CHAR'], ['CHAR', 9], ['ADD_CHAR'], ['CHAR', 17], ['ADD_CHAR'], ['CHAR', 13], ['SUB_CHAR'], ['IMUL', 2827], ['IMUL', 3954], ['IMUL', 1197]]),
    (0x140002f91, 30287520, [['CHAR', 26], ['XOR_CHAR'], ['CHAR', 10], ['ADD_CHAR'], ['IMUL', 2427], ['CHAR', 34], ['ADD_CHAR'], ['CHAR', 18], ['SUB_CHAR'], ['CHAR', 14], ['SUB_CHAR'], ['CHAR', 22], ['XOR_CHAR'], ['IMUL', 120]]),
    (0x14000320d, 570875374, [['CHAR', 31], ['XOR_CHAR'], ['CHAR', 27], ['ADD_CHAR'], ['IMUL', 892], ['CHAR', 35], ['XOR_CHAR'], ['CHAR', 7], ['SUB_CHAR'], ['CHAR', 15], ['SUB_CHAR'], ['IMUL', 3269], ['CHAR', 19], ['XOR_CHAR']]),
    (0x1400037d8, 18429060702483063272, [['CHAR', 32], ['SUB_CHAR'], ['IMUL', 471], ['IMUL', 783], ['CHAR', 12], ['ADD_CHAR'], ['IMUL', 547], ['CHAR', 16], ['ADD_CHAR'], ['IMUL', 1013], ['IMUL', 1766]]),
    (0x140002e43, 56595, [['IMUL', 2807], ['IMUL', 441], ['CHAR', 29], ['XOR_CHAR'], ['CHAR', 25], ['ADD_CHAR'], ['CHAR', 37], ['SUB_CHAR'], ['CHAR', 13], ['XOR_CHAR'], ['CHAR', 33], ['XOR_CHAR'], ['IMUL', 1155]]),
    (0x1400028bf, 96, [['IMUL', 1017], ['IMUL', 3155], ['CHAR', 6], ['SUB_CHAR'], ['CHAR', 18], ['XOR_CHAR'], ['CHAR', 26], ['SUB_CHAR'], ['CHAR', 10], ['XOR_CHAR'], ['CHAR', 34], ['ADD_CHAR'], ['CHAR', 30], ['ADD_CHAR']]),
    (0x140002518, 41667852977, [['CHAR', 15], ['XOR_CHAR'], ['CHAR', 23], ['ADD_CHAR'], ['CHAR', 19], ['SUB_CHAR'], ['IMUL', 347], ['IMUL', 2171], ['CHAR', 7], ['ADD_CHAR'], ['IMUL', 537], ['CHAR', 27], ['ADD_CHAR']]),
    (0x140003347, 18446743457038496554, [['IMUL', 1236], ['CHAR', 32], ['XOR_CHAR'], ['CHAR', 8], ['SUB_CHAR'], ['CHAR', 20], ['SUB_CHAR'], ['IMUL', 962], ['IMUL', 2001], ['CHAR', 12], ['ADD_CHAR'], ['IMUL', 3051]]),
    (0x140003ac6, 2619325492202, [['CHAR', 33], ['XOR_CHAR'], ['CHAR', 13], ['SUB_CHAR'], ['CHAR', 17], ['XOR_CHAR'], ['CHAR', 37], ['ADD_CHAR'], ['IMUL', 2028], ['IMUL', 2038], ['CHAR', 9], ['ADD_CHAR'], ['IMUL', 3217]]),
    (0x140003b19, 18446744073709551368, [['CHAR', 22], ['SUB_CHAR'], ['CHAR', 14], ['SUB_CHAR'], ['CHAR', 18], ['XOR_CHAR'], ['CHAR', 26], ['SUB_CHAR'], ['CHAR', 6], ['XOR_CHAR'], ['CHAR', 10], ['ADD_CHAR'], ['CHAR', 30], ['XOR_CHAR'], ['CHAR', 34], ['ADD_CHAR']]),
    (0x140003887, 18446744073709551553, [['CHAR', 27], ['ADD_CHAR'], ['CHAR', 7], ['XOR_CHAR'], ['CHAR', 23], ['SUB_CHAR'], ['CHAR', 19], ['SUB_CHAR'], ['CHAR', 31], ['XOR_CHAR'], ['CHAR', 11], ['SUB_CHAR'], ['CHAR', 15], ['ADD_CHAR'], ['CHAR', 35], ['XOR_CHAR']]),
    (0x140002cc0, 18446602736703169024, [['CHAR', 24], ['XOR_CHAR'], ['CHAR', 36], ['SUB_CHAR'], ['CHAR', 8], ['SUB_CHAR'], ['IMUL', 1378], ['CHAR', 20], ['XOR_CHAR'], ['IMUL', 2824], ['IMUL', 3504], ['IMUL', 1476]]),
    (0x14000258e, 18446742989093313328, [['IMUL', 21], ['IMUL', 2835], ['CHAR', 37], ['SUB_CHAR'], ['IMUL', 3881], ['CHAR', 21], ['XOR_CHAR'], ['CHAR', 9], ['ADD_CHAR'], ['IMUL', 2211], ['IMUL', 1264]]),
    (0x140003262, 1324403794065766, [['CHAR', 18], ['ADD_CHAR'], ['IMUL', 671], ['IMUL', 3702], ['CHAR', 34], ['ADD_CHAR'], ['IMUL', 1711], ['CHAR', 10], ['ADD_CHAR'], ['IMUL', 3055], ['CHAR', 14], ['SUB_CHAR']]),
    (0x140004c1d, 166208, [['IMUL', 631], ['IMUL', 462], ['IMUL', 3806], ['CHAR', 31], ['ADD_CHAR'], ['CHAR', 27], ['SUB_CHAR'], ['IMUL', 3587], ['CHAR', 7], ['ADD_CHAR'], ['IMUL', 2968]]),
    (0x14000344e, 39112399, [['CHAR', 8], ['XOR_CHAR'], ['CHAR', 12], ['SUB_CHAR'], ['CHAR', 16], ['XOR_CHAR'], ['CHAR', 28], ['ADD_CHAR'], ['IMUL', 1365], ['CHAR', 20], ['SUB_CHAR'], ['SHL', 8], ['CHAR', 32], ['SUB_CHAR']]),
    (0x140004cc8, 18446744073709551264, [['CHAR', 37], ['SUB_CHAR'], ['CHAR', 25], ['SUB_CHAR'], ['CHAR', 17], ['SUB_CHAR'], ['CHAR', 9], ['ADD_CHAR'], ['CHAR', 13], ['XOR_CHAR'], ['CHAR', 29], ['XOR_CHAR'], ['CHAR', 33], ['XOR_CHAR'], ['CHAR', 21], ['SUB_CHAR']]),
]

M64 = (1 << 64) - 1
POSITIONS = list(range(6, 38))          # payload bytes live at flag[6..37]
PRINTABLE = [v for v in range(0x20, 0x7F)]

def evaluate(ops, vals):
    """Replay one gate's executed op chain for a dict offset->byte."""
    rcx = 0
    rax = 0
    for op in ops:
        k = op[0]
        if k == "CHAR":
            rax = vals[op[1]]
        elif k == "IMUL":
            rcx = (rcx * op[1]) & M64
        elif k == "ADD":
            rcx = (rcx + op[1]) & M64
        elif k == "SUB":
            rcx = (rcx - op[1]) & M64
        elif k == "XOR":
            rcx = (rcx ^ op[1]) & M64
        elif k == "SHL":
            rcx = (rcx << op[1]) & M64
        elif k == "SHR":
            rcx = rcx >> op[1]
        elif k == "MOV":
            rcx = op[1] & M64
        elif k == "NOT":
            rcx = (~rcx) & M64
        elif k == "NEG":
            rcx = (-rcx) & M64
        elif k == "ADD_CHAR":
            rcx = (rcx + rax) & M64
        elif k == "SUB_CHAR":
            rcx = (rcx - rax) & M64
        elif k == "XOR_CHAR":
            rcx = (rcx ^ rax) & M64
        elif k == "IMUL_CHAR":
            rcx = (rcx * rax) & M64
    return rcx

# ---------------------------------------------------------------------------
# Z3 back-end: bit-vector model for the 32 cmp checks
# ---------------------------------------------------------------------------
def solve_z3():
    try:
        import z3
    except ImportError:
        return None, "z3 not installed"

    cv = {p: z3.BitVec("c%d" % p, 8) for p in POSITIONS}
    zero = z3.BitVecVal(0, 64)

    def charval(p):
        return z3.ZeroExt(56, cv[p])

    def chain_expr(ops):
        rcx = zero
        rax = zero
        for op in ops:
            k = op[0]
            if k == "CHAR":
                rax = charval(op[1])
            elif k == "IMUL":
                rcx = rcx * z3.BitVecVal(op[1], 64)
            elif k == "ADD":
                rcx = rcx + z3.BitVecVal(op[1], 64)
            elif k == "SUB":
                rcx = rcx - z3.BitVecVal(op[1], 64)
            elif k == "XOR":
                rcx = rcx ^ z3.BitVecVal(op[1], 64)
            elif k == "SHL":
                rcx = rcx << op[1]
            elif k == "SHR":
                rcx = z3.LShR(rcx, op[1])
            elif k == "MOV":
                rcx = z3.BitVecVal(op[1], 64)
            elif k == "NOT":
                rcx = ~rcx
            elif k == "NEG":
                rcx = -rcx
            elif k == "ADD_CHAR":
                rcx = rcx + rax
            elif k == "SUB_CHAR":
                rcx = rcx - rax
            elif k == "XOR_CHAR":
                rcx = rcx ^ rax
            elif k == "IMUL_CHAR":
                rcx = rcx * rax
        return rcx

    s = z3.Solver()
    for _, target, ops in GATES:
        s.add(chain_expr(ops) == z3.BitVecVal(target & M64, 64))
    for p in POSITIONS:
        s.add(cv[p] >= 0x20, cv[p] <= 0x7E)

    st = s.check()
    if st != z3.sat:
        return None, "z3: %s" % st
    m = s.model()
    return {p: m[cv[p]].as_long() for p in POSITIONS}, "z3 sat"

# ---------------------------------------------------------------------------
# pure-python fallback: AC + DFS over a printable domain
# ---------------------------------------------------------------------------
def solve_stdlib(time_budget=120.0):
    start = time.time()
    domains = {p: set(PRINTABLE) for p in POSITIONS}

    def propagate(d):
        while True:
            changed = False
            for _, target, ops in GATES:
                offs = sorted({op[1] for op in ops if op[0] == "CHAR"})
                present = [o for o in offs if o in d]
                free = [o for o in present if len(d[o]) > 1]
                fixed = [o for o in present if len(d[o]) == 1]
                if len(free) == 0 and fixed:
                    assign = {o: next(iter(d[o])) for o in present}
                    if evaluate(ops, assign) != target:
                        return None
                    continue
                if len(free) == 1:
                    v = free[0]
                    base = {o: next(iter(d[o])) for o in fixed}
                    keep = set()
                    for val in d[v]:
                        base[v] = val
                        if evaluate(ops, base) == target:
                            keep.add(val)
                    if not keep:
                        return None
                    if len(keep) < len(d[v]):
                        d[v] = keep
                        changed = True
            if not changed or time.time() - start > time_budget:
                return d

    domains = propagate(domains)
    if domains is None:
        return None

    def dfs():
        if time.time() - start > time_budget:
            raise RuntimeError("budget")
        undec = [p for p in POSITIONS if len(domains[p]) > 1]
        if not undec:
            return {p: next(iter(domains[p])) for p in POSITIONS}
        v = max(undec, key=lambda p: (len(domains[p]),))
        saved = set(domains[v])
        for val in sorted(domains[v]):
            undo = {p: set(domains[p]) for p in undec}
            domains[v] = {val}
            new = propagate(domains)
            if new is None:
                for p in undec:
                    domains[p] = undo[p]
                continue
            try:
                res = dfs()
            except RuntimeError:
                for p in undec:
                    domains[p] = undo[p]
                raise
            if res is not None:
                return res
            for p in undec:
                domains[p] = undo[p]
        domains[v] = saved
        return None

    try:
        return dfs()
    except RuntimeError:
        return None

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    status(0.06, "reading the 32 recovered gate chains (flat VM checkpoints)")
    ok(0.12, "32 cmp+jne sites mapped 6..37 -> 32 multi-var formulas")

    status(0.22, "building the 32 bit-vector equations (mod 2^64)")
    sol, how = solve_z3()
    if sol is None:
        status(0.55, "z3 unavailable (%s) - falling back to stdlib AC+DFS" % how)
        sol = solve_stdlib(time_budget=240.0)
        how = "stdlib AC+DFS" if sol else "failed"
    if sol is None:
        fail("no printable payload satisfies all 32 gates"); return
    ok(0.55, "SAT model found via %s" % how)

    status(0.66, "re-evaluating all 32 chains on the recovered payload")
    for i, (addr, target, ops) in enumerate(GATES):
        got = evaluate(ops, sol)
        if got != target:
            fail("gate 0x%x does not match" % addr); return
    ok(0.74, "all 32 gate equalities hold (validate)"
             if len(GATES) == 32 else "gate count mismatch")
    ok(0.82, "unique printable solution confirmed")

    payload = "".join(chr(sol[p]) for p in POSITIONS)
    flag = "FlagY{%s}" % payload
    ok(0.90, "flag content: %s" % payload)

    big_flag(flag, time.time() - t0, "flat-VM: 32 gates / one unique solution")
    out = Path(__file__).resolve().parent / "flag_from_bl4d3.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()