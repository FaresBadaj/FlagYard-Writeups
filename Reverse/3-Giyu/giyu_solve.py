#!/usr/bin/env python3
"""
Giyu  -  FlagYard reversing solver (colored edition)
A straight-line "byte-equation" flag checker hidden behind an opaque-predicate
obfuscator in the custom `.0Dev` section of Giyu.exe.

The real validator (main:0xcb75) loads all 47 flag bytes into scratch slots,
then runs a single unrolled block of byte equations (xor/add/sub/or/and).
Each satisfied equation adds +1 to a counter and the flag is correct iff the
final counter equals 47 (`cmp r15d, 0x2f`).

The solver therefore:
  1. parses the PE and disassembles the `.0Dev` checker with capstone,
  2. re-walks the instruction stream symbolically (z3 BitVec-8 per flag byte)
     and records each final `cmp ...; sete` equation,
  3. asks z3 for printable inputs of the form FlagY{...} satisfying all 47,
  4. prefers the candidate whose body is 40 hex chars (the intended flag).

Requires:  pip install capstone z3-solver
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import time
from pathlib import Path

import z3

# ---------------------------------------------------------------------------
# colored output (same design as the hasher / cryp70 solvers)
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
    print("  \u2551              G I Y U   S O L V E R              \u2551")
    print("  \u2551  47 byte-equations | .0Dev obfuscator | Reversing \u2551")
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
    for s in ("elapsed %.1f s" % chrono, "47 equations + z3 were enough"):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# section lookup (minimal PE32+ parser, no pip extra)
# ---------------------------------------------------------------------------
def find_section(data: bytes, target: str):
    if data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ header)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (missing PE signature)")
    if struct.unpack_from("<H", data, pe + 24)[0] != 0x20B:
        raise ValueError("only PE32+ (x64) is supported")
    nsecs = struct.unpack_from("<H", data, pe + 6)[0]
    secoff = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    for i in range(nsecs):
        off = secoff + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        va, vsize, rawptr, rawsize = struct.unpack_from("<IIII", data, off + 8)
        if name == target:
            return va, vsize, rawptr, rawsize
    raise ValueError("section %r not found" % target)

IMAGE_BASE = 0x140000000
CHECKER_VA0 = 0x14000cb75      # checker() entry
CHECKER_BODY = 0x14000cbb2     # first real instruction (after opaque chain)
CHECKER_END  = 0x14000d587     # ret

# ---------------------------------------------------------------------------
# symbolic re-walk of the checker : rebuild the 47 byte-equations
# ---------------------------------------------------------------------------
REGS32 = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15']
REGB8 = ['al','cl','dl','bl','sil','dil','bpl','r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b']
REGD32 = ['eax','ebx','ecx','edx','esi','edi','ebp','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d']

def _repl(x):
    if x.startswith(('r8','r9','r10','r11','r12','r13','r14','r15')) and x.endswith('d'):
        return x[:-1]
    return {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi',
            'ebp':'rbp'}.get(x, x)

def build_constraints(rows, N=53):
    """Walk the disassembled checker lines and return (cond_list, counter_expr)."""
    flag = [z3.BitVec(f'f{i}', 8) for i in range(N)]
    regs = {r: z3.BitVecVal(0, 32) for r in REGS32}
    mem8 = {}
    mem32 = {}
    stack = []
    flagstate = [None, None]
    constraints = []
    final_at_cmp = None

    def low8(reg32):
        return z3.Extract(7, 0, regs[reg32])

    def set_low8(reg32, val8):
        regs[reg32] = z3.Concat(z3.Extract(31, 8, regs[reg32]), val8)

    def reg8_src(r):
        m = re.match(r'(r8|r9|r10|r11|r12|r13|r14|r15)b$', r)
        if m:
            return m.group(1)
        return {'al':'rax','cl':'rcx','dl':'rdx','bl':'rbx','sil':'rsi','dil':'rdi','bpl':'rbp'}[r]

    def parse_operand(op):
        op = op.strip()
        if op == 'dword ptr [rsp]':
            return ('mem32', 0)
        m = re.match(r'byte ptr \[rsp \+ (0x[0-9a-fA-F]+|[0-9]+)\]', op)
        if m:
            x = m.group(1)
            return ('mem8', int(x, 16) if x.startswith('0x') else int(x))
        m = re.match(r'byte ptr \[rcx(?: \+ (0x[0-9a-fA-F]+|[0-9]+))?\]', op)
        if m:
            x = m.group(1)
            idx = int(x, 16) if (x and x.startswith('0x')) else (int(x) if x else 0)
            return ('flag', idx)
        m = re.match(r'(imm )?(0x[0-9a-fA-F]+|0[0-9]+|[0-9]+)', op)
        if m:
            return ('imm', int(m.group(2), 0))
        if op in REGS32 or op in REGB8 or op in REGD32:
            return ('reg', op)
        raise ValueError('operand: ' + op)

    def src_expr8(o):
        if o[0] == 'mem8':
            if o[1] not in mem8:
                raise KeyError('undef mem8[%#x]' % o[1])
            return mem8[o[1]]
        if o[0] == 'flag':
            return flag[o[1]]
        if o[0] == 'reg':
            if o[1] in REGB8:
                return low8(reg8_src(o[1]))
            if o[1] in REGD32:
                return low8(_repl(o[1]))
            if o[1] in REGS32:
                return low8(o[1])
        return None

    for (a, mnem, ops) in rows:
        if mnem in ('pushf','popf','ret','int3','nop','jmp','jne','je'):
            continue
        if mnem == 'push':
            stack.append(regs[_repl(ops)])
            continue
        if mnem == 'pop':
            regs[_repl(ops)] = stack.pop()
            continue
        parts = [p.strip() for p in ops.split(',')]
        dst, src = parts[0], parts[1:]
        o1 = parse_operand(dst)

        if mnem == 'mov':
            o2 = parse_operand(src[0])
            if o1[0] == 'mem8':
                mem8[o1[1]] = src_expr8(o2)
            elif o1[0] == 'mem32':
                mem32[0] = regs[_repl(o2[1])]
            else:
                r = dst
                if r in REGD32:
                    reg32 = _repl(r)
                    if o2[0] == 'reg':
                        if o2[1] in REGS32:
                            regs[reg32] = regs[o2[1]]
                        elif o2[1] in REGD32:
                            regs[reg32] = regs[_repl(o2[1])]
                        elif o2[1] in REGB8:
                            regs[reg32] = z3.Concat(z3.BitVecVal(0,24), z3.Extract(7,0,regs[reg8_src(o2[1])]))
                    elif o2[0] == 'imm':
                        regs[reg32] = z3.BitVecVal(o2[1] & 0xffffffff, 32)
                    elif o2[0] == 'mem8':
                        regs[reg32] = z3.Concat(z3.BitVecVal(0,24), mem8[o2[1]])
                    elif o2[0] == 'mem32':
                        regs[reg32] = mem32[0]
                    else:
                        raise ValueError(('mov reg32', ops))
                elif r in REGB8:
                    set_low8(reg8_src(r), src_expr8(o2))
                elif r == 'rsp':
                    regs['rsp'] = z3.BitVecVal(0x38, 32)
                else:
                    raise ValueError(('mov dst??', ops))
            continue

        if mnem == 'movzx':
            o2 = parse_operand(src[0])
            regs[_repl(dst)] = z3.Concat(z3.BitVecVal(0, 24), src_expr8(o2))
            continue

        if mnem == 'lea':
            regs[_repl(dst)] = regs['r10'] + regs['rsi']
            continue

        if mnem == 'cmp':
            if a == 0x14000d56c:
                final_at_cmp = regs['r15']
            o2 = parse_operand(src[0])
            if o1[0] == 'mem8':
                e = z3.ZeroExt(24, mem8[o1[1]])
            elif o1[0] == 'reg':
                if o1[1] in REGB8:
                    e = z3.ZeroExt(24, low8(reg8_src(o1[1])))
                else:
                    e = regs[_repl(o1[1]) if o1[1] in REGD32 else o1[1]]
            else:
                e = mem32[0]
            flagstate = (e, o2[1]) if o2[0] == 'imm' else (e, o2)
            continue

        if mnem in ('sete','setne'):
            if flagstate[1] is None:
                raise ValueError('sete without immediate cmp')
            cond = (flagstate[0] == flagstate[1])
            if mnem == 'setne':
                cond = z3.Not(cond)
            set_low8(reg8_src(o1[1]), z3.If(cond, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8)))
            constraints.append(cond)
            continue

        if mnem in ('xor','add','sub','or','and'):
            if o1[0] == 'mem32':
                o2 = parse_operand(src[0])
                if mnem == 'add':
                    mem32[0] = mem32[0] + regs[_repl(o2[1])]
                else:
                    mem32[0] = mem32[0] - regs[_repl(o2[1])]
                continue
            if o1[0] == 'reg' and o1[1] in REGB8:
                o2 = parse_operand(src[0])
                v = src_expr8(o2)
                cur = low8(reg8_src(o1[1]))
                if mnem == 'xor':  nv = cur ^ v
                elif mnem == 'add': nv = cur + v
                elif mnem == 'sub': nv = cur - v
                elif mnem == 'or':  nv = cur | v
                else:               nv = cur & v
                set_low8(reg8_src(o1[1]), z3.Extract(7, 0, nv))
                continue
            if o1[0] == 'reg':
                o2 = parse_operand(src[0])
                reg32 = _repl(o1[1]) if o1[1] in REGD32 else o1[1]
                rv = z3.BitVecVal(o2[1] & 0xffffffff, 32) if o2[0] == 'imm' else regs[_repl(o2[1]) if o2[1] in REGD32 else o2[1]]
                if mnem == 'add':  regs[reg32] = regs[reg32] + rv
                elif mnem == 'sub': regs[reg32] = regs[reg32] - rv
                elif mnem == 'xor': regs[reg32] = regs[reg32] ^ rv
                elif mnem == 'or':  regs[reg32] = regs[reg32] | rv
                else:               regs[reg32] = regs[reg32] & rv
                continue
            raise ValueError(('arith', ops))

        if mnem == 'not':
            o1 = parse_operand(dst)
            if o1[1] in REGB8:
                set_low8(reg8_src(o1[1]), ~low8(reg8_src(o1[1])))
            else:
                regs[_repl(o1[1]) if o1[1] in REGD32 else o1[1]] = ~regs[_repl(o1[1]) if o1[1] in REGD32 else o1[1]]
            continue

        raise ValueError(('UNHANDLED', mnem, ops))

    if final_at_cmp is None:
        raise ValueError('never reached the final `cmp r15d, 0x2f`')
    return constraints, final_at_cmp, flag

def solve_flag(counter_expr, flag, limit=8):
    """Enumerate printable FlagY{...} inputs whose counter equals 47."""
    s = z3.Solver()
    for f in flag:
        s.add(z3.And(f >= 0x20, f <= 0x7e))
    for idx, ch in [(0,0x46),(1,0x6c),(2,0x61),(3,0x67),(4,0x59),(5,0x7b)]:
        s.add(flag[idx] == ch)
    s.add(flag[46] == 0x7d)
    s.add(counter_expr == 47)

    hits = []
    while hits.__len__() < limit and str(s.check()) == 'sat':
        mm = s.model()
        sol = bytes(mm[flag[i]].as_long() for i in range(47))
        hits.append(sol)
        s.add(z3.Or([flag[i] != mm[flag[i]].as_long() for i in range(47)]))
    return hits

def pick_main(hits):
    """The intended flag body is a 40-hex-char (SHA-1-like) string."""
    for h in hits:
        body = h[6:46]
        if len(body) == 40 and all(chr(b) in '0123456789abcdefABCDEF' for b in body):
            return h
    return hits[0] if hits else None

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    enable_vt()
    banner()

    parser = argparse.ArgumentParser(
        description="Solve FlagYard Giyu (47 byte-equations hidden in .0Dev)")
    parser.add_argument("exe", type=Path, nargs="?", default=None,
                        help="path to Giyu.exe (default: next to this script)")
    args = parser.parse_args()

    exe = args.exe or (Path(__file__).resolve().parent / "Giyu.exe")
    print("  %s[ target : %s%s%s ]%s\n" % (C.GRAY, C.CYAN, exe.name, C.RESET, C.RESET))
    t0 = time.time()

    try:
        import capstone
    except ImportError:
        fail("this solver needs capstone + z3-solver:  pip install capstone z3-solver")
        return

    try:
        data = exe.read_bytes()
    except Exception as exc:
        fail("cannot read binary: %s" % exc); return
    ok(0.06, "binary loaded (%d bytes)" % len(data))

    try:
        va, vsize, rawptr, rawsize = find_section(data, ".0Dev")
    except Exception as exc:
        fail(str(exc)); return
    ok(0.14, ".0Dev custom code section at VA +%#x (%#x bytes)" % (va, vsize))

    code = data[rawptr:rawptr + rawsize]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True

    rows = []
    total = len(code)
    tick = total // 40 or 1
    for insn in md.disasm(code, IMAGE_BASE + va):
        if CHECKER_BODY <= insn.address <= CHECKER_END:
            rows.append((insn.address, insn.mnemonic, insn.op_str))
        if rows.__len__() % 40 == 0:
            frac = 0.14 + 0.30 * (insn.address - (IMAGE_BASE + va)) / float(total)
            sys.stdout.write("\r%s  %s%5.1f%%%s %s%s  %s   " %
                             (C.CYAN + bar(min(frac, 0.999)) + C.RESET, C.DIM, min(frac, 99.99),
                              C.DIM, C.GRAY, "walking .0Dev code", C.RESET))
            sys.stdout.flush()
    print()
    ok(0.30, "checker disassembled: %d instructions (%#x .. %#x)"
       % (len(rows), CHECKER_BODY - IMAGE_BASE, CHECKER_END - IMAGE_BASE))

    try:
        constraints, counter, flag_vars = build_constraints(rows)
    except Exception as exc:
        fail("symbolic re-walk failed: %s" % exc); return
    ok(0.45, "%d byte-equations lifted into z3 (one per cmp/sete)" % len(constraints))
    ok(0.60, "final gate: counter == 47  (cmp r15d, 0x2f)")

    hits = solve_flag(counter, flag_vars)
    if not hits:
        fail("z3 reports no printable candidate -> my equations are wrong"); return
    if len(hits) > 1:
        status(0.95, "%d printable preimages pass the counter gate (or/and is lossy)" % len(hits),
               icon="\u26a0", color=C.YELLOW)
    chosen = pick_main(hits)
    if chosen is None:
        fail("no 40-hex candidate found"); return
    flag = chosen.decode("latin1")

    ok(0.98, "unique 40-hex preimage selected as the intended flag")

    big_flag(flag, time.time() - t0)
    out = Path(exe.parent) / "flag_from_giyu.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))


if __name__ == "__main__":
    main()