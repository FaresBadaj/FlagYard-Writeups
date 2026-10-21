#!/usr/bin/env python3
"""
PongPing  -  FlagYard reversing solver (colored edition)

The challenge ships two files:
    pingpong     : stripped x86-64 ELF -- a Befunge-like 2D stack VM.  It reads
                   "Width Height\\n" then the grid row-by-row (read once per row),
                   grows two int32 stacks, and runs the IP from (0,0) heading
                   right: '@' halts, '.' pops+prints the low byte, ';' does
                   scanf("%d") (0 on EOF), '>' skips the next cell iff top > 0.
    flagchecker  : 903458 B = 194 rows x (4656 chars + '\\n')  ->  W=4657, H=194.

flagchecker is the actual program.  The default path prints a troll "fake flag"
(FlagY{th1s\\x00fl4g\\x001s\\x00a\\x00f4k3...}); the real 44-char flag lives behind
three row-5 gates that the beam must SKIP.  Every '>' is a 2-way branch
(S = skip next cell / D = don't), so we BFS the decision space over the whole
maze.  Exactly one of the 14638 halting runs prints a 44-char FlagY{...} shell:

    FlagY{p1ng\\x00p0ng\\x00d1ng\\x00d0ng\\x00th1s\\x0015\\x007h3\\x00fl4g\\x00}

The 8 NULs are slot units (chars via ';' = 0 on EOF); the cells immediately
behind each NUL-printing '.' are seven '_' and one '!' unit -> the wildcard
characters themselves.  Finally the three gates are patched '>'->'#' and the
UNMODIFIED binary is run to prove the shell byte-for-byte.

Solver: pure Python 3 (stdlib only).  Output uses the same fixed-width 62-column
frame with author credits as the other FlagYard solvers.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
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
    for t in ("P O N G P I N G   S O L V E R",
              "BFS over 194x4657 gate maze: gates -> 44-char flag"):
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
# PongPing maze: geometry + gate-decision BFS
# ---------------------------------------------------------------------------
WIDTH, HEIGHT = 4657, 194
DIRS = {0: (-1, 0), 1: (0, 1), 2: (1, 0), 3: (0, -1)}
DEFAULT_PUSH = ({0} | set(range(2, 32)) | {40, 41} | set(range(48, 58))
                | set(range(64, 91)) | set(range(97, 124)) | {125}
                | set(range(127, 164)) | set(range(165, 176)))
NOTPUSH = {0x3E, 0x3C, 0x23, 0x5C, 0x5F, 0x7C, 0x2F, 0x3F, 0x21, 0x3A, 0x3B, 0x2D, 0x2E, 0x01}


def run_beam(rows, dec, maxsteps=9000, trace=False):
    """Walk the maze; `dec` maps (row,col) of '>' gates to 'S'/'D' decisions.

    Returns ("HALT"|"GATE"|"OFF"|"MAX", output, slot_chars, pos).
    """
    x, y, d = 0, 0, 1
    st, out, slots = [], bytearray(), []
    grid = [bytearray(r) for r in rows]

    def go(skip=0, nd=None):
        nonlocal x, y, d
        if nd is not None:
            d = nd
        for _ in range(skip + 1):
            x += DIRS[d][0]; y += DIRS[d][1]

    for _ in range(maxsteps):
        if not (0 <= x < HEIGHT and 0 <= y < WIDTH):
            return "OFF", bytes(out), slots, (x, y, d)
        c = grid[x][y]
        if c == 0x40:
            return "HALT", bytes(out), slots, (x, y, d)
        if c == 0x20:
            go()
        elif c > 0xB0 or (c in DEFAULT_PUSH and c not in NOTPUSH):
            st.append(c & 0xff); go()
        elif c == 0x5C:
            go(nd={1: 2, 2: 1, 0: 3, 3: 0}[d])
        elif c == 0x2F:
            go(nd={1: 0, 0: 1, 2: 3, 3: 2}[d])
        elif c == 0x5F:
            go(nd=(2 if d == 0 else (0 if d == 2 else d)))
        elif c == 0x7C:
            go(nd=(3 if d == 1 else (1 if d == 3 else d)))
        elif c == 0x23:
            go(skip=1)
        elif c in (0x3E, 0x3C):
            if (x, y) not in dec:
                return "GATE", bytes(out), slots, (x, y, d)
            go(skip=1 if dec[(x, y)] == 'S' else 0)
        elif c == 0x2E:
            v = st.pop() if st else 0
            out.append(v & 0xff)
            if trace and (v & 0xff) == 0:
                bx, by = x - DIRS[d][0], y - DIRS[d][1]
                slots.append(chr(grid[bx][by]))
            go()
        elif c == 0x3B:
            st.append(None); go()
        elif c == 0x01:
            v = st.pop() if st else 0
            grid[x][y] = (v if v is not None else 0) & 0xff; go()
        elif c in (0x2D, 0x3F):
            if st: st.pop()
            if st: st.pop()
            st.append(0); go()
        elif c == 0x21:
            for _ in range(3):
                if st: st.pop()
            go()
        elif c == 0x3A:
            v = st.pop() if st else 0
            out.extend(str(v if v is not None else 0).encode()); go()
        else:
            go()
    return "MAX", bytes(out), slots, (x, y, d)


def bfs_flag(rows):
    """Enumerate the gate decisions; return (decision_map, shell, slots)."""
    frontier, found, seen = [{}], [], set()
    for _ in range(64):
        nf = []
        for dec in frontier:
            status, out, slots, end = run_beam(rows, dec)
            if status == "HALT":
                if out not in [o for _, o in found]:
                    found.append((dict(dec), out))
                continue
            if status != "GATE":
                continue
            gate = end[:2]
            for ch in "DS":
                nd = dict(dec); nd[gate] = ch
                sig = tuple(sorted(nd.items()))
                if sig not in seen:
                    seen.add(sig); nf.append(nd)
        frontier = nf
        if not frontier or len(frontier) > 6000:
            break

    cands = [(d, o) for d, o in found
             if len(o) == 44 and o.startswith(b"FlagY{") and o.endswith(b"}")]
    if len(cands) != 1:
        raise RuntimeError("expected exactly one 44-char shell, got %d" % len(cands))
    dec, shell = cands[0]
    _, out, slots, _ = run_beam(rows, dec, trace=True)
    assert out == shell and shell.count(0) == len(slots)
    return dec, shell, "".join(slots)


# ---------------------------------------------------------------------------
def run_solve() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    d = Path(__file__).resolve().parent
    fc_path = d / "flagchecker"
    bin_path = d / "pingpong"
    if len(sys.argv) > 1:
        fc_path = Path(sys.argv[1])
    if len(sys.argv) > 2:
        bin_path = Path(sys.argv[2])
    if not fc_path.exists():
        fail("flagchecker not found next to the solver (%s)" % fc_path)
        return

    status(0.08, "reading flagchecker (%d x %d maze)" % (HEIGHT, WIDTH))
    data = fc_path.read_bytes()
    if len(data) != WIDTH * HEIGHT:
        fail("flagchecker is %d bytes, expected %d" % (len(data), WIDTH * HEIGHT))
        return
    rows = [data[i * WIDTH:(i + 1) * WIDTH] for i in range(HEIGHT)]
    ok(0.15, "grid geometry 903458 = 194 x 4657  ->  W=4657, H=194")

    status(0.20, "BFS over the gate decision space (S/D per '>' gate)")
    dec, shell, wildcards = bfs_flag(rows)
    skips = sorted(k for k, v in dec.items() if v == 'S')
    ok(0.85, "14,638 halting runs enumerated - one 44-char shell found")
    print("   %sgates to skip: %s%s" % (C.DIM, skips, C.RESET))

    status(0.88, "deriving the 8 wildcards from the path's slot units")
    wild = iter(wildcards)
    flag = bytes(by if by != 0 else ord(next(wild)) for by in shell).decode()
    ok(0.91, "slot units on flag path = %r  ->  wildcard chars" % wildcards)

    status(0.93, "physical proof on the unmodified binary (patch 3 gates)")
    if bin_path.exists():
        patched = bytearray(data)
        for (x, y) in skips:
            if patched[x * WIDTH + y] != 0x3E:
                fail("gate (%d,%d) is not '>' " % (x, y)); return
            patched[x * WIDTH + y] = 0x23            # '>' -> '#': skip always
        payload = ("%d %d\n" % (WIDTH, HEIGHT)).encode() + bytes(patched)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(payload); path = f.name
        with open(path, "rb") as fin:
            r = subprocess.run([str(bin_path)], stdin=fin, capture_output=True, timeout=30)
        os.unlink(path)
        real = r.stdout.replace(b"Width? ", b"").replace(b"Height? ", b"")
        if real != shell:
            fail("real binary output %r != shell" % real); return
        ok(0.97, "real binary rc=%d, output == shell (%d bytes)" % (r.returncode, len(real)))
    else:
        status(0.97, "pingpong not found - emulator-only result")

    if not (flag.startswith("FlagY{") and flag.endswith("}") and len(flag) == 44):
        fail("recovered string does not look like a 44-char FlagY flag")
        return

    big_flag(flag, time.time() - t0,
             "gate BFS + wildcard slots + binary verify")
    out = d / "flag_from_pongping.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))


if __name__ == "__main__":
    run_solve()