#!/usr/bin/env python3
"""
tables  -  FlagYard C++ vtable-state-machine reversing solver

`tables` is an x86-64 ELF (non-PIE, base 0x400000) compiled from C++ that
implements the whole flag check as a VIRTUAL-TABLE STATE MACHINE.  It reads
a line into a 0x2c-byte stack buffer and then runs 43 iterations of:

    for (i = 0; i < 43; i++)
        obj = dispatch(obj, input[i]);       // 0x4012bc -> dispatcher 0x401390

For every input byte the dispatcher  (0x401390)  computes  idx = c - 0x30,
bounds-checks it against 0x4d and switches on a static 0x4e-entry jump table
at 0x404008.  Each case calls one VIRTUAL SLOT of the current object, e.g.

    mov rax,[obj]      ; vtable
    mov rdi,obj
    call [rax+8]       ; slot (idx + 1)

The interesting part: every transition returns a NEW 8-byte object whose
only member is a vtable pointer.

  * wrong character  ->  shared "fail"   object,   vtable = 0x404440
                        (created by the dead-branch handler 0x4017a0)
  * correct character -> "advance" object,
                        vtable = 0x4045a0 + 0x180 * position

After the 43-byte loop main calls vtable[0] (0x4017e0); the object is in
the final advance state only when every character was right -> "Correct!".

This solver therefore mounts a DYNAMIC ORACLE instead of re-deriving every
slot stub: it breaks right after the store at 0x4012c1, `mov [rbp-0x38],rax`,
where %rax holds the freshly returned object, and reads *(ulong*)$rax (its
vtable).  For candidate scanning only the printable chars whose jump-table
entry is NOT the dead branch are probed, and a character is accepted iff the
returned vtable EQUALS the exact expected advance vtable 0x4045a0+0x180*pos
(no heuristic).  The FlagY{...} envelope is pinned, leaving 36 free positions.

The Linux ELF runs under WSL; the driver generates a small gdb python
script, executes gdb -batch inside WSL and re-verifies the recovered flag
against the real binary (expects "Correct!").
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
import sys
import tempfile
import textwrap
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
    W = 58
    titles = ("T A B L E S   S O L V E R",
              "C++ vtable state machine | gdb oracle on the dispatch loop")
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    for t in titles:
        t = t if len(t) <= W else t[: W - 1] + "\u2026"
        l = (W - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (W - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * W + "\u255d")
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
# static facts pulled straight out of the ELF (offset = vaddr - 0x400000)
# ---------------------------------------------------------------------------
GDB_DRIVER = r'''
import gdb
import time

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set debuginfod enabled off")

INP = "/tmp/brute_in.txt"
BPADDR = "0x4012c1"          # mov [rbp-0x38], rax  -> rax = returned object
ADV0 = 0x4045a0              # first advance vtable
STEP = 0x180                 # per-position vtable stride
ANSWER_LEN = 43
ENVELOPE = "FlagY{"          # pinned prefix (positions 0..5)
CANDIDATES = "__CANDIDATES__"   # printable chars that have a live jt handler

class Hit(gdb.Breakpoint):
    """Deterministic breakpoint: stop exactly on the (want+1)-th dispatcher hit."""
    def __init__(self, want):
        super().__init__("*" + BPADDR)
        self.want = want
        self.cnt = 0
    def stop(self):
        self.cnt += 1
        return self.cnt >= self.want + 1

def expected_vtable(pos):
    return ADV0 + STEP * pos

def run_once(inp, pos):
    with open(INP, "w") as f:
        f.write(inp + "\n")
    brk.want = pos
    brk.cnt = 0
    gdb.execute("run < " + INP)
    try:
        return int(gdb.parse_and_eval("*(unsigned long*)$rax"))
    except (gdb.MemoryError, gdb.error):
        return None

def find_char(prefix, pos, attempts):
    exp = expected_vtable(pos)
    for c in CANDIDATES:
        inp = prefix + c + "X" * (ANSWER_LEN - pos - 1)
        attempts.append(c)
        v = run_once(inp, pos)
        if v == exp:
            return (c, v)
    return (None, None)

brk = Hit(0)
pfx = [""]
attempts = []
t0 = time.time()
for pos in range(ANSWER_LEN):
    if pos < len(ENVELOPE):
        c, v = ENVELOPE[pos], expected_vtable(pos)
    elif pos == ANSWER_LEN - 1:
        c, v = "}", expected_vtable(pos)
    else:
        print("pos %d/%d scanning %d candidates..." % (pos, ANSWER_LEN, len(CANDIDATES)), flush=True)
        c, v = find_char(pfx[0], pos, attempts)
        print("  scans: %s  elapsed %.0fs" % (",".join(attempts), time.time() - t0), flush=True)
        attempts = []
        if c is None:
            print("POS %d: NO CANDIDATE (prefix=%r)" % (pos, pfx[0]), flush=True)
            break
    nxt = pfx[0] + c
    pfx[0] = nxt
    print("  -> pos %d char=%r vtable=0x%x   partial=%r" % (pos, c, v, pfx[0]), flush=True)

open("/tmp/brute_result.txt", "w").write(pfx[0])
print("FLAG:", pfx[0])
gdb.execute("quit")
'''

def wsl_stream(args, timeout=2700):
    """Run a command in WSL and stream its output live (collected for parsing)."""
    cmd = ["wsl", "-e", "bash", "-lc", args]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace")
    buf = []
    deadline = time.time() + timeout
    for line in p.stdout:
        buf.append(line)
        print("  " + C.DIM + C.GRAY + line.rstrip("\n") + C.RESET, flush=True)
        if time.time() > deadline:
            p.kill()
            break
    p.wait()
    return p.returncode, "".join(buf)

def to_wsl_path(p):
    p = str(Path(p).resolve())
    m = re.match(r"^([A-Za-z]):\\(.*)$", p)
    if m:
        return "/mnt/%s/%s" % (m.group(1).lower(), m.group(2).replace("\\", "/"))
    return p.replace("\\", "/")

def static_facts(path):
    d = Path(path).read_bytes()
    def q(va):
        return struct.unpack("<Q", d[va - 0x400000:va - 0x400000 + 8])[0]
    jt = [q(0x404008 + i * 8) for i in range(0x4e)]
    candidates = sorted(chr(0x30 + i) for i in range(0x4e) if jt[i] != 0x4017a0)
    return dict(entry_va=0x401090, loop_a=0x4012a5, loop_b=0x4012ce,
                store=0x4012c1, dispatch=0x401390, jtable=0x404008,
                fail_vtable=0x404440, adv0=0x4045a0, step=0x180,
                unique_jt=len(set(jt)), fail_handler=0x4017a0, n=43,
                candidates=candidates)

def solve(target):
    t = str(Path(target).resolve())
    facts = static_facts(t)
    driver = GDB_DRIVER.replace("__CANDIDATES__", repr("".join(facts["candidates"])))
    tmp = Path(tempfile.gettempdir()) / "tables_solve_drv.py"
    tmp.write_text(driver, encoding="utf-8")

    bash = (
        "rm -f /tmp/tables /tmp/t_solve.py; "
        "cp %s /tmp/tables && chmod +x /tmp/tables && "
        "cp %s /tmp/t_solve.py && "
        "cd /tmp && gdb -q -batch -x /tmp/t_solve.py /tmp/tables 2>&1"
        % (repr(to_wsl_path(t)), repr(to_wsl_path(str(tmp))))
    )
    last = None
    for attempt in range(3):
        print("  " + C.DIM + "  oracle attempt %d/3 (live stream below)..." % (attempt + 1) + C.RESET)
        rc, out = wsl_stream(bash)
        out = out or ""
        incomplete = "NO CANDIDATE" in out
        flag = None
        for line in out.splitlines():
            m = re.match(r"^FLAG:\s*(.+)$", line.strip())
            if m:
                flag = m.group(1).strip()
        last = flag
        if flag and len(flag) == 43 and not incomplete:
            return flag, facts
    return last, facts

def verify(target, flag):
    bash = ("printf %s | /tmp/tables" % repr(flag + "\n"))
    r = subprocess.run(["wsl", "-e", "bash", "-lc", bash],
                       capture_output=True, text=True, timeout=120)
    return "Correct!" in (r.stdout or "") + (r.stderr or "")

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    target = sys.argv[1] if len(sys.argv) > 1 else None
    here = Path(__file__).resolve().parent / "tables"
    if target is None and here.exists():
        target = str(here)
    if target is None:
        fail("usage: tables_solve.py [path/to/tables]")
        return

    status(0.12, "target: %s (ELF, non-PIE, base 0x400000)" % target)
    f = static_facts(target)
    ok(0.20, "jump table 0x%x: %d unique handlers for 0x%x entries" %
       (f["jtable"], f["unique_jt"], 0x4e))
    ok(0.28, "loop 0x%x..0x%x: 43 inputs through dispatcher 0x%x" %
       (f["loop_a"], f["loop_b"], f["dispatch"]))
    ok(0.34, "fail vtable 0x%x | advance vtables 0x%x + 0x%x*pos" %
       (f["fail_vtable"], f["adv0"], f["step"]))

    status(0.48, "mounting gdb oracle at 0x%x (vtable of returned object)" % f["store"])
    try:
        flag, facts = solve(target)
    except Exception as e:
        fail("oracle failed: %s" % e)
        return
    if not flag:
        fail("gdb oracle produced no FLAG line -- did gdb print errors above?")
        return
    ok(0.78, "oracle recovered a candidate (%d bytes): %s" % (len(flag), flag))

    status(0.86, "re-verifying against the real binary inside WSL")
    if len(flag) != 43 or not verify(target, flag):
        fail("verification failed (partial or wrong candidate) -- binary did not print Correct!")
        return
    ok(0.94, "binary printed Correct! for the recovered flag")

    big_flag(flag, time.time() - t0,
             "gdb oracle @0x4012c1 over 43 positions of the vtable state machine")

if __name__ == "__main__":
    main()