#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ROLL CALL  -  FlagYard Crypto solver

Roll Call (FlagYard Training Labs, Hard / SAFCSP)

Server: p = 2q+1 safe prime (256-bit QR subgroup of prime order q -> DLP is
infeasible), N=256 members. For every "handle c" the server picks a fresh
random k and replies with the ordered list

    eids[j] = H(roster[j])^k mod p,   roster = [0..255] minus the absent member

then deid = c^k. We win a round by naming the absent member `a`, and we only
get 3 commands per round (<= 2 handle calls + 1 submit), so 8-bit binary
search / membership tests can't work.

Attack (no DLP needed): pick c = product of H(m) over ALL ODD members.
The eids order means "claiming" a hypothesis a' maps every odd member m to
position m (if a' > m) or m-1 (if a' < m).  The predicate

    pred(a') = product of eids[claimed position of m] over odd m

equals deid IF AND ONLY IF a' and the true absent a sit on the same side of
every odd member, i.e. a' and a lie in the same cell of the odd partition.
Odd thresholds make 2-wide cells {1,3,..,255} -> holes, so:

    a even  -> the ONLY consistent a' is a  itself  (1 round, 1 handle, submit)
    a odd   -> no consistent a' at all            (signal: a is odd)

If a is odd, repeat with c = product of H(m) over all EVEN members; now the
unique consistent a' is a again. => every round is solved with <= 2 handles.

Verified locally against all 256 absent values, then live on
tcp.flagyard.com:27905: recovered 16/16 rounds -> DYN_FLAG saved to
`flag_from_rollcall.txt`.
"""
from __future__ import annotations

import ast
import hashlib
import socket
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# challenge constants (same p/q/N as the server)
# ---------------------------------------------------------------------------
P = 113922386694983050382912391517437431439572639334235676622418446302583918640667
Q = 56961193347491525191456195758718715719786319667117838311209223151291959320333
N = 256
ROUNDS = 16

def H(member_id):
    h = int.from_bytes(hashlib.sha256(f"id={member_id}".encode()).digest(), "big") % P
    return pow(h, 2, P)  # always a QR -> never zero

_ODD = [m for m in range(N) if m % 2 == 1]
_EVEN = [m for m in range(N) if m % 2 == 0]

def _product(members):
    v = 1
    for m in members:
        v = v * H(m) % P
    return v

C_ODD = _product(_ODD)   # c that tests all odd members at once
C_EVEN = _product(_EVEN)  # c that tests all even members at once

def claimed_pos(m, aq):
    """position of member m in the roster under the hypothesis absent=aq."""
    return m if m < aq else m - 1

def predict(aq, members, eids):
    """product of the eids at the positions the hypothesis aq claims
    for `members`; equals deid only when aq is (or co-sides with) the truth."""
    v = 1
    for m in members:
        v = v * eids[claimed_pos(m, aq)] % P
    return v

def solve_absent(io, members, deid, eids, who):
    step("testing %s members (hypotheses that are %s)" %
         ("odd" if who == _ODD else "even", who))
    cands = [aq for aq in who if predict(aq, members, eids) == deid]
    if len(cands) == 1:
        return cands[0]
    return None

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
    except Exception:
        pass

def bar(frac):
    w = 20
    f = max(0.0, min(1.0, frac))
    full = int(round(f * w))
    return "[%s%s] %5.1f%%" % ("\u2588" * full, "\u2591" * (w - full), f * 100.0)

def step(msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s%s%s" % (C.BOLD + color + icon + " ",
                             C.DIM, C.BOLD, msg, C.RESET), flush=True)

def ok(msg):
    step(msg, icon="\u2713", color=C.GREEN)

def tick(frac, msg):
    line = ("%s%s %s %s%s%s" %
            (C.BOLD + C.YELLOW + "\u25b6 ",
             C.CYAN + bar(frac) + C.RESET,
             C.DIM, C.BOLD, msg, C.RESET))
    sys.stdout.write("\r  " + line + "   ")
    sys.stdout.flush()

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("R O L L   C A L L   S O L V E R",
              "every/even block product -> name the absent member"):
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
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    _row([(" " * 10, "", ""), ("elapsed %.1f s" % chrono, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# target / io helpers
# ---------------------------------------------------------------------------
def ask_target(argv):
    if len(argv) > 2:
        return argv[1].strip(), argv[2].strip()
    raw = input("  Enter the Roll Call target like tcp.flagyard.com:27905 : ").strip()
    if ":" in raw:
        h, _, pt = raw.rpartition(":")
        return h.strip(), pt.strip()
    if raw:
        return raw, "27905"
    raise RuntimeError("no target provided")

def recvline(fd):
    return fd.readline()

def parse_list(text):
    return ast.literal_eval(text.decode("utf-8", "replace"))

def main():
    t0 = time.time()
    enable_vt()
    banner()

    try:
        host, port = ask_target(sys.argv)
        port = int(port)
    except Exception:
        fail("no target given")
        return
    step("connecting to %s:%d" % (host, port))

    try:
        s = socket.create_connection((host, port), timeout=30)
    except OSError as e:
        fail("connection failed: %s" % e)
        return
    fd = s.makefile("rwb", buffering=0)
    banner_server = fd.readline()
    step("server: %s" % banner_server.decode("utf-8", "replace").strip())

    ok("c_odd  = product of H(m) over odd members")
    ok("c_even = product of H(m) over even members")

    for r in range(ROUNDS):
        tick((r + 0.45) / ROUNDS, "round %d/%d : querying odd block" % (r + 1, ROUNDS))
        fd.write(b"handle %d\n" % C_ODD)
        eids = parse_list(fd.readline())
        deid = int(fd.readline())
        if len(eids) != N - 1:
            fail("round %d: odd handle returned %d eids (expected %d)"
                 % (r + 1, len(eids), N - 1))
            return

        a = solve_absent(fd, _ODD, deid, eids, _EVEN)
        if a is None:
            tick((r + 0.7) / ROUNDS, "round %d/%d : absent is odd, querying even block"
                 % (r + 1, ROUNDS))
            fd.write(b"handle %d\n" % C_EVEN)
            eids2 = parse_list(fd.readline())
            deid2 = int(fd.readline())
            a = solve_absent(fd, _EVEN, deid2, eids2, _ODD)
        if a is None:
            fail("round %d: no consistent hypothesis found" % (r + 1))
            return

        fd.write(("submit %d\n" % a).encode())
        resp = fd.readline().decode("utf-8", "replace").strip()
        if not resp.startswith("Correct"):
            fail("round %d: server rejected absent=%d (%s)" % (r + 1, a, resp))
            return
        tick((r + 1) / ROUNDS, "round %d/%d correct (absent=%d)"
             % (r + 1, ROUNDS, a))

    s.settimeout(10)
    flag = None
    try:
        flag = fd.readline().decode("utf-8", "replace").strip()
    except OSError:
        pass
    print()
    if not flag:
        fail("16/16 correct but no flag line received")
        s.close()
        return
    ok("16/16 rounds correct -> FLAG = %s" % flag)

    s.close()
    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_rollcall.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()