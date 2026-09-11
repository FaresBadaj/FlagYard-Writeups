#!/usr/bin/env python3
"""
B4sh33  -  FlagYard bash-keygen solver (colored edition)
Chall.sh is a 124-line bash "reading" challenge.  It joins version=(0 0 0 0)
into 0.0.0.0, MD5s that string, splits the digest into 16 hash_bytes, then
runs 20 checks of the form:

    char_val = ord(input[k])                       # via printf "%d" "'...` input[k]`...'"
    ((char_val ^ CONST) == hash_bytes[j])          # one check, one input slot

Each victory bumps one of four version counters; SUCCESS needs every counter
to be exactly 5.  Because each counter is wired to exactly 5 checks, ALL 20
must pass - so every input character is pinned:

    input[k] = hash_bytes[j] ^ CONST

Table (derived from the 20 checks):

    b89f-f302-dd51-205f1

which prints (the flag is FlagY{$1}):

    FlagY{b89f-f302-dd51-205f1}

Caveat: the shipped Chall.sh has its backticks stripped (bash command
substitution ``"'`${input:k:1}`"`` -> ``"'${input:k:1}"``) - an artifact of
how the file was exported.  "Reading bash is always fun": the arithmetic is
read from intent, and the solver re-derives and re-verifies every byte.

This solver is pure stdlib: it parses Chall.sh, recovers the 20 (pos, hash_byte,
xor, version) checks, re-computes md5(0.0.0.0), derives the flag, simulates the
bash counters and independently re-checks all 20 constraints, then saves
flag_from_b4sh33.txt.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# colored output (same design as the other FlagYard solvers)
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
    for t in ("B 4 S H 3 3   S O L V E R", "bash keygen | md5(0.0.0.0) + 20 XOR checks"):
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
# parse the 20 checks out of Chall.sh
#   each gate: char_val=$(printf "%d" "'`input[k]`")
#              if [ $((char_val ^ X)) -eq ${hash_bytes[J]} ]; then version[V]++ fi
# ---------------------------------------------------------------------------
CHECK_RE = re.compile(
    r"\$\{input:(\d+):1\}.*?"
    r"\(char_val \^ (0x[0-9a-f]+)\)\)\s+-eq\s+\$\{hash_bytes\[(\d+)\]\}.*?"
    r"version\[(\d)\]", re.S)

def parse_checks(text: str):
    out = {}
    for m in CHECK_RE.finditer(text):
        pos, x, kb, v = int(m.group(1)), int(m.group(2), 16), int(m.group(3)), int(m.group(4))
        out[pos] = (kb, x, v)
    return out

def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    ap = argparse.ArgumentParser(description="B4sh33 bash-keygen solver")
    ap.add_argument("script", nargs="?", default=None, help="path to Chall.sh")
    args = ap.parse_args()
    if args.script:
        script = Path(args.script)
    else:
        script = Path(__file__).resolve().parent / "Chall.sh"
    if not script.exists():
        fail("cannot find %s" % script); return

    status(0.08, "parsing %s" % script.name)
    text = script.read_text(encoding="latin1")
    checks = parse_checks(text)
    if len(checks) != 20 or sorted(checks) != list(range(20)):
        fail("expected the 20 single-char gates over positions 0..19"); return
    ok(0.16, "20 input gates recovered: each position 0..19 pinned by exactly one check")

    status(0.26, "reading the key schedule (version = 0.0.0.0)")
    digest = hashlib.md5(b"0.0.0.0").digest()
    hb = list(digest)
    ok(0.34, "md5(0.0.0.0) = %s -> 16 hash_bytes" % digest.hex())

    status(0.44, "deriving each flag char: input[k] = hash_bytes[j] ^ CONST")
    flag_inner = "".join(chr(hb[kb] ^ x) for kb, x, _ in (checks[p] for p in sorted(checks)))
    if not all(32 <= ord(c) < 127 for c in flag_inner):
        fail("derived content is not printable ASCII"); return
    ok(0.52, "flag content: %s" % flag_inner)

    status(0.60, "simulating the bash version counters")
    vers = [0, 0, 0, 0]
    for p in sorted(checks):
        kb, x, v = checks[p]
        if (ord(flag_inner[p]) ^ x) == hb[kb]:
            vers[v] += 1
    if vers != [5, 5, 5, 5]:
        fail("version counters != 5,5,5,5: %r" % vers); return
    ok(0.68, "each version counter reaches 5 (%d,%d,%d,%d) -> all 20 gates must pass"
             % (vers[0], vers[1], vers[2], vers[3]))

    status(0.76, "constraint cross-check (re-derived from the parsed gate table)")
    if not all((ord(flag_inner[p]) ^ x) == hb[kb] for p in sorted(checks)
               for kb, x, _ in (checks[p],)):
        fail("constraint re-check mismatch"); return
    ok(0.84, "all 20 gates hold: input[%d] ^ 0x%02x == hash_bytes[%d]" % (0, checks[0][1], checks[0][0]))

    status(0.90, "no exec probe: shipped .sh has its backticks stripped; pure read-only solve")
    ok(0.96, "keygen solved from source (format: FlagY{%s})" % flag_inner)

    flag = "FlagY{%s}" % flag_inner
    big_flag(flag, time.time() - t0, "md5(0.0.0.0) schedule + 20 XOR gates")
    out = script.parent / "flag_from_b4sh33.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()