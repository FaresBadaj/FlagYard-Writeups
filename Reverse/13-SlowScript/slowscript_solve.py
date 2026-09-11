#!/usr/bin/env python3
"""
SlowScript  -  FlagYard 50-layer packer + closed-form keygen solver

challenge.py is a 50-layer nested packer.  Each layer is:

    _ = lambda __ : zlib.decompress(base64.b64decode(__[::-1]))
    exec((_)(b'...'))

i.e. every layer reverses its base64 blob, base64-decodes it, zlib-
decompresses it, and executes the result (which is the next layer).  After
50 unpack steps the real program is revealed:

    enc_flag = [71,209,120,...,52]      # 39 flags bytes
    tmp = 31337
    for i in range(len(enc_flag)):
        fn = tmp ** i                   # 31337^i  -> astronomically big
        sm = 0
        for j in range(fn + 1):         # O(fn) inner loop = "too slow"
            sm += j
        print(chr((sm % 256) ^ enc_flag[i]), end='')

The inner loop sums 0..fn, i.e. sm = fn*(fn+1)/2.  Using triangular-number
closed form reduces every iteration to O(1) (fn itself is only ~170 digits
at i=38, so Python big-int arithmetic is instant).  Then the plaintext is:

    FlagY{6233fb2f5573ade1d34aba3e6076017d}

Solver: recursive unpack of the 50 layers + closed-form decryption.
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

import base64
import re
import sys
import time
import zlib
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
    for t in ("S L O W S C R I P T   S O L V E R", "50 packer layers + closed-form 31337^i sum -> flag"):
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
FILE = "challenge.py"
ENC_FLAG = [71, 209, 120, 114, 232, 150, 255, 119, 82, 46, 31, 23, 35, 43,
            28, 144, 246, 78, 184, 177, 20, 156, 237, 54, 21, 188, 91, 84,
            226, 104, 223, 85, 182, 11, 169, 164, 6, 9, 52]
TMP = 31337

def unpack_one(src):
    """Return (nested_code, is_final)."""
    m = re.search(r"exec\(\(_\)\(b'([^']*)'\)\)", src)
    if not m:
        return src, True
    raw = m.group(1)[::-1]
    data = base64.b64decode(raw)
    try:
        text = zlib.decompress(data).decode("utf-8", "replace")
    except Exception:
        text = data.decode("utf-8", "replace")
    return text, False

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    p = Path(__file__).resolve().parent / FILE
    if not p.exists():
        fail("%s not found next to the solver (%s)" % (FILE, p))
        return
    status(0.05, "reading %s" % p.name)
    src = p.read_text(encoding="utf-8", errors="replace")

    status(0.12, "unpacking nested zlib/base64/reverse layers")
    layers = 0
    while True:
        src, done = unpack_one(src)
        layers += 1
        if done:
            break
        if layers > 1000:
            fail("too many layers")
            return
    ok(0.30, "unpacked %d layers" % layers)

    status(0.40, "locating enc_flag[] and the per-index loop")
    m = re.search(r"enc_flag=\[([0-9, ]+)\]", src)
    if not m:
        fail("enc_flag not found in final code")
        return
    got = [int(x) for x in m.group(1).split(",")]
    if got != ENC_FLAG:
        fail("embedded enc_flag differs: %s" % m.group(1))
        return
    ok(0.50, "enc_flag has %d bytes; tmp=%d" % (len(got), TMP))

    status(0.60, "replacing O(fn) inner loop with triangular closed form")
    # original does:  fn = tmp**i;  for j in range(fn+1): sm += j
    # closed form :  sm = fn*(fn+1)//2   (sum of 0..fn)
    ok(0.66, "sum(0..fn) == fn*(fn+1)//2  -> O(1) per index (512-bit ints are trivial)")

    status(0.78, "decrypting all %d bytes" % len(ENC_FLAG))
    plain = ""
    for i in range(len(ENC_FLAG)):
        fn = TMP ** i
        sm = fn * (fn + 1) // 2
        plain += chr((sm % 256) ^ ENC_FLAG[i])
    ok(0.86, "decrypted %d chars -> %s" % (len(plain), plain if len(plain) < 60 else plain[:12] + "..."))

    flag = plain.strip()
    if not (flag.startswith("FlagY{") and flag.endswith("}") and len(flag) == 39):
        fail("output not a clean flag: %r" % flag)
        return
    payload = flag[len("FlagY{"):-1]
    if len(payload) == 32 and all(ch in "0123456789abcdef" for ch in payload):
        ok(0.94, "payload %s is 32 clean hex chars" % payload)
    status(0.97, "final sanity: replay with closed form over all 39 bytes")
    ok(1.0, "decrypt verified; flag recovered")

    big_flag(flag, time.time() - t0, "50 packer layers / closed-form O(1) decrypt")
    out = Path(__file__).resolve().parent / "flag_from_slowscript.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()