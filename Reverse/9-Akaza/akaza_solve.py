#!/usr/bin/env python3
"""
Akaza  -  FlagYard flat-VM divisor-chain keygen solver (colored edition)

Akaza.exe is a 64-bit PE whose real logic lives in a *sparse* executable
section named ".0Dev" (VA 0x25000, chars 0x60000020).  The compiler-stripped
section holds a flattened switch-machine:  .pdata shows a main-like function
0x10e0..0x1460 that starts with  `jmp 0x140026000`  (into .0Dev), where a
classic CFF dispatcher walks 41 states.

The whole validation is:

    scanf("%s") reads a 32-byte payload (the future hex inside FlagY{...}).
    16 independent rounds; round r::
        v = (payload[2*r] << 8) | payload[2*r+1]        # 16-bit window
        for every divisor d in the 3476-word table (RVA 0x3280, ascending):
            if v % d == 0:
                counter[word idx] += 1                  # WORD at byte off 2*idx
                v = v // d                              # quotient carries on
        memcmp(counter, expected_row[r], 0xd94)         # row RVA 0x6080, stride 0x1b28

    All 16 memcmp must succeed (ebx == 0x10) or it prints "Wrong Flag :(".

The divisor chain was VALIDATED live (Frida) against the real counter buffer:
for known windows the replayed bytes are identical byte-for-byte
(e.g. "Fl" -> [0:2, 1220:1], "AA" -> [4:1, 10:1, 108:1]).

Because every window is only 16 bits, each round is solved by enumerating all
65536 windows and replaying the exact chain; each expected row accepts exactly
ONE window, and the 16 windows tile the 32 payload bytes in order.

Solver: pure Python + embedded table extraction from the bundled Akaza.exe.
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

import struct
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
    for t in ("A K A Z A   S O L V E R", "16 windows x 3476 divisors -> one flag"):
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
# embedded table locations inside Akaza.exe (raw == RVA for every section)
# ---------------------------------------------------------------------------
EXE_NAME = "Akaza.exe"
DIV_OFF = 0x3280          # 3476 x u16 divisor words (ascending, 2..0x7e6d)
DIV_COUNT = 0xD94
ROW_OFF = 0x6080          # 16 x 0x1b28 expected rows (stride 0x1b28)
ROW_STRIDE = 0x1B28
ROWS = 16
MCMP_LEN = 0xD94          # compared slice (bytes) of the counter buffer

def load_tables():
    exe = Path(__file__).resolve().parent / EXE_NAME
    if not exe.exists():
        return None, None, "Akaza.exe not found next to the solver (%s)" % exe
    data = exe.read_bytes()
    # sanity against SIGFPE: no zero divisors anywhere
    div = struct.unpack("<%dH" % DIV_COUNT, data[DIV_OFF:DIV_OFF + 2 * DIV_COUNT])
    if not div or min(div) < 2:
        return None, None, "divisor table looks wrong"
    rows = [data[ROW_OFF + r * ROW_STRIDE : ROW_OFF + (r + 1) * ROW_STRIDE]
            for r in range(ROWS)]
    return div, rows, None

# ---------------------------------------------------------------------------
# exact replay of the executed divisor chain
# ---------------------------------------------------------------------------
def counters(v, div):
    """Full 0x1b28-byte counter buffer for the 16-bit value v (word LE)."""
    buf = bytearray(ROW_STRIDE)
    r8 = 0          # byte offset into divisor table (== counter word offset)
    r9 = 0          # iteration counter (advances only on 'not divisible')
    while r9 < DIV_COUNT:
        idx = r8 >> 1
        d = div[idx]
        q = v // d
        if v % d == 0:
            off = r8
            w = buf[off] | (buf[off + 1] << 8)
            w = (w + 1) & 0xFFFF
            buf[off] = w & 0xFF
            buf[off + 1] = (w >> 8) & 0xFF
            v = q
            if v == 0:
                break
        else:
            r9 += 1
            r8 += 2
    return bytes(buf)

def candidate_for_row(div, row):
    """Find the unique 16-bit window whose *compared* counter bytes == row[:0xd94]."""
    cmp_slice = row[:MCMP_LEN]
    expected_words = {}
    for i in range(0, MCMP_LEN, 2):
        w = cmp_slice[i] | (cmp_slice[i + 1] << 8)
        if w:
            expected_words[i >> 1] = w
    out = []
    for v in range(0x10000):
        vv = v
        buf = bytearray(MCMP_LEN)
        r8 = 0
        r9 = 0
        okc = True
        while r9 < DIV_COUNT:
            idx = r8 >> 1
            if idx >= (MCMP_LEN >> 1):
                break              # beyond the compared slice: result irrelevant
            d = div[idx]
            if vv % d == 0:
                if idx not in expected_words:
                    okc = False
                    break
                off = r8
                w = buf[off] | (buf[off + 1] << 8)
                w = (w + 1) & 0xFFFF
                if w > expected_words[idx]:
                    okc = False
                    break
                buf[off] = w & 0xFF
                buf[off + 1] = (w >> 8) & 0xFF
                vv //= d
                if vv == 0:
                    break
            else:
                r9 += 1
                r8 += 2
        if not okc:
            continue
        if bytes(buf) != cmp_slice:
            continue
        out.append(v)
    return out

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    status(0.05, "locating Akaza.exe and the embedded tables")
    div, rows, err = load_tables()
    if err:
        fail(err); return
    ok(0.12, "3476 ascending divisors @ RVA 0x3280 + 16 expected rows @ RVA 0x6080")

    status(0.20, "replaying the divisor chain semantics (validated live, 0 diffs)")
    ok(0.26, "counter bytes are WORD exponent counters, quotient carries on")

    solvetime = time.time()
    payload = bytearray(32)
    status(0.34, "searching each 16-bit window against its expected row")
    for r in range(ROWS):
        cands = candidate_for_row(div, rows[r])
        if len(cands) != 1:
            fail("row %d: expected exactly one window, got %d" % (r, len(cands)))
            return
        v = cands[0]
        payload[2 * r] = (v >> 8) & 0xFF        # window r = (payload[2r] << 8) | payload[2r+1]
        payload[2 * r + 1] = v & 0xFF
        ok(0.34 + 0.60 * (r + 1) / ROWS,
           "row %2d -> window 0x%04x (%s%s)" % (r, v,
             chr(payload[2 * r]), chr(payload[2 * r + 1])))
    ok(0.94, "all 16 windows unique; payload assembled (%s)" % (time.time() - solvetime))

    pl = payload.decode("ascii", "replace")
    if len(pl) != 32 or any(ch not in "0123456789abcdef" for ch in pl):
        fail("payload is not clean hex: %s" % pl); return
    ok(0.96, "payload is 32 clean hex chars")

    status(0.97, "re-running the full 16-round check on the recovered payload")
    for r in range(ROWS):
        buf = counters((payload[2 * r] << 8) | payload[2 * r + 1], div)
        if buf[:MCMP_LEN] != rows[r][:MCMP_LEN]:
            fail("full-check mismatch on row %d" % r); return
    ok(1.0, "all 16 memcmp slices match the expected rows (validate)")

    flag = "FlagY{%s}" % pl
    big_flag(flag, time.time() - t0, "flat-VM: 16 windows / one unique payload")
    out = Path(__file__).resolve().parent / "flag_from_akaza.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()