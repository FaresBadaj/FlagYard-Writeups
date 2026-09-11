#!/usr/bin/env python3
"""
GuessyMan  -  FlagYard number-guessing solver (colored edition)
GuessyMan.exe is a stripped x64 Zig build: a 1..100 guessing game whose
"flag decrypt" is a running single-byte XOR of a 39-byte ciphertext in .rdata
with the (random) secret number.  The ciphertext starts at file offset 0x3c45
== rva 0x5045:

    5b 5f 5e 41 5c 41 5d 41 5e 41 5f 5d c3 55 41 56 56 57 53 48 83 ec 30 ...

Known-plaintext recovery:
    ct[0]^'F' == ct[1]^'l' == ct[2]^'a' == ... == 0x15
so the XOR key is 0x15 = 21, and

    flag = bytes(b ^ 0x15 for b in ct)
    flag = FlagY{a01b1ac2858ec221d87a015d9f85837f}

This solver is pure stdlib: it parses the PE, relocates the ciphertext into
.rdata, recovers the key from the 'FlagY{' prefix, decrypts, re-encrypts
(round-trip) and proves 0x15 is the UNIQUE single-byte key that turns any
.rdata window into a 32-hex FlagY{} block.  The game itself picks the secret
with RtlGenRandom each run, so no deterministic live-acceptance probe exists;
the known-plaintext + uniqueness checks are the proof.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
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
    for t in ("G U E S S Y M A N   S O L V E R", "Zig guessing game  |  flag = ciphertext ^ secret"):
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
# minimal PE32+ parser
# ---------------------------------------------------------------------------
def parse_sections(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ header)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (missing PE signature)")
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    if magic != 0x20B:
        raise ValueError("only PE32+ (x64) is supported")
    nsects = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    base = pe + 24 + opt
    secs = []
    for i in range(nsects):
        off = base + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, rp, ps, pl, chars = struct.unpack_from("<IIIIIIH", data, off + 8)
        secs.append({"name": name, "va": va, "vsize": vs, "rp": rp, "rsize": rs})
    return secs

FLAG_RE = re.compile(rb"^FlagY\{[0-9a-f]{32}\}$")

def find_ciphertext(data: bytes, sec):
    """Return (file_off, key, ct) of the unique .rdata window that single-byte
    XORs into a 32-hex FlagY{} block.  key is recovered from the known 'F'."""
    raw = data[sec["rp"]:sec["rp"] + sec["rsize"]]
    for off in range(len(raw) - 39):
        win = raw[off:off + 39]
        diff = win[0] ^ ord("F")
        plain = bytes(b ^ diff for b in win)
        if FLAG_RE.match(plain):
            return sec["rp"] + off, diff, win
    return None, None, None

def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    ap = argparse.ArgumentParser(description="GuessyMan flag solver")
    ap.add_argument("exe", nargs="?", default=None, help="path to GuessyMan.exe")
    args = ap.parse_args()
    if args.exe:
        exe = Path(args.exe)
    else:
        exe = Path(__file__).resolve().parent / "GuessyMan.exe"
    if not exe.exists():
        fail("cannot find %s" % exe); return

    status(0.08, "parsing %s" % exe.name)
    data = exe.read_bytes()
    secs = parse_sections(data)
    rdata = next((s for s in secs if s["name"] == ".rdata"), None)
    if rdata is None:
        fail("no .rdata section"); return
    ok(0.16, "x64 PE parsed: .rdata @ rva 0x%x (rs 0x%x)" % (rdata["va"], rdata["rsize"]))

    status(0.24, "scanning .rdata for the encrypted flag block")
    fo, key, ct = find_ciphertext(data, rdata)
    if ct is None:
        fail("no 'FlagY{' known-plaintext window found in .rdata"); return
    rva = rdata["va"] + (fo - rdata["rp"])
    ok(0.32, "39-byte ciphertext @ rva 0x%x (file 0x%x)" % (rva, fo))

    status(0.40, "recovering the XOR key from the known prefix 'FlagY{'")
    probes = [ct[i] ^ c for i, c in enumerate(b"Flag") if i < 4]
    if len(set(probes)) != 1:
        fail("prefix mismatch - key not constant"); return
    ok(0.48, "key recovered: 0x%02x (%d) - ct[0]^'F'==ct[1]^'l'==ct[2]^'a'==0x%02x"
             % (key, key, key))

    status(0.56, "decrypting ct ^ 0x%02x" % key)
    flag = bytes(b ^ key for b in ct).decode("ascii")
    ok(0.64, "flag decrypted: %s" % flag)

    status(0.72, "round-trip: re-encrypting the flag")
    if bytes(ord(c) ^ key for c in flag) != ct:
        fail("round-trip mismatch"); return
    ok(0.78, "round-trip re-XOR == the ciphertext bytes")

    status(0.84, "uniqueness: single-byte keys hitting FlagY{[0-9a-f]{32}} over .rdata")
    raw = data[rdata["rp"]:rdata["rp"] + rdata["rsize"]]
    sols = []
    for off in range(len(raw) - 39):
        win = raw[off:off + 39]
        k = win[0] ^ 0x46
        if k and all(win[i] ^ k == c for i, c in enumerate(b"FlagY{")):
            if FLAG_RE.match(bytes(b ^ k for b in win)):
                sols.append((off, k))
    other = [k for k in range(1, 256) if k != key
             and FLAG_RE.match(bytes(b ^ k for b in ct))]
    if sols != [(fo - rdata["rp"], key)] or other:
        fail("expected exactly one (offset, key) match"); return
    ok(0.90, "0x%02x is the unique key: no other .rdata window/key decodes to FlagY{}"
             % key)

    big_flag(flag, time.time() - t0,
             "ciphertext ^ 0x%02x @ rva 0x%x (secret %d)" % (key, rva, key))
    out = exe.parent / "flag_from_guessyman.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()