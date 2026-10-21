#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NORMAL EL-GAMAL  -  FlagYard Crypto Solver

Hard / Crypto

Server runs ElGamal over an unknown short-Weierstrass curve over GF(p):

    E : y^2 = x^3 + a*x + b   (p, a, b, G all secret)

The service exposes:

    1. enc (int)   -> (kG, kA + P_m)      two NEW points on the curve
    2. dec (c1x, c1y, c2x, c2y) -> prints the POINT  C2 - x*C1  (x, y)
       unless the ciphertext is the flag's or shares C2 coordinates
       or the embedded integer of the decrypted point equals the flag.

Attack:

    1. Curve recovery. Every output of "enc" is a point (x, y) on E.
       With f(P) = y^2 - x^3  ==  a*x + b (mod p):

            (f0 - f1)*(x0 - x2) - (f0 - f2)*(x0 - x1)  ==  0 (mod p)

       so that integer is a multiple of p; the GCD of many such values
       recovers p (times a small factor), then a and b follow from any
       two points. Verify on all collected points.

    2. Malleability. ElGamal is linear: for a known point D,

            enc(m) + D   decrypts to   P_m + D

       Submit (C1_flag, C2_flag + D). The oracle rejects the exact flag
       ciphertext, but this shifted one passes and leaks the POINT
       P_flag + D. Subtract D locally:

            P_flag = (P_flag + D) - D

       The message embedding is _point_to_int(P) = x >> 8 (L_BITS = 8),
       so flag = long_to_bytes(P_flag.x >> 8).

Target is given as host:port (default tcp.flagyard.com:16085).
"""
from __future__ import annotations

from pwn import *
import re
import sys
import time
import math
from pathlib import Path

try:
    from sympy import isprime
except ImportError:
    isprime = None
try:
    from Crypto.Util.number import long_to_bytes
except ImportError:
    from Crypto.Util.number import long_to_bytes  # pycryptodome

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
    for t in ("N O R M A L   E L - G A M A L   S O L V E R",
              "curve recovery -> malleability -> flag"):
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
    raw = input("  Enter the Normal El-Gamal challenge target (host:port): ").strip()
    return raw or "tcp.flagyard.com:16085"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "16085"
    return host, int(port_s)

# ---------------------------------------------------------------------------
# minimal short-Weierstrass curve arithmetic over GF(p)
# ---------------------------------------------------------------------------
class EC:
    def __init__(self, p, a, b):
        self.p = p; self.a = a % p; self.b = b % p
        self.O = None

    def on(self, P):
        if P is self.O: return True
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, P, Q):
        p = self.p
        if P is self.O: return Q
        if Q is self.O: return P
        x1, y1 = P; x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return self.O
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def neg(self, P):
        if P is self.O: return self.O
        return (P[0], (-P[1]) % self.p)

    def sub(self, P, Q):
        return self.add(P, self.neg(Q))


def curve_ab(p, points):
    x0, y0 = points[0]
    x1, y1 = points[1]
    rhs0 = (y0 * y0 - x0 ** 3) % p
    rhs1 = (y1 * y1 - x1 ** 3) % p
    a = (rhs1 - rhs0) * pow((x1 - x0) % p, -1, p) % p
    b = (rhs0 - a * x0) % p
    return a, b


def recover_curve(points):
    # f(P) = y^2 - x^3  ==  a*x + b (mod p)
    # (f0 - f1)*(x0 - x2) - (f0 - f2)*(x0 - x1)  is a multiple of p
    g = 0
    n = len(points)
    x0, y0 = points[0]
    f0 = y0 * y0 - x0 ** 3
    for i in range(1, n):
        x1, y1 = points[i]
        f1 = y1 * y1 - x1 ** 3
        for j in range(i + 1, n):
            x2, y2 = points[j]
            f2 = y2 * y2 - x2 ** 3
            mlt = (f0 - f1) * (x0 - x2) - (f0 - f2) * (x0 - x1)
            if mlt:
                g = math.gcd(g, abs(mlt))
    for d in range(1, 100000):
        if g % d:
            continue
        cand = g // d
        if cand < 2: continue
        if isprime and not isprime(cand): continue
        try:
            a, b = curve_ab(cand, points)
        except ZeroDivisionError:
            continue
        E = EC(cand, a, b)
        if all(E.on(P) for P in points):
            return cand, a, b
    raise ValueError("curve not recovered")

# ---------------------------------------------------------------------------
# interaction helpers
# ---------------------------------------------------------------------------
def enc(io, m):
    io.sendline(b"1")
    io.recvuntil(b"plaintext>>")
    io.sendline(str(m).encode())
    line = io.recvline(timeout=8).strip()
    io.recvuntil(b">>")
    vals = list(map(int, re.findall(rb"-?\d+", line)))
    return (vals[0], vals[1]), (vals[2], vals[3])

def dec(io, C1, C2):
    io.sendline(b"2")
    io.recvuntil(b"ciphertext>>")
    io.sendline(b"%d,%d,%d,%d" % (C1[0], C1[1], C2[0], C2[1]))
    resp = io.recvuntil(b">>", timeout=8)
    if b"not that easy" in resp:
        return None
    m = re.search(rb"m=\s+(\d+)\s+(\d+)", resp)
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return None

def connect(host, port):
    for _ in range(5):
        try:
            io = remote(host, port, timeout=10)
            io.recv(timeout=3)
            return io
        except Exception:
            time.sleep(2)
    return None

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(host, port):
    io = connect(host, port)
    if io is None:
        fail("could not connect to service")
        return None

    step("fetching flag ciphertext ct = (C1, C2)")
    banner = io.recvuntil(b">>", timeout=15)
    m = re.search(rb"ct=\((\d+), (\d+), (\d+), (\d+)\)", banner)
    if not m:
        fail("flag ciphertext not in banner")
        io.close(); return None
    ct = tuple(int(z) for z in m.groups())
    C1f, C2f = (ct[0], ct[1]), (ct[2], ct[3])
    ok("ct parsed (C1 = %d bits, C2 = %d bits)" % (C1f[0].bit_length(), C2f[0].bit_length()))

    # 1) collect points on the unknown curve via the enc oracle
    step("collecting curve points through the enc oracle")
    points = [C1f, C2f]
    got = 0
    for k in range(12):
        try:
            tick(0.05 + 0.45 * (k / 12), "enc(%d) for curve points" % k)
            P1, P2 = enc(io, k)
            points += [P1, P2]
            got += 2
        except Exception:
            continue
    print()
    ok("%d points on the secret curve collected (incl. flag's)" % len(points))

    # 2) recover (p, a, b) -> the full curve
    step("recovering curve y^2 = x^3 + a*x + b over GF(p)")
    p, a, b = recover_curve(points)
    E = EC(p, a, b)
    if not all(E.on(P) for P in points):
        fail("recovered curve does not fit all points")
        io.close(); return None
    ok("p  =  %d (%d bits)" % (p, p.bit_length()))
    ok("a  =  %d" % a)
    ok("b  =  %d" % b)
    ok("all %d points verified on the curve" % len(points))

    # 3) malleability: dec(C1f, C2f + D) leaks P_flag + D, subtract D
    step("applying ElGamal malleability  (C1_flag, C2_flag + D)")
    D = points[4]                      # any known point on the curve
    C2shift = E.add(C2f, D)
    res = dec(io, C1f, C2shift)
    if res is None:
        fail("oracle refused the shifted ciphertext")
        io.close(); return None
    ok("oracle leaked decrypted point  M + D = (%d, %d)" % res)

    M = E.sub(res, D)
    flag_int = M[0] >> 8
    flag = long_to_bytes(flag_int)
    io.sendline(b"3")
    io.close()

    if not flag or not flag.startswith(b"FlagY"):
        return "FLAG int recovered but not a flag: %r" % flag[:64]
    return flag.decode(errors="replace")


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
        tick(0.9, "flag point recovered and decoded")
        print()
        ok("FLAG = %s" % flag)

        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_normal_elgamal.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail(str(flag))


if __name__ == "__main__":
    main()