#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MOVING ON  -  FlagYard Crypto Solver

Medium / Crypto

"Elapsed modules are no match for the elapsed-curve of the moving on."
                             (supersingular fast-mapping curve)

We are given an elliptic curve E over F_p with:

    p = 0x00e675aaef519c7bdfa7e9b6d5
    a = 0x00c5a83d2b9ce92d9c75a37a08
    b = 0x0020cd6dc3b4b34e4332463ccd

The single flag (PKCS#7 padded to 12-byte blocks) is split into two
scalars s1, s2 and two public points are shipped:

    Q1 = s1 * G ,   Q2 = s2 * G ,   G = E.gens()[0]

The catch is the GROUP ORDER:  #E = p + 1.  That makes E a SINGULAR
variant in disguise -- a SUPERSINGULAR curve -- so the discrete log can
be lifted to the multiplicative group of a quadratic extension via the
Weil pairing (the classic MOV attack):

    DLP on  E(F_p)  unde r  k = 2   ->   truth in  F_{p^2}^*

Pipeline:

    1. factor n = #E = p+1 and build the pair (q, cofactor)
         q        = 24171428442137419      (the big prime)
         cofactor = n / q
         2,5,757,1627,239579 are all tiny prime factors
    2. build E over F_{p^2}, let P = cofactor * G (order q)
    3. pick a random R of order q and get w = P.weil_pairing(R, q) != 1
    4. for each Qi: lift  cofactor * Qi  to the pairings group and solve
         s (mod q) = fflog(target, w, q)      (index calculus in F_{p^2})
    5. solve the tiny subgroups on E(F_p) directly (2,5,757,1627,239579)
    6. CRT everything together -> s1, s2  ->  12-byte blocks -> flag

Backend: if SageMath is installed we drive it; otherwise we drive a
plain PARI/GP binary (gp.exe / gp on PATH) -- the same pairings-based
attack, with index-calculus discrete logs (fflog).  Nothing else needs
to be installed.

Target is the challenge folder (default: the folder of this script).
The full math lives in solve_movingon.gp (PARI) / solve_movingon.sage
(SageMath), i.e. the same shape as Alice's script.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
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

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("M O V I N G   O N   S O L V E R",
              "supersingular ECC  |  MOV attack via Weil pairing"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel + author credits
# ---------------------------------------------------------------------------
W = 58

def _row(segs):
    out = "  \u2551"
    for t, pre, post in segs:
        if pre:
            out += pre + t + (post or "") + C.RESET
        else:
            out += t
    out += " " * (W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

_GRAD = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"

def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)

def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("General", C.BOLD + C.WHITE, "")])
    _row([("   FlagYard CTF  |  Lab Training Write-ups  ", C.DIM + C.CYAN, "")])
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   Crypto  \u203a  ", "", ""),
          ("Moving On - FlagYard", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("ECC - Supersingular curve / MOV", C.DIM + C.GRAY, "")])
    print("  " + "\u255a" + "\u2550" * W + "\u255d")

def big_flag(flag, chrono, extra):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# challenge constants
# ---------------------------------------------------------------------------
P = 0x00e675aaef519c7bdfa7e9b6d5
A = 0x00c5a83d2b9ce92d9c75a37a08
B = 0x0020cd6dc3b4b34e4332463ccd

Q1 = (25868279382606376233089622039, 35226758373642087968613953852)
Q2 = (31211278741961598848732755066, 68653856268530027481128223450)

Q_BIG = 24171428442137419          # the big prime factor of #E
SMALL_MODS = [2, 5, 757, 1627, 239579]

FLAG_RE = re.compile(r"FlagY\{[0-9A-Za-z_!?-]+\}")

def _to_bytes(x: int, blen: int = 12):
    return int(x).to_bytes(blen, "big")

def _unpad(b: bytes, bs: int = 12):
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= bs and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b

# ---------------------------------------------------------------------------
# PARI/GP backend
# ---------------------------------------------------------------------------
_GP_PROG = r"""
\ gp : MOV attack, mirrors the sage pipeline (see solve_movingon.sage)
p = 0x00e675aaef519c7bdfa7e9b6d5;
a = 0x00c5a83d2b9ce92d9c75a37a08;
b = 0x0020cd6dc3b4b34e4332463ccd;
E = ellinit([Mod(a,p), Mod(b,p)]);
grp = ellgroup(E, p, 1);
n   = grp[1];
G   = grp[3][1];
Q1 = [25868279382606376233089622039, 35226758373642087968613953852];
Q2 = [31211278741961598848732755066, 68653856268530027481128223450];
Qs = [Q1, Q2];
q = 24171428442137419;
cofactor = n \ q;
u = ffgen(p^2, 'u);
E2 = ellinit([u^0*a, u^0*b]);
G2 = [u^0 * lift(G[1]), u^0 * lift(G[2])];
P = ellmul(E2, G2, cofactor);
R = [0];
w = 1;
for (i = 1, 1000000, x = random(p) + u*random(p); ys = ellordinate(E2, x); if (#ys == 0, next); Rtmp = ellmul(E2, [x, ys[1]], cofactor); if (Rtmp == [0], next); wtry = ellweilpairing(E2, P, Rtmp, q); if (wtry != 1, R = Rtmp; w = wtry; break));
if (w == 1, error("failed to find good R"));
print("MOV_READY");
secrets = vector(0);
for (i = 1, 2, Q2i = [u^0 * Qs[i][1], u^0 * Qs[i][2]]; Qq = ellmul(E2, Q2i, cofactor); target = ellweilpairing(E2, Qq, R, q); s = fflog(target, w, q); s = lift(s) % q; small_mods = [2, 5, 757, 1627, 239579]; residues = vector(5); for (j = 1, 5, m = small_mods[j]; Gm = ellmul(E, G, n \ m); Qm = ellmul(E, Qs[i], n \ m); r = elllog(E, Qm, Gm, m); residues[j] = r); sfull = Mod(s, q); for (j = 1, 5, sfull = chinese(sfull, Mod(residues[j], small_mods[j]))); print("SECRET_", i, " = ", lift(sfull)));
\q
"""

# ---------------------------------------------------------------------------
# SageMath backend
# ---------------------------------------------------------------------------
_SAGE_PROG = r"""
from sage.all import *

p = 0x00e675aaef519c7bdfa7e9b6d5
a = 0x00c5a83d2b9ce92d9c75a37a08
b = 0x0020cd6dc3b4b34e4332463ccd

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]

Qs = [
    E(25868279382606376233089622039, 35226758373642087968613953852),
    E(31211278741961598848732755066, 68653856268530027481128223450),
]

n = Integer(E.order())
q = Integer(24171428442137419)
cofactor = n // q

K.<u> = GF(p^2)
E2 = EllipticCurve(K, [K(a), K(b)])
G2 = E2(K(G[0]), K(G[1]))
Qs2 = [E2(K(Q[0]), K(Q[1])) for Q in Qs]

P = cofactor * G2
while True:
    R = E2.random_point()
    R = cofactor * R
    if R != E2(0):
        w = P.weil_pairing(R, q)
        if w != 1:
            break

for i, Q in enumerate(Qs2, 1):
    Qq = cofactor * Q
    target = Qq.weil_pairing(R, q)
    s = Integer(target.log(w, q))

    small_mods = [2, 5, 757, 1627, 239579]
    residues = []
    Q_orig = Qs[i - 1]
    for m in small_mods:
        Gm = (n // m) * G
        Qm = (n // m) * Q_orig
        residues.append(Integer(discrete_log(Qm, Gm, ord=m, operation='+')))

    s_full = Integer(crt(residues + [s], small_mods + [q]))
    print("SECRET_%d = %s" % (i, s_full))
"""

def _find_gp():
    for cand in ("gp.exe", "gp"):
        try:
            subprocess.run([cand, "--version"], capture_output=True, timeout=20)
            return cand
        except Exception:
            continue
    for p in (r"C:\Program Files (x86)\Pari64-2-17-4\gp.exe",
              r"C:\Program Files\Pari64\gp.exe",
              r"C:\PARI\gp.exe"):
        if Path(p).exists():
            return p
    return None

def _find_sage():
    for cand in ("sage", "sage.exe"):
        try:
            subprocess.run([cand, "--version"], capture_output=True, timeout=20)
            return cand
        except Exception:
            continue
    return None

_SECRET_LINE = re.compile(r"SECRET_(\d)\s*=\s*(\d+)")

def _run(backend, workdir: Path):
    """Run backend in workdir, return {1: s1, 2: s2} or raise RuntimeError."""
    if backend[0] == "gp":
        gp = backend[1]
        step("running PARI/GP  (%s)" % gp)
        gptxt = _GP_PROG.lstrip("\n").replace("\\ gp :", "\\\\ gp :")
        tmp = workdir / "solve_movingon.gp"
        tmp.write_text(gptxt, encoding="utf-8")
        r = subprocess.run([gp, "-q", "-s", "256000000", "-f", str(tmp)],
                           capture_output=True, text=True, cwd=str(workdir),
                           timeout=3600)
        out = (r.stdout or "") + (r.stderr or "")
    else:
        sage = backend[1]
        step("running SageMath  (%s)" % sage)
        tmp = workdir / "solve_movingon.sage"
        tmp.write_text(_SAGE_PROG.lstrip("\n"), encoding="utf-8")
        r = subprocess.run([sage, str(tmp)],
                           capture_output=True, text=True, cwd=str(workdir),
                           timeout=3600)
        out = (r.stdout or "") + (r.stderr or "")

    if "MOV_READY" not in out and "SECRET_1" not in out:
        tail = "\n".join(out.splitlines()[-15:])
        raise RuntimeError("backend failed:\n%s" % tail)

    secs = dict((int(k), int(v)) for k, v in _SECRET_LINE.findall(out))
    if len(secs) != 2:
        raise RuntimeError("did not recover two secrets; output:\n%s"
                           % "\n".join(out.splitlines()[-15:]))
    return secs

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(folder):
    folder = Path(folder)
    step("reading  #E = p+1  (super-singular detection)")
    n = P + 1
    try:
        fac = " * ".join(["%d%s" % (b, "^%d" % e if e > 1 else "")
                          for b, e in [(2, 1), (5, 1), (757, 1),
                                       (1627, 1), (239579, 1),
                                       (Q_BIG, 1)]])
    except Exception:
        fac = "2 * 5 * 757 * 1627 * 239579 * 24171428442137419"
    ok("n = #E = p+1 = %d" % n)
    ok("factorization: %s" % fac)
    ok("big prime q = %d  (55 bits)" % Q_BIG)
    ok("small factors [%s] -- DLP is a cake walk" % ", ".join(map(str, SMALL_MODS)))

    step("MOV reduction  DLP(E(F_p)) -> F_{p^2}^* via Weil pairing")
    ok("embedding degree k = 2  (supersingular curve)")

    backend = None
    gp = _find_gp()
    sage = _find_sage()
    if gp:
        backend = ("gp", gp)
    elif sage:
        backend = ("sage", sage)
    else:
        fail("no backend found: install SageMath  (apt install sagemath)")
        fail("  or point this script at a PARI/GP gp.exe")
        return None

    secrets = _run(backend, folder)

    s1 = _to_bytes(secrets[1])
    s2 = _to_bytes(secrets[2])
    step("s1 = %d" % secrets[1])
    step("s2 = %d" % secrets[2])

    raw = s1 + s2
    flag_bytes = _unpad(raw, 12)
    try:
        flag = flag_bytes.decode("utf-8")
    except UnicodeDecodeError:
        flag = flag_bytes.decode("latin-1")
    if not FLAG_RE.fullmatch(flag):
        fail("reconstructed string is not a valid flag: %r" % flag)
        return None

    step("CFG assembling  ->  %s" % flag_bytes)
    ok("flag assembled from two 12-byte blocks (PKCS#7,%d)" % 12)
    return flag

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    step("challenge folder %s" % base)

    flag = exploit(base)
    if flag:
        ok("FLAG = %s" % flag)
        big_flag(flag, time.time() - t0,
                 "MOV attack  |  F_{p^2} Weil pairing  |  CRT")
        outp = Path(__file__).resolve().parent / "flag_from_movingon.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail("flag not recovered")

if __name__ == "__main__":
    main()