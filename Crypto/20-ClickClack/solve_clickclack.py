#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLICKCLACK  -  FlagYard Crypto Solver

Medium / Crypto

An ECDH handshake is eavesdropped in output.txt: both public points plus an
AES-128-CBC blob of the flag.

    Q  = client's public key          P = s * G   (server public key)
    key = sha256(str(x of s*Q)).digest()[:16]
    blob = iv(16) || AES-128-CBC(key, pad(FLAG, 16))

Looks like a 255-bit ECDLP.  It is not one.  The "CHECKPOINT" curve is
SINGULAR - its discriminant vanishes:

    4a^3 + 27b^2 == 0   (mod p)

so y^2 = x^3 + a*x + b is a nodal cubic, not an elliptic curve.  Its
rational points form a group isomorphic to (F_p*, *) of order p-1, and p-1
is completely smooth:

    p-1 = 2 * 2757875111 * 2881450211 * 3753286421 * 3997403287
           * 4231024097 * 2936391401 * 3533373847 * 2879985937

Attack:

    1. Find the double root of f(x) = (x-x1)^2 * (x-x2),  2*x1 + x2 = 0:
           x1 = sqrt(-a/3)   (p = 3 mod 4, so one exponentiation)
       The singular point (x1, 0) is a NODE (double root -> two tangents).

    2. Translate the node to the origin:  X = x - x1
           Y^2 = X^3 + a2'*X^2 ,   a2' = 3*x1
       a2' is a QR, so the node SPLITS over F_p and  E(F_p) ~= F_p*.

    3. Explicit isomorphism with s = sqrt(a2'):
           phi(X, Y) = (Y - s*X) / (Y + s*X)        phi(O) = 1

    4. Pohlig-Hellman + baby-step giant-step over the nine smooth
       subgroups of p-1 recovers s.  Largest subgroup is only ~32 bits,
       i.e. ~65k table entries per pass.

    5. s * Q  ->  sha256(str(x))[:16]  ->  AES-128-CBC  ->  flag.

    CAREFUL: a translation changes the group law.  The original curve has
    a2 = 0 so the classic short-Weierstrass x3 = lam^2 - x1 - x2 is
    correct there; after shifting the node to the origin a2' != 0 and
    the term -a2' shows up in x3.  Omitting it silently produces points
    that are NOT on the curve.  Every intermediate point is asserted.

This solve is offline - it works from the captured transcript only.
"""
from __future__ import annotations

import os
import re
import sys
import time
from hashlib import sha256
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import gmpy2
from gmpy2 import mpz
import sympy
from sympy.ntheory.modular import crt

# ---------------------------------------------------------------------------
# curve parameters, verbatim from clickclack.py
# ---------------------------------------------------------------------------
P = mpz(30147047372537667543227596509433268914148160199933678584277532878812522173123)
A = mpz(4295866710341558381730993001337260151326704354119856057045858346018488917551)
B = mpz(27915475329982779370228189153614202544988456477009880605661666567636553859719)
GX = mpz(23660607485931404474159157392651047549672758508793488070957915230753900420346)
GY = mpz(8315837926899275371387974820365523190632259447349013169853248963499139967386)

CIPHERSUITE = "ECDHE_CHECKPOINT_WITH_AES_128"
O = "Origin"          # sentinel for the point at infinity

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
    for t in ("C L I C K C L A C K   S O L V E R",
              "singular curve  |  Pohlig-Hellman on smooth p-1"):
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
    # centred so the frame stays aligned even for a long flag
    _row([(" " * max(1, (W - len(line)) // 2), "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * max(1, (W - len(s)) // 2), "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

def short(n, keep=8):
    s = str(n)
    return s if len(s) <= 2 * keep + 1 else "%s...%s" % (s[:keep], s[-keep:])

# ---------------------------------------------------------------------------
# transcript parsing
# ---------------------------------------------------------------------------
PT_RE = re.compile(r"Point\(x=(\d+), y=(\d+)\)")
HEX_RE = re.compile(r"server->client : ([0-9a-f]{32,})")

def parse_transcript(text):
    pts = PT_RE.findall(text)
    hexes = HEX_RE.findall(text)
    if len(pts) < 2 or not hexes:
        raise ValueError("transcript lacks 2 points + 1 ciphertext")
    return ((mpz(pts[0][0]), mpz(pts[0][1])),
            (mpz(pts[1][0]), mpz(pts[1][1])),
            bytes.fromhex(hexes[-1]))

# ---------------------------------------------------------------------------
# singular-curve arithmetic on  y^2 = x^3 + A*x + B
# ---------------------------------------------------------------------------
def fld_inv(v):
    return mpz(gmpy2.invert(mpz(v), P))

def analyse():
    """Prove the curve is a split nodal cubic; return (x1, a2', sqrt(a2'))."""
    disc = (4 * A ** 3 + 27 * B ** 2) % P
    if disc != 0:
        raise ValueError("curve is not singular - this solver does not apply")
    # f'(x) = 3x^2 + A  vanishes at the double root;  p = 3 mod 4
    x1 = mpz(gmpy2.powmod((-A * fld_inv(3)) % P, (P + 1) // 4, P))
    if (3 * x1 ** 2 + A) % P or (x1 ** 3 + A * x1 + B) % P:
        raise ValueError("double root not found")
    x2 = (-2 * x1) % P
    if (x2 ** 3 + A * x2 + B) % P:
        raise ValueError("simple root not found")
    # X = x - x1  ->  Y^2 = X^3 + a2'*X^2   with a2' = 3*x1
    a2p = (3 * x1) % P
    if gmpy2.legendre(a2p, P) != 1:
        raise ValueError("node does not split over F_p - different attack")
    s = mpz(gmpy2.powmod(a2p, (P + 1) // 4, P))
    if (s * s) % P != a2p:
        raise ValueError("sqrt(a2') failed")
    return x1, a2p, s

def to_translated(pt):
    return ((pt[0] - X1) % P, pt[1])

def to_original(pt):
    return ((pt[0] + X1) % P, pt[1])

def add(Pt, Qt):
    """Chord-and-tangent on  Y^2 = X^3 + a2'*X^2  (a1=a3=a4=a6=0, a2=a2').

    The -a2' term in X3 is what a translation introduces.  The classic
    short-Weierstrass formula (a2 = 0) silently returns off-curve points.
    """
    if Pt == O:
        return Qt
    if Qt == O:
        return Pt
    if Pt[0] == Qt[0] and (Pt[1] + Qt[1]) % P == 0:
        return O
    if Pt == Qt:
        lam = (3 * Pt[0] ** 2 + 2 * A2P * Pt[0]) * fld_inv(2 * Pt[1]) % P
    else:
        lam = (Qt[1] - Pt[1]) * fld_inv(Qt[0] - Pt[0]) % P
    X = (lam * lam - A2P - Pt[0] - Qt[0]) % P
    Y = (lam * (Pt[0] - X) - Pt[1]) % P
    return (X, Y)

def mul(Pt, n):
    R, Q = O, Pt
    n = int(n)
    while n > 0:
        if n & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        n >>= 1
    return R

def on_curve(Pt):
    return (Pt[1] ** 2 - Pt[0] ** 3 - A2P * Pt[0] ** 2) % P == 0

def phi(Pt):
    """Isomorphism into F_p* :  (X, Y) |-> (Y - s*X) / (Y + s*X)."""
    if Pt == O:
        return mpz(1)
    X, Y = Pt
    return ((Y - S * X) % P) * fld_inv((Y + S * X) % P) % P

# ---------------------------------------------------------------------------
# discrete log in F_p* : Pohlig-Hellman + baby-step giant-step
# ---------------------------------------------------------------------------
def bsgs(base, target, order):
    mod, order = int(P), int(order)
    base, target = int(base) % mod, int(target) % mod
    m = int(gmpy2.isqrt(mpz(order))) + 1
    table, cur = {}, 1
    for j in range(m):
        table[cur] = j
        cur = cur * base % mod
    giant = pow(base, order - m, mod)
    gamma = target
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            return (i * m + j) % order
        gamma = gamma * giant % mod
    return None

def ph_solve(base, target, order, report):
    mods, res = [], []
    for q, e in sympy.factorint(int(order)).items():
        Q = q ** e
        report(Q)
        x = bsgs(pow(int(base), order // Q, int(P)),
                 pow(int(target), order // Q, int(P)), Q)
        if x is None:
            raise ValueError("no solution in subgroup %s" % Q)
        mods.append(Q)
        res.append(int(x))
    return int(crt(mods, res, False)[0])

# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    here = Path(__file__).resolve().parent
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    tf = Path(args[0]) if args else here / "output.txt"
    if not tf.exists():
        fail("transcript not found: %s" % tf)
        return

    # ---- 1. transcript ------------------------------------------------------
    status(0.03, "reading the eavesdropped transcript")
    try:
        client_pub, server_pub, blob = parse_transcript(
            tf.read_text(encoding="utf-8", errors="replace"))
    except Exception as ex:
        fail(str(ex))
        return
    ok(0.07, "%s  (%d bytes)" % (tf.name, tf.stat().st_size))
    ok(0.10, "ciphersuite %s" % CIPHERSUITE)
    ok(0.12, "field %d bits, client pub x = %s" % (P.bit_length(), short(client_pub[0], 10)))
    ok(0.14, "server pub x = %s" % short(server_pub[0], 10))
    ok(0.16, "ciphertext %d bytes, iv = %s" % (len(blob), blob[:16].hex()))

    # ---- 2. singularity --------------------------------------------------
    global X1, A2P, S
    status(0.20, "checking the discriminant  4a^3 + 27b^2 (mod p)")
    disc = (4 * A ** 3 + 27 * B ** 2) % P
    if disc != 0:
        fail("curve is NOT singular (%d) - wrong solver" % disc)
        return
    ok(0.24, "4a^3 + 27b^2 = 0  ->  discriminant vanishes")
    status(0.28, "this is not an elliptic curve - it is a singular cubic")

    status(0.32, "locating the singular point  x1 = sqrt(-a/3)")
    X1, A2P, S = analyse()
    ok(0.36, "double root x1 = %s" % short(X1, 10))
    ok(0.40, "simple root x2 = -2*x1 = %s" % short((-2 * X1) % P, 10))

    status(0.44, "translating the node to the origin  (a2' = 3*x1)")
    ok(0.48, "Y^2 = X^3 + a2'*X^2,  a2' = %s" % short(A2P, 10))
    ok(0.51, "legendre(a2') = +1  ->  split node,  E(F_p) ~= F_p*")
    ok(0.53, "s = sqrt(a2') = %s" % short(S, 10))

    # ---- 3. group law + isomorphism -------------------------------------
    G = to_translated((GX, GY))
    Q = to_translated(client_pub)
    R = to_translated(server_pub)
    status(0.57, "verifying the translated group law")
    for nm, pt in (("G", G), ("client", Q), ("server", R)):
        if not on_curve(pt):
            fail("%s is not on Y^2 = X^3 + a2'*X^2" % nm)
            return
    ok(0.60, "G, client and server all lie on the translated cubic")

    g, gq, gr = phi(G), phi(Q), phi(R)
    status(0.64, "checking phi is a homomorphism  (k=1..5)")
    for k in range(1, 6):
        if phi(mul(G, k)) != pow(int(g), k, int(P)):
            fail("phi(kG) != phi(G)^k at k=%d" % k)
            return
    ok(0.68, "phi(kG) = phi(G)^k for k = 1..5")
    status(0.71, "checking the group order is p-1")
    if mul(G, P - 1) != O:
        fail("(p-1)*G != O")
        return
    ok(0.74, "(p-1)*G = O  ->  order p-1, so E(F_p) ~= F_p*")
    ok(0.76, "phi(G) = %s" % short(g, 10))
    ok(0.77, "phi(server) = %s" % short(gr, 10))

    # ---- 4. discrete log -------------------------------------------------
    order = int(P - 1)
    fac = sympy.factorint(order)
    status(0.80, "factoring p-1  (%d distinct prime factors)" % len(fac))
    biggest = max(q ** e for q, e in fac.items())
    ok(0.83, "largest prime-power subgroup %d  (~%d-bit DLP)"
           % (biggest, biggest.bit_length()))
    ok(0.84, "p-1 = %s" % " * ".join("%d^%d" % (q, e) for q, e in fac.items()))

    status(0.87, "Pohlig-Hellman + baby-step giant-step over F_p*")
    sub = {"n": 0, "tot": len(fac)}

    def report(Q):
        status(0.87 + 0.09 * sub["n"] / sub["tot"],
               "BSGS in the subgroup of order %d" % Q)
        sub["n"] += 1

    secret = ph_solve(g, gr, order, report)
    if pow(int(g), secret, int(P)) != int(gr):
        fail("dlog verification failed")
        return
    ok(0.97, "server secret s = %s" % short(secret, 10))
    ok(0.98, "verified:  phi(G)^s == phi(server)")

    # ---- 5. shared secret + AES -----------------------------------------
    status(0.985, "recomputing the ECDH shared point  s * Q")
    shared = to_original(mul(Q, secret))
    key = sha256(str(shared[0]).encode()).digest()[:16]
    ok(0.99, "shared x   = %s" % short(shared[0], 10))
    ok(0.993, "sha256(str(x))[:16] = %s" % key.hex())

    status(0.996, "decrypting AES-128-CBC")
    iv, body = blob[:16], blob[16:]
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
    try:
        plain = unpad(plain, 16)
    except ValueError:
        plain = plain.rstrip(b"\x00")
    flag = plain.decode("latin1").strip()
    if not (flag.startswith("FlagY{") and flag.endswith("}")):
        fail("decrypted bytes do not look like a FlagY{} flag: %r" % flag[:64])
        return
    ok(0.999, "valid FlagY{} format")

    big_flag(flag, time.time() - t0,
             "singular curve -> F_p* | PH/BSGS on 9 factors")
    out = here / "flag_from_clickclack.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()