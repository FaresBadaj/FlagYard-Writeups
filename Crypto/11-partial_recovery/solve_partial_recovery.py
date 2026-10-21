#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PARTIAL_RECOVERY  -  FlagYard Crypto solver  (factoring via partial CRT
exponents with a custom Coppersmith lattice)

Hard / Crypto

The server stores only the LOWER 512 bits of the CRT exponents dp and dq:

    dp = dp % 2^512   (this is "dp_low")
    dq = dq % 2^512   (this is "dq_low")

with a 2048-bit RSA modulus N and a small public exponent e (a 16-bit
prime).  From key generation we always have:

    e*dp = 1 + k*(p-1)   =>   k*p = e*dp + k - 1
    e*dq = 1 + l*(q-1)   =>   l*q = e*dq + l - 1

Because dp and dq are known only modulo 2^512, the products above are
known only partially:

    (e*dp_low + k - 1)(e*dq_low + l - 1) == k*l*N   (mod 2^512)

Expanding that congruence gives a single quadratic in (k, l):

    A  = e*(dp_low + dq_low) - e^2*dp_low*dq_low - 1
    f(x,y) = (N-1)*x*y - (e*dq_low-1)*x - (e*dp_low-1)*y + A
    f(k,l) == 0   (mod e*2^512)

A quick scan over x < e (e is only 65536 at most) recovers the UNIQUE
pair (k, l) = (36031, 3334).

With k known and odd, e*2^512 is invertible modulo k*N, so the equation

    e*(h_dp*2^512 + dp_low) + k - 1 == 0   (mod k*p)

becomes a modular-root problem for the unknown upper half h_dp:

    f(x) = x + a,   a = (e*dp_low + k - 1) * (e*2^512)^{-1}  mod k*N
    h_dp  is a root of f  mod k*p,  and  0 < h_dp < 2^512

"Standard small_roots" only *just* reaches this theoretical boundary
(beta ~ 0.504, X = 2^512), so this solver uses the CUSTOM lattice from
the paper "Factoring with Only a Third of the Secret CRT-Exponents"
(eprint 2022/271):

    row i  =  f(x)^i * k^(m-i) * N^max(0, t-i)   (evaluated at x*X)

After LLL the reduced rows are polynomials whose small integer root IS
h_dp.  LLL is done through python-flint (flint.fmpz_mat.lll) - no Sage
required.  Bigger m (>= 35) is needed here because the in-process
flint LLL is less aggressive than fplll which Sage ships.

Once h_dp is known:  p = gcd(e*(h_dp*2^512 + dp_low) + k - 1, N),
then q = N // p, phi, d, and pow(c, d, N) -> the flag.

Solver pipeline:

    1. read N, e, c, dp_low, dq_low from output.txt next to this file
    2. scan the quadratic to recover (k, l)    [O(e) -> instant]
    3. build the custom lattice and LLL it through python-flint
    4. scan the reduced rows for the root h_dp, recover p
    5. decrypt c -> print the flag box + save flag_from_partial_recovery.txt

Default target folder = the folder next to this solver.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from math import comb, gcd
from pathlib import Path

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
    for t in ("PARTIAL_RECOVERY   S O L V E R",
              "RSA 2048  |  half of dp+dq  ->  factor N"):
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
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# challenge data parsing
# ---------------------------------------------------------------------------
HEX = r"0x[0-9a-fA-F]+"

def parse_output(txt: str):
    """Pull N, e, c, dp_low, dq_low out of output.txt (exact copy)."""
    def grab(prefix):
        m = re.search(prefix + r"\s*=\s*(" + HEX + r")", txt)
        return int(m.group(1), 16) if m else None
    return (grab(r"N"), grab(r"e"), grab(r"c"),
            grab(r"dp"), grab(r"dq"))

# ---------------------------------------------------------------------------
# step 1 - recover (k, l) from the quadratic congruence
# ---------------------------------------------------------------------------
def inv_mod(a, m):
    return pow(a % m, -1, m)

def find_kl(e, N, dp_low, dq_low, MOD):
    A = e * (dp_low + dq_low) - e * e * dp_low * dq_low - 1

    def f(k, l):
        return ((N - 1) * k * l - (e * dq_low - 1) * k
                - (e * dp_low - 1) * l + A) % MOD

    found = []
    for k in range(1, e):
        coef = ((N - 1) * k + 1) % e
        if gcd(coef, e) != 1:
            continue
        l = ((1 - k) * inv_mod(coef, e)) % e
        if l == 0 or l >= e:
            continue
        if f(k, l) == 0:
            found.append((k, l))
    return found

# ---------------------------------------------------------------------------
# step 2 - custom Coppersmith lattice (eprint 2022/271) + flint LLL
# ---------------------------------------------------------------------------
def solve_h_dp(e, N, dp_low, k_val, MOD, X, ms):
    """Return (h_dp, p) by building the custom lattice for several m."""
    if gcd(e * MOD, k_val * N) != 1:
        return None
    a = (e * dp_low + k_val - 1) * pow(e * MOD, -1, k_val * N) % (k_val * N)

    for m in ms:
        t = m // 2
        dim = m + 1

        Xpow = [1] * (dim + 2)
        for j in range(1, dim + 2):
            Xpow[j] = Xpow[j - 1] * X
        apow = [1] * (dim + 1)
        for i in range(1, dim + 1):
            apow[i] = apow[i - 1] * a

        rows = []
        for i in range(dim):
            nk = k_val ** (m - i)
            ne = N ** max(0, t - i)
            row = [0] * dim
            for j in range(i + 1):
                row[j] = comb(i, j) * Xpow[j] * apow[i - j] * nk * ne
            rows.append(row)

        try:
            import flint
        except ImportError:
            fail("python-flint is required (pip install python-flint)")
            return None

        MAT = flint.fmpz_mat(rows)
        red = MAT.lll(delta=0.99, eta=0.51, rep="zbasis", gram="approx")

        for row in range(dim):
            coeffs = [int(red[row, j]) for j in range(dim)]
            scaled = [coeffs[j] * Xpow[dim - 1 - j] for j in range(dim)]
            while scaled and scaled[-1] == 0:
                scaled.pop()
            if not scaled:
                continue
            try:
                rts = flint.fmpz_poly(scaled).roots()
            except Exception:
                continue
            for r_, _ in rts:
                h = int(r_)
                if not 0 < h < X:
                    continue
                kp = e * (h * MOD + dp_low) + k_val - 1
                p_cand = gcd(kp, N)
                if 1 < p_cand < N and N % p_cand == 0:
                    return h, p_cand
    return None

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(folder: Path):
    try:
        import flint  # noqa: F401
        ok(0.08, "python-flint %s (LLL engine)" % flint.__version__)
    except ImportError:
        fail("python-flint NOT installed - 'pip install python-flint' first")
        return None

    of = folder / "output.txt"
    if not of.is_file():
        fail("output.txt not found under %s" % folder)
        return None
    txt = of.read_text()

    N, e, c, dp_low, dq_low = parse_output(txt)
    if not all(v is not None for v in (N, e, c, dp_low, dq_low)):
        fail("could not parse N/e/c/dp/dq from output.txt")
        return None

    MOD = 2 ** 512
    X = MOD

    print("   %s  N   = %d-bit RSA modulus" % (C.DIM, N.bit_length()))
    print("   %s  e   = %d (16-bit prime)" % (C.DIM, e))
    print("   %s  dp  = %d low bits known   dq = %d low bits known"
          % (C.DIM, dp_low.bit_length(), dq_low.bit_length()))

    status(0.16, "recovering (k, l) from f(k,l) == 0 (mod e*2^512)")
    pairs = find_kl(e, N, dp_low, dq_low, MOD)
    ok(0.24, "(k, l) candidates: %s" % (pairs if pairs else "none"))
    if not pairs:
        return None

    # prefer an ODD k (invertibility of e*2^512 mod k*N)
    k_use = l_use = None
    for k_val, l_val in pairs:
        if k_val % 2 == 1 and gcd(e * MOD, k_val * N) == 1:
            k_use, l_use = k_val, l_val
            break
    if k_use is None:
        k_use, l_use = pairs[0]
        fail("no odd k candidate - lattice inverse may not exist")
    ok(0.30, "using  k = %d   (l = %d)" % (k_use, l_use))

    ms = [35, 40, 45, 50, 30, 25, 20]
    status(0.36, "custom lattice (eprint 2022/271) + flint LLL")

    res = None
    for m in ms:
        status(0.40 + 0.06 * ms.index(m), "LLL m=%d t=%d ..." % (m, m // 2))
        res = solve_h_dp(e, N, dp_low, k_use, MOD, X, [m])
        if res:
            break
    if not res:
        fail("lattice reduction found no root - try larger m")
        return None

    h_dp, p = res
    ok(0.70, "h_dp = %d" % h_dp)
    ok(0.76, "p    = %d" % p)

    q = N // p
    ok(0.82, "recovered both primes  (p*q == N: %s)" % (p * q == N))

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m0 = pow(c, d, N)

    flag = m0.to_bytes((m0.bit_length() + 7) // 8, "big")
    try:
        flag = flag.decode()
    except UnicodeDecodeError:
        flag = flag.decode("latin-1")

    ok(0.88, "flag recovered: %s" % flag)
    out = folder / "flag_from_partial_recovery.txt"
    out.write_text(flag + "\n")
    ok(0.94, "saved to %s" % out)
    return flag

def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    ap = argparse.ArgumentParser(description="partial_recovery flag solver")
    ap.add_argument("folder", nargs="?", default=None, help="path to the challenge folder")
    args = ap.parse_args()
    if args.folder:
        folder = Path(args.folder)
    else:
        folder = Path(__file__).resolve().parent
    if not folder.is_dir():
        fail("cannot open %s" % folder)
        return
    status(0.04, "challenge folder %s" % folder)

    flag = exploit(folder)
    if not flag:
        return
    big_flag(flag, time.time() - t0,
             "custom lattice m>=35 | h_dp recovered -> p -> d -> flag")

if __name__ == "__main__":
    main()