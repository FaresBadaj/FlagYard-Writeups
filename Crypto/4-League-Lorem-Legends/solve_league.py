#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEAGUE-LOREM-LEGENDS - FlagYard Crypto Solver

Medium / Cryptography

The server generates:

    e  = getPrime(128)
    p  = getPrime(1024)
    q  = getPrime(1024)
    n  = p*q
    c  = flag^e mod n

    d       = e^-1 mod (p-1)*(q-1)
    dp      = d mod (p-1)
    dp_high = dp >> 205          <- leaked

and gives n, e, c, dp_high.

We know the top ~816 bits of the CRT exponent dp:

    dp = dp_high * 2^205 + x          with x < 2^205 unknown

and e*dp = 1 + k*(p-1):

    k*p = e*dp_high*2^205 - 1 + e*x + k
                \\________B_________/   \\__u__/

So p | (B + u) with u = e*x + k < e*2^205 + e about 2^333.

Since p ~ n^0.5, this is a Coppersmith small-root problem:

    monic linear f(u) = B + u  (mod p),  p | n,  |u| <= X

The classical lattice (Heninger-Shacham / May) with m=2, t=2 (dim 4)
satisfies the Howgrave-Graham bound because for beta=0.5 the root
budget is n^(beta^2) = n^0.25 ~ 2^512 > X.

After LLL reduction we get a degree-3 integer polynomial whose exact
integer root is u0, recovered by sign-based binary search (single
exact Horner evaluations - mpmath polyroots is unstable at these
coefficient magnitudes). Then:

    p = gcd(n, B + u0)
    q = n / p
    d = e^-1 mod (p-1)*(q-1)
    m = c^d mod n  ->  flag
"""

from __future__ import annotations

import math
import os
import re
import sys
import time
from pathlib import Path
from fractions import Fraction


# =====================================================================
# Constants
# =====================================================================

BITS_LEAKED = 205
X_BITS = 336


# =====================================================================
# Colours
# =====================================================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


def enable_vt():

    if sys.platform == "win32":

        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32

            mode = ctypes.c_uint()

            handle = kernel32.GetStdHandle(-11)

            kernel32.GetConsoleMode(
                handle,
                ctypes.byref(mode)
            )

            kernel32.SetConsoleMode(
                handle,
                mode.value | 0x0004
            )

        except Exception:
            pass

    try:
        sys.stdout.reconfigure(
            encoding="utf-8",
            errors="replace"
        )
    except Exception:
        pass


def step(msg, icon="▶", color=C.CYAN):

    print(
        "  %s%s %s%s%s"
        % (
            C.BOLD + color + icon + " ",
            C.DIM,
            C.BOLD,
            msg,
            C.RESET
        ),
        flush=True
    )


def ok(msg):

    step(
        msg,
        icon="✓",
        color=C.GREEN
    )


def fail(msg):

    print(
        "  %s✗ %s%s%s"
        % (
            C.RED,
            C.BOLD,
            msg,
            C.RESET
        ),
        flush=True
    )


# =====================================================================
# Banner
# =====================================================================

def banner():

    print(C.MAGENTA + C.BOLD)

    print(
        "  ╔" +
        "═" * 58 +
        "╗"
    )

    lines = [
        "LEAGUE - LOREM - LEGENDS   S O L V E R",
        "partial dp leak -> lattice -> RSA"
    ]

    for text in lines:

        left = (58 - len(text)) // 2

        print(
            "  ║" +
            " " * left +
            text +
            " " * (58 - len(text) - left) +
            "║"
        )

    print(
        "  ╚" +
        "═" * 58 +
        "╝"
    )

    print(C.RESET)


# =====================================================================
# Result panel
# =====================================================================

W = 58

_TG = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"


def _osc(url, color):

    return "\x1b]8;;%s\x1b\\%s" % (
        url,
        color
    )


def _row(segs):

    out = "  ║"

    visible = 0

    for text, pre, post in segs:

        if pre:
            out += (
                pre +
                text +
                (post or "") +
                C.RESET
            )
        else:
            out += text

        visible += len(text)

    out += " " * max(
        0,
        W - visible
    )

    out += "║"

    print(out)


def _credits():

    print(
        "  ╠" +
        "═" * W +
        "╣"
    )

    _row([
        ("   made with ", C.GREEN, ""),
        ("♥", "\033[1;31m", ""),
        ("  by  ", C.GREEN, ""),
        ("Fares Badaj", C.BOLD + C.WHITE, "")
    ])

    _row([
        (
            "   Red Team Operator | Penetration Tester Specialist",
            C.DIM + C.CYAN,
            ""
        )
    ])

    print(
        "  ╠" +
        "═" * W +
        "╣"
    )

    _row([
        ("   Telegram  ›  ", "", ""),
        (
            "@ptok3",
            _osc(
                "https://t.me/ptok3",
                _TG
            ),
            _OSC_END
        )
    ])

    _row([
        ("   GitHub    ›  ", "", ""),
        (
            "github.com/FaresBadaj",
            _osc(
                "https://github.com/FaresBadaj",
                "\033[1;36m"
            ),
            _OSC_END
        )
    ])

    _row([
        ("   LinkedIn  ›  ", "", ""),
        (
            "linkedin.com/in/FaresBadaj",
            _osc(
                "https://www.linkedin.com/in/FaresBadaj",
                "\033[1;34m"
            ),
            _OSC_END
        )
    ])

    _row([
        ("   Credly    ›  ", "", ""),
        (
            "credly.com/users/faresbadaj",
            _osc(
                "https://www.credly.com/users/faresbadaj",
                "\033[1;33m"
            ),
            _OSC_END
        )
    ])

    print(
        "  ╚" +
        "═" * W +
        "╝"
    )


def big_flag(flag, chrono):

    print()

    head = "★  FLAG RECOVERED  ★"

    print(
        "  ╔" +
        "═" * W +
        "╗"
    )

    _row([
        ("", "", "")
    ])

    _row([
        (
            " " * max(
                0,
                (W - len(head)) // 2
            ),
            "",
            ""
        ),
        (
            head,
            C.BOLD + C.YELLOW,
            ""
        )
    ])

    _row([
        ("", "", "")
    ])

    _row([
        (" " * 6, "", ""),
        (
            flag,
            C.BOLD + C.GREEN,
            ""
        )
    ])

    _row([
        (" " * 10, "", ""),
        (
            "elapsed %.2f s" % chrono,
            C.DIM + C.CYAN,
            ""
        )
    ])

    _row([
        ("", "", "")
    ])

    _credits()

    print()


# =====================================================================
# Parse output.txt
# =====================================================================

def load_output(path):

    step(
        "reading %s" % path
    )

    text = path.read_text(
        encoding="utf-8",
        errors="replace"
    )

    def extract(pattern, name):

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if not match:

            raise ValueError(
                "missing %s in output.txt" % name
            )

        return match.group(1)

    n = int(
        extract(
            r"\bn\s*=\s*(\d+)",
            "n"
        )
    )

    e = int(
        extract(
            r"\be\s*=\s*(\d+)",
            "e"
        )
    )

    c = int(
        extract(
            r"\bc\s*=\s*(\d+)",
            "c"
        )
    )

    dp_high = int(
        extract(
            r"\bdp_high\s*=\s*(\d+)",
            "dp_high"
        )
    )

    return n, e, c, dp_high


# =====================================================================
# LLL (pure Python, exact arithmetic)
# =====================================================================

def dot(u, v):

    return sum(
        a *
        b
        for a, b in zip(u, v)
    )


def lll(M, delta=Fraction(99, 100)):
    """
    LLL-reduce the integer rows of M (exact Fraction arithmetic).
    Small dimensions only (4-8) - fast enough for CTF lattice.
    """

    n = len(M)
    mlen = len(M[0])

    B = [
        [
            Fraction(int(x))
            for x in row
        ]
        for row in M
    ]

    mu = [
        [Fraction(0)] * n
        for _ in range(n)
    ]

    Bst = [None] * n
    Bnorm = [Fraction(0)] * n

    def refresh():

        for i in range(n):

            v = B[i][:]

            for j in range(i):

                mu[i][j] = (
                    dot(v, Bst[j]) /
                    Bnorm[j]
                )

                v = [
                    v[t] - mu[i][j] * Bst[j][t]
                    for t in range(mlen)
                ]

            Bst[i] = v
            Bnorm[i] = dot(v, v)

    refresh()

    k = 1

    while k < n:

        for j in range(k - 1, -1, -1):

            if abs(mu[k][j]) > Fraction(1, 2):

                q = round(mu[k][j])

                B[k] = [
                    B[k][t] - q * B[j][t]
                    for t in range(mlen)
                ]

                refresh()

        if (
            Bnorm[k] >=
            (
                delta -
                mu[k][k - 1] * mu[k][k - 1]
            ) *
            Bnorm[k - 1]
        ):

            k += 1

        else:

            B[k], B[k - 1] = B[k - 1], B[k]

            refresh()

            k = max(k - 1, 1)

    return [
        [int(v) for v in row]
        for row in B
    ]


# =====================================================================
# Univariate Coppersmith (unknown divisor p ~ n^beta)
# =====================================================================

def poly_mul(p, q):

    r = [0] * (len(p) + len(q) - 1)

    for i, a in enumerate(p):
        for j, b in enumerate(q):
            r[i + j] += a * b

    return r


def poly_pow(p, e):

    r = [1]

    for _ in range(e):

        r = poly_mul(r, p)

    return r


def small_roots_linear(N, constB, X, beta=0.5, m=2, t=2):
    """
    Find integer u with |u| <= X and gcd(N, u + constB) = p,
    where p | N and p >= N^beta (Coppersmith / Heninger-Shacham).

    f(x) = x + constB   (monic linear)

    Shift rows:

        g_i(u) = N^(m-i) * f(u)^i        i = 0..m-1
        g_j(u) = u^j * f(u)^m            j = 0..t-1

    Each g vanishes mod p^m at the root. Scale column c by X^c,
    LLL-reduce, the shortest vector is the target polynomial.
    """

    f = [constB, 1]

    GG = []

    for i in range(m):

        p = poly_pow(f, i)

        scale = N ** (m - i)

        GG.append([scale * cf for cf in p])

    fm = poly_pow(f, m)

    for i in range(t):

        GG.append([0] * i + fm)

    D = m + t

    Bmat = []

    for p in GG:

        row = []

        for c in range(D):

            cf = p[c] if c < len(p) else 0

            row.append(cf * (X ** c))

        Bmat.append(row)

    red = lll(Bmat)

    return red, D, X


# =====================================================================
# Exact integer root via sign binary search
# =====================================================================

def hval(h, u):

    return sum(
        c * (u ** j)
        for j, c in enumerate(h)
    )


def find_int_root(h, X):
    """
    h has integer coefficients, h(u0) = 0 for 0 <= u0 <= X.
    sign-of-h binary search - 337 exact Horner evaluations,
    immune to the coefficient magnitude that breaks mpmath polyroots.
    """

    if hval(h, 0) == 0:
        return 0

    if hval(h, X) == 0:
        return X

    if (hval(h, 0) > 0) == (hval(h, X) > 0):
        return None

    lo, hi = 0, X

    while hi - lo > 1:

        mid = (hi + lo) // 2

        if hval(h, mid) == 0:

            return mid

        if (hval(h, mid) > 0) == (hval(h, lo) > 0):

            lo = mid

        else:

            hi = mid

    return lo if hval(h, lo) == 0 else None


# =====================================================================
# Recover p from the lattice
# =====================================================================

def recover_prime(
    n,
    B,
    X
):

    step(
        "building Coppersmith lattice (dim 4)"
    )

    red, D, X = small_roots_linear(
        n,
        B,
        X,
        beta=0.5,
        m=2,
        t=2
    )

    step(
        "LLL reduction done"
    )

    got = 0

    for row in red:

        if all(v == 0 for v in row):
            continue

        h = []

        valid = True

        for c in range(D):

            if row[c] % (X ** c) != 0:

                valid = False
                break

            h.append(row[c] // (X ** c))

        if not valid:
            continue

        for hh in (h, [-v for v in h]):

            xi = find_int_root(hh, X)

            if xi is None:
                continue

            p = math.gcd(n, B + xi)

            if 1 < p < n:

                got += 1

                if got == 1:

                    ok(
                        "recovered root u0"
                    )

                return xi, p

    return None, None


# =====================================================================
# Decrypt RSA
# =====================================================================

def decrypt(
    n,
    e,
    p,
    q,
    c
):

    step(
        "verifying RSA factorization"
    )

    if p * q != n:

        raise RuntimeError(
            "p*q != n"
        )

    ok(
        "p * q == n"
    )

    step(
        "recovering private exponent"
    )

    phi = (
        (p - 1) *
        (q - 1)
    )

    d = pow(
        e,
        -1,
        phi
    )

    ok(
        "private exponent recovered"
    )

    step(
        "decrypting ciphertext"
    )

    m = pow(
        c,
        d,
        n
    )

    length = (
        (m.bit_length() + 7) // 8
    )

    plaintext = m.to_bytes(
        length,
        "big"
    )

    ok(
        "plaintext recovered (%d bytes)"
        % len(plaintext)
    )

    return plaintext


# =====================================================================
# Extract flag
# =====================================================================

def extract_flag(
    plaintext
):

    step(
        "searching plaintext for flag"
    )

    patterns = [
        rb"FlagYard\{[^}\r\n]+\}",
        rb"FLAGYARD\{[^}\r\n]+\}",
        rb"FlagY\{[^}\r\n]+\}",
        rb"FLAGY\{[^}\r\n]+\}",
        rb"FLAG\{[^}\r\n]+\}",
        rb"flag\{[^}\r\n]+\}",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            plaintext,
            re.IGNORECASE
        )

        if match:

            return match.group(
                0
            ).decode(
                "utf-8",
                "replace"
            )

    return None


# =====================================================================
# Main
# =====================================================================

def main():

    started = time.time()

    enable_vt()

    banner()

    try:

        base = Path(
            __file__
        ).resolve().parent

        output = (
            base /
            "output.txt"
        )

        if not output.exists():

            fail(
                "output.txt not found next to solver"
            )

            return

        # ----------------------------------------------------------
        # Read output
        # ----------------------------------------------------------

        (
            n,
            e,
            c,
            dp_high
        ) = load_output(
            output
        )

        print()

        step(
            "n bits = %d"
            % n.bit_length()
        )

        step(
            "e bits = %d"
            % e.bit_length()
        )

        step(
            "dp_high bits = %d"
            % dp_high.bit_length()
        )

        step(
            "leaked = dp >> %d  (missing low bits)"
            % BITS_LEAKED
        )

        print()

        # ----------------------------------------------------------
        # Recover p
        # ----------------------------------------------------------

        B = (
            e *
            dp_high *
            (1 << BITS_LEAKED) -
            1
        )

        X = 1 << X_BITS

        step(
            "targeting root u = e*x + k < 2^%d"
            % X_BITS
        )

        u0, p = recover_prime(
            n,
            B,
            X
        )

        if p is None:

            fail(
                "no lattice root recovered"
            )

            return

        print()

        step(
            "recovered RSA primes"
        )

        print(
            "    u0 = %d"
            % u0
        )

        print(
            "    p  = %d"
            % p
        )

        print(
            "    q  = %d"
            % (
                n // p
            )
        )

        # ----------------------------------------------------------
        # Decrypt
        # ----------------------------------------------------------

        print()

        plaintext = decrypt(
            n,
            e,
            p,
            n // p,
            c
        )

        flag = extract_flag(
            plaintext
        )

        if flag is None:

            fail(
                "flag pattern not found"
            )

            return

        ok(
            "flag extracted successfully"
        )

        elapsed = (
            time.time() -
            started
        )

        big_flag(
            flag,
            elapsed
        )

        # ----------------------------------------------------------
        # Save
        # ----------------------------------------------------------

        flag_file = (
            base /
            "flag_from_league_lorem_legends.txt"
        )

        flag_file.write_text(
            flag + "\n",
            encoding="utf-8"
        )

        print(
            "  %s[+] saved to %s%s"
            % (
                C.GREEN,
                flag_file,
                C.RESET
            )
        )

    except KeyboardInterrupt:

        print()

        fail(
            "interrupted by user"
        )

    except Exception as exc:

        print()

        fail(
            "%s: %s"
            % (
                type(exc).__name__,
                exc
            )
        )


# =====================================================================
# Entry point
# =====================================================================

if __name__ == "__main__":

    main()