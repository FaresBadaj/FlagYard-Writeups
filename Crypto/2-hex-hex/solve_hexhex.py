#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HEX-HEX - FlagYard Crypto Solver

Easy / Crypto

The server generates:

    n  = p*q
    e  = 127

and leaks:

    dp = e^-1 mod (p-1)
    dq = e^-1 mod (q-1)

but applies the SAME random hexadecimal substitution to dp and dq.

For:

    dp = e^-1 mod (p-1)

there exists k such that:

    e*dp - 1 = k*(p-1)

Likewise:

    e*dq - 1 = l*(q-1)

Therefore:

    p = (e*dp - 1)/k + 1
    q = (e*dq - 1)/l + 1

and:

    p*q = n

The important part is that dp/dq are only hex-digit substituted.

Instead of asking Z3 to solve a huge nonlinear 1024-bit multiplication,
we recover the substitution digit-by-digit.

At position t we know dp and dq modulo 16^(t+1).
Therefore we can test:

    (e*dp + k-1) * (e*dq + l-1)
        == k*l*n             mod 16^(t+1)

Only the newly encountered hexadecimal substitution digits have to be
guessed at each step.

Once the complete substitution is recovered, p and q are reconstructed,
RSA is decrypted, and the flag is extracted from the end of plaintext.
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from multiprocessing import Pool, cpu_count


# =====================================================================
# Constants
# =====================================================================

E = 127
HEX = "0123456789abcdef"
HEX_LEN = 128

# Number of parallel workers.
# Leave one CPU core free for the OS.
WORKERS = max(1, min(cpu_count() - 1, 12))


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


def bar(frac):

    width = 20

    frac = max(
        0.0,
        min(1.0, frac)
    )

    full = int(round(frac * width))

    return (
        "[%s%s] %5.1f%%"
        % (
            "█" * full,
            "░" * (width - full),
            frac * 100.0
        )
    )


def tick(frac, msg):

    line = (
        "%s%s %s%s%s"
        % (
            C.BOLD + C.YELLOW + "▶ ",
            C.CYAN + bar(frac) + C.RESET,
            C.DIM,
            msg,
            C.RESET
        )
    )

    sys.stdout.write(
        "\r  " + line + "   "
    )

    sys.stdout.flush()


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
        "H E X - H E X   S O L V E R",
        "hex substitution -> CRT -> RSA"
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

    dp = extract(
        r"\bdp\s*=\s*([0-9a-fA-F]+)",
        "dp"
    ).lower()

    dq = extract(
        r"\bdq\s*=\s*([0-9a-fA-F]+)",
        "dq"
    ).lower()

    ct = int(
        extract(
            r"\bct\s*=\s*(\d+)",
            "ct"
        )
    )

    return n, e, dp, dq, ct


# =====================================================================
# Fast modular equation
# =====================================================================

def check_equation(
    D,
    Q,
    k,
    l,
    n,
    modulus
):
    """
    Check:

        (eD+k-1)(eQ+l-1) = kl*n mod modulus
    """

    left = (
        (E * D + k - 1) *
        (E * Q + l - 1)
    )

    right = (
        k *
        l *
        n
    )

    return (
        (left - right) %
        modulus
    ) == 0


# =====================================================================
# One k,l search
# =====================================================================

def solve_kl(args):

    (
        k,
        l,
        n,
        dp_enc,
        dq_enc
    ) = args

    # Reverse strings because we recover from LSB -> MSB.
    pd = [
        int(x, 16)
        for x in reversed(dp_enc)
    ]

    qd = [
        int(x, 16)
        for x in reversed(dq_enc)
    ]

    # mapping[encrypted_digit] = original_digit
    mapping = [-1] * 16

    # used original digits
    used = 0

    # Current dp/dq modulo 16^t.
    D = 0
    Q = 0

    # --------------------------------------------------------------
    # Recursive digit solver
    # --------------------------------------------------------------

    def dfs(
        pos,
        D,
        Q,
        mapping,
        used
    ):

        power = 16 ** pos

        if pos == HEX_LEN:

            # Full values recovered.
            numerator_p = E * D - 1
            numerator_q = E * Q - 1

            if numerator_p % k != 0:
                return None

            if numerator_q % l != 0:
                return None

            p = numerator_p // k + 1
            q = numerator_q // l + 1

            if p * q != n:
                return None

            return (
                tuple(mapping),
                D,
                Q,
                p,
                q
            )

        a = pd[pos]
        b = qd[pos]

        # ----------------------------------------------------------
        # Candidate original digit for dp[pos]
        # ----------------------------------------------------------

        if mapping[a] != -1:

            candidates_a = (
                mapping[a],
            )

        else:

            candidates_a = [
                x
                for x in range(16)
                if not (used & (1 << x))
            ]

        # ----------------------------------------------------------
        # Try candidate A
        # ----------------------------------------------------------

        for va in candidates_a:

            if mapping[a] == -1:

                m1 = mapping.copy()
                m1[a] = va

                used1 = (
                    used |
                    (1 << va)
                )

            else:

                m1 = mapping
                used1 = used

            # ------------------------------------------------------
            # Candidate for dq[pos]
            # ------------------------------------------------------

            if m1[b] != -1:

                candidates_b = (
                    m1[b],
                )

            else:

                candidates_b = [
                    x
                    for x in range(16)
                    if not (used1 & (1 << x))
                ]

            for vb in candidates_b:

                if mapping[b] == -1:

                    m2 = m1.copy()
                    m2[b] = vb

                    used2 = (
                        used1 |
                        (1 << vb)
                    )

                else:

                    m2 = m1
                    used2 = used1

                # --------------------------------------------------
                # New partial values
                # --------------------------------------------------

                D2 = D + va * power
                Q2 = Q + vb * power

                modulus = power * 16

                # --------------------------------------------------
                # Main modular constraint
                # --------------------------------------------------

                if not check_equation(
                    D2,
                    Q2,
                    k,
                    l,
                    n,
                    modulus
                ):
                    continue

                result = dfs(
                    pos + 1,
                    D2,
                    Q2,
                    m2,
                    used2
                )

                if result is not None:

                    return result

        return None

    return dfs(
        0,
        0,
        0,
        mapping,
        used
    )


# =====================================================================
# Generate k,l candidates
# =====================================================================

def generate_candidates(
    n,
    e,
    dp,
    dq
):

    candidates = []

    # The actual factors are generated as 512-bit primes.
    # Thus p and q are in [2^511, 2^512).
    #
    # dp = (k*(p-1)+1)/e
    #
    # We can use the leading substituted hex digit to narrow k,
    # but the substitution is unknown. We therefore keep the
    # complete small k/l space.

    for k in range(1, e):

        for l in range(1, e):

            candidates.append(
                (
                    k,
                    l,
                    n,
                    dp,
                    dq
                )
            )

    return candidates


# =====================================================================
# Recover RSA
# =====================================================================

def recover_key(
    n,
    e,
    dp,
    dq
):

    step(
        "building k/l search space"
    )

    candidates = generate_candidates(
        n,
        e,
        dp,
        dq
    )

    total = len(candidates)

    ok(
        "%d CRT combinations prepared"
        % total
    )

    step(
        "launching %d parallel workers"
        % WORKERS
    )

    started = time.time()

    # --------------------------------------------------------------
    # Multiprocessing
    # --------------------------------------------------------------

    with Pool(
        processes=WORKERS
    ) as pool:

        iterator = pool.imap_unordered(
            solve_kl,
            candidates,
            chunksize=1
        )

        checked = 0

        for result in iterator:

            checked += 1

            if checked % 100 == 0:

                tick(
                    checked / total,
                    "testing CRT candidates %d/%d"
                    % (
                        checked,
                        total
                    )
                )

            if result is not None:

                # Stop workers as soon as a solution appears.
                pool.terminate()

                elapsed = (
                    time.time() -
                    started
                )

                print()

                ok(
                    "solution found after %d candidates"
                    % checked
                )

                ok(
                    "search time %.2f seconds"
                    % elapsed
                )

                return result

    raise RuntimeError(
        "no valid RSA solution found"
    )


# =====================================================================
# Show substitution
# =====================================================================

def show_mapping(mapping):

    step(
        "recovered hexadecimal substitution"
    )

    print()

    print(
        "    encrypted : %s"
        % HEX
    )

    print(
        "    original  : %s"
        %
        "".join(
            format(mapping[i], "x")
            for i in range(16)
        )
    )

    print()

    for i in range(16):

        print(
            "      %x -> %x"
            % (
                i,
                mapping[i]
            )
        )


# =====================================================================
# Decrypt RSA
# =====================================================================

def decrypt(
    n,
    e,
    p,
    q,
    ct
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
        ct,
        d,
        n
    )

    block = (
        n.bit_length() // 8
    ) - 1

    plaintext = m.to_bytes(
        block,
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

    # --------------------------------------------------------------
    # Fallback:
    # flag is at the end of plaintext.
    # --------------------------------------------------------------

    printable = re.findall(
        rb"[ -~]{4,}",
        plaintext
    )

    for item in reversed(printable):

        try:
            candidate = item.decode(
                "utf-8"
            )
        except UnicodeDecodeError:
            continue

        if (
            "{" in candidate and
            "}" in candidate
        ):

            return candidate

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
            dp,
            dq,
            ct
        ) = load_output(
            output
        )

        print()

        step(
            "n bits = %d"
            % n.bit_length()
        )

        step(
            "e = %d"
            % e
        )

        step(
            "dp length = %d"
            % len(dp)
        )

        step(
            "dq length = %d"
            % len(dq)
        )

        step(
            "workers = %d"
            % WORKERS
        )

        # ----------------------------------------------------------
        # Validation
        # ----------------------------------------------------------

        if e != E:

            fail(
                "unexpected e=%d (expected %d)"
                % (
                    e,
                    E
                )
            )

            return

        if len(dp) != HEX_LEN:

            fail(
                "unexpected dp length"
            )

            return

        if len(dq) != HEX_LEN:

            fail(
                "unexpected dq length"
            )

            return

        ok(
            "challenge parameters validated"
        )

        print()

        # ----------------------------------------------------------
        # Recover key
        # ----------------------------------------------------------

        (
            mapping,
            dp_value,
            dq_value,
            p,
            q
        ) = recover_key(
            n,
            e,
            dp,
            dq
        )

        print()

        show_mapping(
            mapping
        )

        print()

        step(
            "recovered CRT exponents"
        )

        print(
            "    dp = %0128x"
            % dp_value
        )

        print(
            "    dq = %0128x"
            % dq_value
        )

        print()

        step(
            "recovered RSA primes"
        )

        print(
            "    p = %d"
            % p
        )

        print(
            "    q = %d"
            % q
        )

        # ----------------------------------------------------------
        # Decrypt
        # ----------------------------------------------------------

        print()

        plaintext = decrypt(
            n,
            e,
            p,
            q,
            ct
        )

        print()

        # Useful debugging output
        print(
            "    plaintext = %r"
            % plaintext
        )

        print()

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
            "flag_from_hexhex.txt"
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