#!/usr/bin/env python3
"""
incunabula  -  FlagYard Naccache-Stern knapsack solver (colored edition)
"Just another good and strong cryptosystem. Please, decrypt the flag."

The server runs the Naccache-Stern knapsack cryptosystem:

    p      = random 256-bit prime
    primes = the first 64 primes (2 .. 311)
    s      = secret, gcd(s, p-1) == 1
    roots[i] = primes[i]^(s^-1 mod p-1) mod p     ->  roots[i]^s = primes[i]

    encrypt(m): c = product over set bits i of m of roots[i]  (mod p)

The secret s makes decryption free (c^s -> small primes, gcd-recovers bits),
but the FIRST message byte + Legendre symbols break it without the private key:

    legendre(c)  =  product over set bits i of legendre(roots[i])
    legendre(roots[i]) == legendre(primes[i])     (s is odd)
so each ciphertext gives ONE GF(2) linear equation over its 64 message bits.

Every new connection re-encrypts the SAME flag with a fresh (p, s, roots).
N connections -> N independent random Legendre parity equations per 64-bit
chunk -> plain linear algebra over GF(2) recovers every chunk, and the flag
is rebuilt big-endian.

This solver: pure stdlib, gathers Legendre equations until the shared GF(2)
coefficient matrix hits full rank 64 (a few dozen connections), generalizes
Gaussian elimination to each chunk over GF(2), re-encrypts the recovered
chunks against a saved ciphertext instance (round-trip proof) and prints
the flag.  If the rate-limited server is unreachable it falls back to the
bundled incunabula_samples.jsonl cache from the original solution run.
"""
from __future__ import annotations

import ast
import json
import os
import socket
import sys
import time
from pathlib import Path

HOST = "tcp.flagyard.com"
PORT = 26167
NBITS = 64          # message bits per chunk (== nprimes)
NCONN = 220         # soft cap of connections per solve run
CACHE = Path(__file__).resolve().parent / "incunabula_samples.jsonl"

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
    for t in ("I N C U N A B U L A   S O L V E R",
              "Naccache-Stern knapsack  |  Legendre parity leak"):
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
    _row([(" " * 7, "", ""), (line[:44], C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# network / capture
# ---------------------------------------------------------------------------
def fetch_once():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((HOST, PORT))
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()
    return data

def parse(data):
    text = data.decode("utf-8", errors="replace")
    d_end = text.rindex("}") + 1
    pd = ast.literal_eval(text[text.index("{"): d_end])
    cts = ast.literal_eval(text[text.index("[", d_end): text.rindex("]") + 1])
    return pd, cts

def legendre_bit(x, p):
    """0 if x is a quadratic residue mod p, 1 otherwise."""
    return 0 if pow(x, (p - 1) // 2, p) == 1 else 1

def _gauss_rank(masks, nbits):
    m = masks[:]
    r = 0
    for c in range(nbits):
        sel = None
        for i in range(r, len(m)):
            if (m[i] >> c) & 1:
                sel = i
                break
        if sel is None:
            continue
        m[r], m[sel] = m[sel], m[r]
        for i in range(len(m)):
            if i != r and ((m[i] >> c) & 1):
                m[i] ^= m[r]
        r += 1
    return r


def load_cache():
    """Reuse previously captured instances when the server is unreachable."""
    if not CACHE.exists():
        return None
    samples = []
    for line in CACHE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            samples.append(json.loads(line))
    return samples or None


def capture(nconn):
    """Return list of (p, row[64], rhs[chunks]) captured from live server.
    Keeps connecting until the shared GF(2) coefficient matrix has full
    rank (64), which makes every chunk's equation system solvable.
    Falls back to the bundled cache file if the server is unavailable."""
    samples = []
    masks = []
    offline = False
    while len(samples) < nconn:
        try:
            data = fetch_once()
            pd, cts = parse(data)
            row = [legendre_bit(r, pd["p"]) for r in pd["roots"]]
            rhs = [legendre_bit(c, pd["p"]) for c in cts]
            samples.append({"p": pd["p"], "row": row, "rhs": rhs,
                            "roots": pd["roots"], "cts": cts, "primes": pd["primes"]})
            masks.append(sum(row[i] * (1 << i) for i in range(NBITS)))
            rank = _gauss_rank(masks, NBITS)
            status((len(samples) - 1) / nconn,
                   "captured connection %2d/%d  (chunks=%d, rank %2d/64)"
                   % (len(samples), nconn, len(cts), rank))
            if rank == NBITS:
                break
        except Exception as e:
            if not offline:
                cached = load_cache()
                if cached:
                    print("  %s[!] server unavailable (%s) - falling back to cache (%d samples)%s"
                          % (C.YELLOW, e, len(cached), C.RESET), flush=True)
                    return cached
                offline = True
            time.sleep(0.4)
    if not samples:
        cached = load_cache()
        if cached:
            return cached
        raise SystemExit("could not reach server and no cache file found")
    return samples

# ---------------------------------------------------------------------------
# GF(2) Gaussian elimination
# ---------------------------------------------------------------------------
def gauss_solve(A, b, nbits):
    """Solve A x = b over GF(2).  A: list of int bitmasks, b: list of 0/1."""
    mat = [(m | ((r & 1) << nbits)) for m, r in zip(A, b)]
    n = len(mat)
    piv = {}
    r = 0
    for c in range(nbits):
        sel = None
        for i in range(r, n):
            if (mat[i] >> c) & 1:
                sel = i
                break
        if sel is None:
            continue
        mat[r], mat[sel] = mat[sel], mat[r]
        piv[c] = r
        pr = mat[r]
        for i in range(n):
            if i != r and ((mat[i] >> c) & 1):
                mat[i] ^= pr
        r += 1
    # every leftover row must be 0 == 0 (any 0 == 1 would mean corruption)
    for i in range(r, n):
        if ((mat[i] >> nbits) & 1) == 1:
            raise ValueError("inconsistent GF(2) system (all-zero row, rhs=1)")
    sol = 0
    for c, rr in piv.items():
        if (mat[rr] >> nbits) & 1:
            sol |= (1 << c)
    return sol, len(piv)

def encrypt_int(pt, roots, p):
    c = 1
    for i, root in enumerate(roots):
        if (pt >> i) & 1:
            c = (c * root) % p
    return c

# ---------------------------------------------------------------------------
def main() -> None:
    enable_vt()
    banner()
    t0 = time.time()

    status(0.04, "connecting to %s:%d  (gather until GF(2) rank 64)"
           % (HOST, PORT))
    samples = capture(NCONN)
    nchunks = len(samples[0]["rhs"])
    ok(0.30, "%d instances loaded, %d x 64-bit chunks each"
             % (len(samples), nchunks))

    status(0.34, "building GF(2) Legendre parity equations")
    Abits = [sum(s["row"][i] * (1 << i) for i in range(NBITS)) for s in samples]
    chunks = []
    for j in range(nchunks):
        B = [s["rhs"][j] for s in samples]
        sol, rank = gauss_solve(Abits, B, NBITS)
        chunks.append(sol)
        ok(0.40 + 0.40 * (j + 1) / nchunks,
           "chunk %2d: rank %2d/64 -> 0x%016x" % (j, rank, sol))

    status(0.82, "rebuilding the flag from its 64-bit chunks, big-endian")
    plain = 0
    for j in range(nchunks):
        plain |= chunks[j] << (64 * j)
    nbytes = (plain.bit_length() + 7) // 8
    flag_bytes = plain.to_bytes(nbytes, "big")
    ok(0.87, "%d bytes recovered" % len(flag_bytes))

    status(0.90, "round-trip: re-encrypting chunks on a captured instance")
    s0 = next((s for s in samples if "roots" in s and "cts" in s), None)
    if s0 is None:
        fail("no cached instance with roots/ciphertexts for round-trip proof"); return
    checks = [encrypt_int(chunks[j], s0["roots"], s0["p"]) == s0["cts"][j]
              for j in range(nchunks)]
    if not all(checks):
        fail("round-trip re-encryption mismatch"); return
    ok(0.94, "%d/%d chunks re-encrypt to the observed ciphertexts (proof)"
             % (sum(checks), nchunks))

    flag = flag_bytes.decode("latin1").rstrip("\n").rstrip("\r")
    if not (flag.startswith("FlagY{") and flag.endswith("}")):
        fail("recovered bytes do not look like a FlagY{} flag"); return
    ok(0.97, "valid FlagY{} format")

    big_flag(flag, time.time() - t0,
             "Legendre parity over %d live instances (GF(2) rank 64/chunk)"
             % len(samples))
    out = Path(__file__).resolve().parent / "flag_from_incunabula.txt"
    out.write_text(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    main()