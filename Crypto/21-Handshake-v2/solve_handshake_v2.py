#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HANDSHAKE-V2  -  FlagYard Crypto solver  (LWE key-exchange -> recover the
small secret with a Kannan-embedding lattice + LLL, then open the sealed flag)

Hard / Crypto

The remote service runs an "LWE key exchange".  It publishes

    N = 64                 (dimension)
    Q = 268435399          (prime modulus)
    M                      (a N x N matrix over Z_Q)
    b = M*s + 2*eS  (mod Q)     <- a public LWE sample
    flag = AESGCM( sha256(canon(s)), FLAG )   (nonce || ciphertext, hex)

where the SECRET s and the NOISE eS are both "small":

    s[i], eS[i]  in  [-BOUND, BOUND] = [-64, 64]

So b is a textbook LWE sample with modulus Q, dimension N, and a *very*
short secret and error.  Nothing about the handshake is needed: the flag
key is  key = sha256(canon(s)), and if we recover s we decrypt directly.

Attack: build the primal Kannan-embedding lattice

    B = [ Q*I_m     | 0       | 0 ]     (m rows)  noise block
        [ M^T       | I_n*sc  | 0 ]     (n rows)  secret block
        [ b^T       | 0       | 1 ]     (1 row )  embedding marker

whose short vectors are of the shape (e, s, +-1).  After LLL a row with
last coordinate +-1 and a secret part inside [-BOUND, BOUND] IS the
solution.  We then try s and -s (LLL sign is arbitrary) against the
sealed flag.

LLL is done through sympy's Matrix.lll (no fpylll / Sage needed) - the
dimension (2N+1 = 129) reduces in a few seconds.

Solver pipeline:

    1. connect to host:port, solve the 4-bit sha256 proof-of-work
    2. read N, Q, M, b, flag, sessions
    3. build the embedding lattice and LLL it with sympy
    4. scan reduced rows for the short (e, s) vector -> candidate secret(s)
    5. key = sha256(canon(s)), AESGCM-decrypt the sealed flag
    6. print the flag box + save flag_from_handshake_v2.txt

Usage:

    python solve_handshake_v2.py            # interactive: asks for the target
    python solve_handshake_v2.py <host> <port>
    python solve_handshake_v2.py tcp://host:port

The target can be given as `host`, `host:port` or a full url
(`tcp://tcp.flagyard.com:25418`); the default port is 25418.

Interactive mode asks for the environment link first and, if the
connection is refused (environment still starting / port changed), offers
to retry with a new link instead of quitting.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import sys
import time

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
    for t in ("HANDSHAKE-V2   S O L V E R",
              "LWE key exchange  |  short-secret LLL  ->  flag"):
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
# target handling (interactive prompt + url parsing)
# ---------------------------------------------------------------------------
DEFAULT_HOST = "tcp.flagyard.com"
DEFAULT_PORT = 25418

def parse_target(raw, default_host=DEFAULT_HOST, default_port=DEFAULT_PORT):
    """Accept 'host', 'host:port', 'tcp://host:port', 'http://host:port/path'."""
    s = (raw or "").strip().strip('"').strip("'")
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if not s:
        return default_host, default_port
    if s.startswith("["):                      # [ipv6]:port
        host, _, rest = s.partition("]")
        host = host[1:]
        ps = rest.lstrip(":")
        try:
            return host, int(ps) if ps else default_port
        except ValueError:
            return host, default_port
    if ":" in s:
        host, _, ps = s.partition(":")
        try:
            return (host or default_host), int(ps)
        except ValueError:
            return (host or default_host), default_port
    return s, default_port

def prompt_target():
    print()
    print("  %s┌─ target ───────────────────────────────────────────%s" % (C.CYAN, C.RESET))
    print("  %s│%s  %s" % (C.CYAN, C.RESET, C.BOLD + "host:port" + C.RESET + C.DIM +
          "   (a full url is accepted too)"))
    print("  %s│%s  %s" % (C.CYAN, C.RESET, C.DIM + "e.g. %s:%d   or   tcp://%s:%d"
          % (DEFAULT_HOST, DEFAULT_PORT, DEFAULT_HOST, DEFAULT_PORT) + C.RESET))
    print("  %s└───────────────────────────────────────────────────%s" % (C.CYAN, C.RESET))
    try:
        raw = input("  %s>%s " % (C.BOLD + C.CYAN, C.RESET)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return parse_target(raw)

# ---------------------------------------------------------------------------
# protocol helpers
# ---------------------------------------------------------------------------
def dec(txt, count):
    raw = base64.b64decode(txt.split("=", 1)[1].strip())
    return [int.from_bytes(raw[4 * i:4 * i + 4], "big") for i in range(count)]

def solve_pow(chal, bits=4):
    i = 0
    while True:
        x = format(i, "x")
        if hashlib.sha256((chal + x).encode()).hexdigest().startswith("0" * bits):
            return x
        i += 1

def recv_block(host, port):
    s = socket.create_connection((host, port), timeout=30)
    f = s.makefile("rw")
    rd = lambda: f.readline().rstrip("\n")
    wr = lambda m: (f.write(m + "\n"), f.flush())

    rd()                                    # banner line 1
    rd()                                    # banner line 2 (pow spec)
    chal = rd().split("=", 1)[1].strip()
    wr(solve_pow(chal))
    if rd() != "ok":
        raise RuntimeError("pow rejected")
    N = int(rd().split("=", 1)[1])
    Q = int(rd().split("=", 1)[1])
    Mflat = dec(rd(), N * N)
    M = [Mflat[i * N:(i + 1) * N] for i in range(N)]
    b = dec(rd(), N)
    flaghex = rd().split("=", 1)[1].strip()
    rd()                                    # sessions
    s.close()
    return N, Q, M, b, flaghex

# ---------------------------------------------------------------------------
# lattice attack
# ---------------------------------------------------------------------------
def recover_secret(N, Q, M, b, BOUND=64):
    """Return a list of candidate secret vectors s (small) solving
    b = M*s + 2*eS (mod Q)."""
    from sympy import Matrix

    m = N
    n = N
    rows = []
    # noise block: q*e_i
    for i in range(m):
        row = [0] * (m + n + 1)
        row[i] = Q
        rows.append(row)
    # secret block: column j of M  +  unit in secret block
    for j in range(n):
        row = [0] * (m + n + 1)
        for i in range(m):
            row[i] = M[i][j]
        row[m + j] = 1
        rows.append(row)
    # embedding row: b + marker
    row = [0] * (m + n + 1)
    for i in range(m):
        row[i] = b[i]
    row[m + n] = 1
    rows.append(row)

    L = Matrix(rows).lll()

    cands = []
    for r in L.tolist():
        if abs(r[m + n]) != 1:
            continue
        s_part = [int(x) for x in r[m:m + n]]
        if all(-BOUND - 2 <= x <= BOUND + 2 for x in s_part):
            cands.append(s_part)
            cands.append([-x for x in s_part])
    return cands

def try_open(N, flaghex, s):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    canon = ",".join(str(i) for i in s).encode()
    key = hashlib.sha256(canon).digest()
    blob = bytes.fromhex(flaghex)
    nonce, ct = blob[:12], blob[12:]
    try:
        pt = AESGCM(key).decrypt(nonce, ct, None)
        return pt.decode("utf-8", "replace").strip()
    except Exception:
        return None

# ---------------------------------------------------------------------------
def main():
    t0 = time.time()
    enable_vt()
    banner()

    args = sys.argv[1:]
    scripted = len(args) >= 1
    if len(args) >= 2:                        # scripted mode: host port
        host = parse_target(args[0])[0]
        port = int(args[1])
    elif len(args) == 1:                      # scripted mode: url / host[:port]
        host, port = parse_target(args[0])
    else:                                     # interactive: ask the user
        tgt = prompt_target()
        if not tgt:
            fail("no target given")
            return
        host, port = tgt

    # connect (interactive mode may ask for a new target on failure)
    while True:
        status(0.05, "target %s:%d" % (host, port))
        try:
            N, Q, M, b, flaghex = recv_block(host, port)
            break
        except Exception as e:
            fail("connection failed: %s" % e)
            if scripted:
                return
            print()
            print("  %s[!] the challenge environment may still be starting, or the"
                  % C.YELLOW)
            print("      port changed - ask for the current link and try again.")
            try:
                again = input("  %sretry?%s [y/N] " % (C.BOLD + C.CYAN, C.RESET)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if again not in ("y", "yes"):
                return
            tgt = prompt_target()
            if not tgt:
                return
            host, port = tgt

    ok(0.20, "handshake received (N=%d, Q=%d, sealed flag %d bytes)"
       % (N, Q, len(flaghex) // 2))

    status(0.35, "building Kannan-embedding lattice (%d x %d) + LLL ..."
           % (2 * N + 1, 2 * N + 1))
    try:
        cands = recover_secret(N, Q, M, b)
    except Exception as e:
        fail("lattice attack failed: %s" % e)
        return
    ok(0.75, "%d candidate secret(s) from reduced basis" % (len(cands) // 2))

    status(0.85, "testing candidates against the sealed flag ...")
    flag = None
    for s in cands:
        got = try_open(N, flaghex, s)
        if got:
            flag = got
            break
    if not flag:
        fail("no candidate opened the flag (re-run: instance key changes each connect)")
        return

    ok(1.0, "FLAG = %s" % flag)
    big_flag(flag, time.time() - t0,
             "short-secret LLL (N=64) | b = M*s+2*eS -> sha256(canon(s)) -> AESGCM")
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "flag_from_handshake_v2.txt")
    with open(outp, "w", encoding="utf-8") as fh:
        fh.write(flag + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()
