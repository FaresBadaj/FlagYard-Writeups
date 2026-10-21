#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASTRAL PROPAGATION  -  FlagYard Crypto Solver

Medium / Crypto

"CBC mode is vulnerable to padding oracle attacks, but what about PCBC?"

The service runs a PCBC AES oracle:

    P_i = D(C_i) XOR C_{i-1} XOR P_{i-1}        (C_0 = IV, P_0 = IV)

and returns:
    * 'failed to decrypt'    -> the padding is invalid     (oracle = False)
    * 'incorrect message'    -> padding valid, not MESSAGE (oracle = True)
    * flag.txt               -> padding valid, == MESSAGE  (oracle = True)

Attack:

    1. Padding oracle on a ONE-block ciphertext (iv, C):

           out = D(C) XOR iv      (pure CBC single-block structure)

       So the classic byte-by-byte CBC padding oracle recovers D(C)
       for ANY chosen block C -> an "AES decryption oracle".

    2. Malleability / forgery.  We know the target plaintext
       T = pad("propagating cipher block chaining")  (3 blocks).
       Walk the PCBC equations backwards and synthesize ciphertext
       blocks so that decrypting yields exactly T:

           P_1 = D(C_1) XOR IV                => IV  = D(C_1) XOR t_1
           P_2 = D(C_2) XOR C_1 XOR P_1        => C_1 = D(C_2) XOR t_1 XOR t_2
           P_3 = D(C_3) XOR C_2 XOR P_2        => C_2 = D(C_3) XOR t_2 XOR t_3

       C_3 is free; recover D(C_3), then C_2, then D(C_2), then C_1,
       then D(C_1), then IV. Send IV||C_1||C_2||C_3 -> decrypts to
       MESSAGE -> the server prints the flag.

Target is given as host:port (default tcp.flagyard.com:31145).
"""
from __future__ import annotations

from pwn import *
import sys
import time
from pathlib import Path

from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

MESSAGE = b'propagating cipher block chaining'
TARGET = pad(MESSAGE, 16)

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
    for t in ("A S T R A L   P R O P A G A T I O N   S O L V E R",
              "PCBC padding oracle -> forge -> flag"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel + author credits
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
    raw = input("  Enter the astral propagation target (host:port): ").strip()
    return raw or "tcp.flagyard.com:31145"

def parse_target(raw):
    raw = raw.replace("tcp://", "").replace("http://", "").rstrip("/")
    if ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, "31145"
    return host, int(port_s)

# ---------------------------------------------------------------------------
# PCBC oracle interaction  (pipelined: 256 guesses in one round-trip per byte)
# ---------------------------------------------------------------------------
def oracle_batch(io, ivs, block):
    """Batch single-block PCBC queries. Returns list of True/False (padding OK)."""
    payload = b'\n'.join((iv + block).hex().encode() for iv in ivs) + b'\n'
    io.send(payload)
    data = b''
    needed = len(ivs)
    got = 0
    while got < needed:
        chunk = io.recv(65536, timeout=20)
        if not chunk:
            break
        data += chunk
        got = data.count(b'failed') + data.count(b'incorrect')
    lines = data.split(b'\n')
    out = []
    for ln in lines:
        if b'failed' in ln:
            out.append(False)
        elif b'incorrect' in ln:
            out.append(True)
    if len(out) < needed:
        return None
    return out[:needed]

def recover_D(io, block):
    """Classic CBC/PCBC byte-by-byte padding oracle -> D(block) (16 bytes).
    Each byte tests all 256 IV values in a single pipelined round-trip."""
    D = bytearray(16)
    for i in range(15, -1, -1):
        pad_len = 16 - i
        ivs = []
        base = bytearray(16)
        for j in range(i + 1, 16):
            base[j] = D[j] ^ pad_len
        for g in range(256):
            iv = bytearray(base)
            iv[i] = g
            ivs.append(bytes(iv))
        res = oracle_batch(io, ivs, block)
        if res is None:
            return None
        found = None
        for g, ok in enumerate(res):
            if ok:
                found = g ^ pad_len
                break
        if found is None:
            return None
        D[i] = found
    return bytes(D)

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(io):
    blocks = [TARGET[i:i+16] for i in range(0, len(TARGET), 16)]
    t1, t2, t3 = blocks

    step("recovering D(C_3)  (block 3)")
    C3 = b'\x00' * 16
    D3 = recover_D(io, C3)
    if D3 is None:
        fail("D(C_3) failed"); return None
    ok("D(C_3) = %s" % D3.hex())

    step("recovering D(C_2)  (block 2)")
    C2 = strxor(D3, strxor(t2, t3))
    D2 = recover_D(io, C2)
    if D2 is None:
        fail("D(C_2) failed"); return None
    ok("D(C_2) = %s" % D2.hex())

    step("recovering D(C_1)  (block 1)")
    C1 = strxor(D2, strxor(t1, t2))
    D1 = recover_D(io, C1)
    if D1 is None:
        fail("D(C_1) failed"); return None
    ok("D(C_1) = %s" % D1.hex())

    IV = strxor(D1, t1)
    ct = IV + C1 + C2 + C3
    ok("forged ciphertext  IV+C1+C2+C3  = %s" % ct.hex())

    step("submitting forged ciphertext")
    io.sendline(ct.hex().encode())
    data = io.recvall(timeout=10)

    import re
    m = re.search(rb"FlagY\{[^}]+\}", data)
    if m:
        return m.group(0).decode()
    if b'failed' in data:
        return "forgery REJECTED (failed to decrypt)"
    if b'incorrect' in data:
        return "forgery decrypted to wrong message"
    return "no flag in response: %r" % data[:200]

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
    try:
        io = remote(host, port, timeout=15)
    except Exception:
        fail("connection failed")
        return

    flag = exploit(io)
    io.close()

    if flag and flag.startswith("FlagY"):
        ok("FLAG = %s" % flag)
        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_astral_propagation.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail(str(flag))

if __name__ == "__main__":
    main()