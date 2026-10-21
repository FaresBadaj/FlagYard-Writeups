#!/usr/bin/env python3
"""
Power of Statistics  -  FlagYard hardware/side-channel CPA solver (colored edition)

The "device" is a custom STM32F3 (ChipWhisperer CW308) firmware that encrypts a
16-byte plaintext with a handmade 8-round block cipher:

    for round in 8:
        t[i]       = sbox[ key[i] ^ pt[i] ]          for i in 0..15
        new[0..7]  = t[7], t[0], t[1], ... t[6]       (rotate t first byte)
        new[8+i]   = t[i] ^ t[8+i]                    for i in 0..7

known from the Thumb disassembly of get_pt() @ 0x0800025c and the decompiled
listing.  The custom S-box and a decoy key ("FlagY{DummyFlag}") live in .data:
the 256-byte table is copied to 0x20000000 and the 16-byte dummy key to
0x20000100.

The encryption is surrounded by the power trigger, and the challenge ships
1000 (plaintext, trace) pairs (1000x16 and 1000x1500 float64).  The sensitive
operation is the S-box lookup  sbox[key[i] ^ pt[i]]  ->  a textbook Hamming
weight leakage sink.  So we run a byte-by-byte Correlation Power Analysis
(CPA) with the Hamming-weight model, pick the key byte that maximizes the
Pearson correlation against the trace columns, and recover all 16 key bytes.

With the 16-byte key in hand we invert the 8-round function the same 8 times
(inverse S-box, un-rotate, undo the byte-XOR mix) and decrypt the bundled
encrypted_flag block.  A re-encryption round-trip proves the key before the
flag is printed and saved to flag_from_power_of_statistics.txt.

Solver: pure Python 3 + numpy, stdlib ELF section table parsing (no pyelftools).
Output uses the same fixed-width 62-column frame with author credits as the
other FlagYard solvers.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

import numpy as np

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
    for t in ("P O W E R   O F   S T A T I S T I C S   S O L V E R",
              "CPA on 1000 CW308 traces: 16 key bytes -> 1 flag"):
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
# stdlib ELF32 section-table reader (no pyelftools needed)
# ---------------------------------------------------------------------------
def elf_section(blob, want):
    """Return (content_bytes, sh_addr) of the section named `want` (ELF32)."""
    if blob[:4] != b"\x7fELF" or blob[4] != 1 or blob[5] != 1:
        raise ValueError("not a little-endian ELF32 file")
    e_shoff = struct.unpack_from("<I", blob, 0x20)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x2E)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x30)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x32)[0]
    shstr_off, shstr_size = None, None
    for n in range(e_shnum):
        off = e_shoff + n * e_shentsize
        s_name, s_type, s_flags, s_addr = struct.unpack_from("<IIII", blob, off)
        s_offset, s_size = struct.unpack_from("<II", blob, off + 16)
        if n == e_shstrndx:
            shstr_off, shstr_size = s_offset, s_size
    if shstr_off is None:
        raise ValueError("no section-name string table")
    for n in range(e_shnum):
        off = e_shoff + n * e_shentsize
        s_name, s_type = struct.unpack_from("<II", blob, off)[:2]
        s_addr = struct.unpack_from("<I", blob, off + 12)[0]
        s_offset, s_size = struct.unpack_from("<II", blob, off + 16)
        name = blob[shstr_off + s_name: shstr_off + s_name + (shstr_size - s_name)].split(b"\x00")[0]
        w = want.encode("latin1")
        if name == w:
            return blob[s_offset: s_offset + s_size], s_addr
    raise ValueError("no section named %r" % want)

# ---------------------------------------------------------------------------
# custom 8-round cipher (Thumb get_pt @ 0x0800025c) + its inverse
# ---------------------------------------------------------------------------
def build_cipher(sbox):
    sinv = np.zeros(256, dtype=np.uint8)
    sinv[sbox.astype(int)] = np.arange(256, dtype=np.uint8)
    return sinv

def enc_block(state, key, sbox):
    st = bytearray(bytes(state))
    k = bytes(key)
    for _ in range(8):
        t = bytearray(16)
        for i in range(16):
            t[i] = int(sbox[st[i] ^ k[i]])
        new = bytearray(16)
        for i in range(8):
            new[i] = t[(i - 1) % 8]          # new[0]=t[7], new[1]=t[0], ...
        for i in range(8):
            new[8 + i] = t[i] ^ t[8 + i]
        st = new
    return bytes(st)

def dec_block(ct, key, sbox, sinv):
    st = bytearray(bytes(ct))
    k = bytes(key)
    for _ in range(8):
        t = bytearray(16)
        for i in range(8):
            t[i] = st[(i + 1) % 8]           # undo new[0..7] = rotate(t)
        for i in range(8):
            t[8 + i] = st[8 + i] ^ t[i]      # undo new[8+i] = t[i] ^ t[8+i]
        prev = bytearray(16)
        for i in range(16):
            prev[i] = int(sinv[t[i]]) ^ k[i] # undo t[i] = sbox[key[i]^pt[i]]
        st = prev
    return bytes(st)

# ---------------------------------------------------------------------------
# CPA
# ---------------------------------------------------------------------------
def hamming_weight(vals):
    hw = np.zeros(vals.shape, dtype=np.float64)
    v = vals.astype(np.uint32)
    while v.any():
        hw += (v & 1).astype(np.float64)
        v >>= 1
    return hw

def cpa_recover_key(traces, plain, sbox):
    """Byte-by-byte CPA with a Hamming-weight model on the S-box output."""
    N, S = traces.shape
    Tm = traces - traces.mean(axis=0, keepdims=True)
    Tstd = traces.std(axis=0)
    Tstd[Tstd < 1e-9] = 1e-9
    key = bytearray(16)
    per_byte = []
    for b in range(16):
        idx = plain[:, b, None] ^ np.arange(256, dtype=np.uint8)[None, :]  # (N,256)
        hw = hamming_weight(np.take(sbox, idx))
        Hm = hw - hw.mean(axis=0, keepdims=True)
        Hstd = hw.std(axis=0)
        Hstd[Hstd < 1e-9] = 1e-9
        corr = (Tm.T @ Hm) / (Tstd[:, None] * Hstd[None, :] * N)          # (S,256)
        absmax = np.abs(corr).max(axis=0)
        best_k = int(absmax.argmax())
        key[b] = best_k
        per_byte.append((best_k, float(absmax[best_k]),
                         int(np.abs(corr[:, best_k]).argmax())))
    return bytes(key), per_byte

# ---------------------------------------------------------------------------
def run_solve() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    d = Path(__file__).resolve().parent
    elf_path = d / "crypto_firmware.elf"
    if not elf_path.exists():
        fail("crypto_firmware.elf not found next to the solver (%s)" % elf_path)
        return

    status(0.05, "parsing ELF section table (stdlib) for the custom S-box")
    try:
        sbox, sbox_addr = elf_section(elf_path.read_bytes(), ".data")
        if len(sbox) < 0x110:
            fail(".data too small for sbox+key")
            return
    except Exception as e:
        fail("ELF parse error: %s" % e)
        return
    sbox = np.frombuffer(sbox[:256], dtype=np.uint8)
    key_blob, _ = elf_section(elf_path.read_bytes(), ".data")
    dbg = bytes(key_blob[0x100:0x110])
    ok(0.14, ".data @ 0x%08x: 256-byte S-box + 16-byte dummy key @ 0x100" % sbox_addr)
    ok(0.18, "dummy firmware key @ 0x20000100 = %s" % dbg.hex())

    status(0.22, "loading plaintexts + power traces")
    try:
        plain = np.load(d / "plaintext.npy").astype(np.uint8)
        trace_path = d / "traces_aligned.npy"
        if not trace_path.exists():
            trace_path = d / "traces.npy"
        traces = np.load(trace_path)
    except Exception as e:
        fail("trace load error: %s" % e)
        return
    N, S = traces.shape
    ok(0.30, "plaintext %s | traces %s (%d x %d)" % (plain.shape, traces.shape, N, S))

    sinv = build_cipher(sbox)

    status(0.34, "CPA model: HW( sbox[key[i] ^ pt[i]] ) over all 256 key guesses")
    key, per_byte = cpa_recover_key(traces, plain, sbox)
    ok(0.62, "16-byte key recovered by correlation maximization")
    for i, (k, c, smp) in enumerate(per_byte):
        print("   %sbyte %2d: key=0x%02x  corr=%.4f  peak@sample %d%s"
              % (C.DIM, i, k, c, smp, C.RESET))
    ok(0.74, "key = %s" % key.hex())

    status(0.78, "inverting the 8-round custom cipher (inverse S-box, 8x)")
    ct = (d / "encrypted_flag").read_bytes()
    if len(ct) != 16:
        fail("encrypted_flag is %d bytes, expected 16" % len(ct))
        return
    flag = dec_block(ct, key, sbox, sinv)
    ok(0.86, "decrypted 16-byte block")

    status(0.90, "round-trip proof: re-encrypt decrypted block with the same key")
    if enc_block(flag, key, sbox) != ct:
        fail("re-encryption mismatch - key or cipher wrong")
        return
    ok(0.96, "enc(dec(ct)) == ct  ->  key and cipher confirmed")

    if not (flag.startswith(b"FlagY{") and flag.endswith(b"}")):
        fail("decrypted block does not look like a FlagY flag: %r" % flag)
        return

    big_flag(flag.decode("ascii"), time.time() - t0,
             "CPA + custom 8-round cipher inversion")
    out = d / "flag_from_power_of_statistics.txt"
    out.write_text(flag.decode("ascii") + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    run_solve()