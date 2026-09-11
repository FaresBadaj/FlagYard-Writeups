#!/usr/bin/env python3
"""
Cryp70  -  FlagYard reversing solver (colored edition)
Serpent-256/ECB + MSVCRT rand()-derived key; brute-forces the small seed
space and re-verifies the seed<=>plaintext relation.

Requires libgcrypt (run on Linux/WSL; e.g. sudo apt install libgcrypt20).
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# colored output (same design as the mra / NOSJ / phone_book solvers)
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

def bar(frac, width=22):
    filled = int(frac * width)
    return "\u2588" * filled + "\u2591" * (width - filled)

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
    print("  \u2551            C R Y P 70   S O L V E R            \u2551")
    print("  \u2551  Serpent-256/ECB + MSVCRT rand() key  |  Reversing \u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# result panel (fixed-width frame) + author credits
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

def big_flag(seed, key, flag, chrono):
    line = flag.strip().splitlines()[0]
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, "seed = %d" % seed):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# core solver
# ---------------------------------------------------------------------------
SERPENT256 = 306
GCRY_CIPHER_MODE_ECB = 1
FLAG_LENGTH = 48


def load_libgcrypt() -> ctypes.CDLL:
    library_name = ctypes.util.find_library("gcrypt") or "libgcrypt.so.20"
    try:
        lib = ctypes.CDLL(library_name)
    except Exception:
        try:
            lib = ctypes.CDLL("libgcrypt.so")
        except Exception:
            raise RuntimeError(
                "libgcrypt not found on this system.\n"
                "        run the solver on Linux / WSL (sudo apt install libgcrypt20)."
            )

    lib.gcry_check_version.restype = ctypes.c_char_p
    lib.gcry_cipher_open.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    lib.gcry_cipher_open.restype = ctypes.c_uint
    lib.gcry_cipher_setkey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    lib.gcry_cipher_setkey.restype = ctypes.c_uint
    lib.gcry_cipher_decrypt.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    lib.gcry_cipher_decrypt.restype = ctypes.c_uint
    lib.gcry_cipher_close.argtypes = [ctypes.c_void_p]
    if not lib.gcry_check_version(None):
        raise RuntimeError("libgcrypt initialization failed")
    return lib


def generate_key(seed: int) -> bytes:
    """MSVCRT srand/rand reproduction, with the binary's XOR 0x9d step."""
    state = seed & 0xFFFFFFFF
    key = bytearray()
    for _ in range(32):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        rand_value = (state >> 16) & 0x7FFF
        key.append((rand_value % 256) ^ 0x9D)
    return bytes(key)


def to_signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def derive_seed(plaintext: bytes) -> int:
    """Reproduce sum((signed_char)byte ^ 0xbb) with 32-bit arithmetic."""
    total = 0
    for byte in plaintext:
        signed_byte = byte if byte < 128 else byte - 256
        total = (total + (signed_byte ^ 0xBB)) & 0xFFFFFFFF
    return to_signed32(total)


def is_printable_flag(data: bytes) -> bool:
    return all(32 <= byte < 127 for byte in data) and data.endswith(b"}")


def make_backend():
    """Prefer libgcrypt (Linux/WSL) -> PyCryptodome -> embedded pure-Python."""
    try:
        load_libgcrypt()
        return ("gcrypt", None)
    except Exception:
        pass
    try:
        from Crypto.Cipher import Serpent
        return ("pycrypto", Serpent)
    except Exception:
        pass
    try:
        import serpent_py
        return ("pyserpent", serpent_py)
    except Exception:
        pass
    raise RuntimeError(
        "no cipher backend available.\n"
        "        the bundled serpent_py.py should be next to this script;\n"
        "        or install PyCryptodome (pip install pycryptodome)\n"
        "        or run on Linux / WSL with libgcrypt."
    )


def decrypt_block(backend, name, key, ciphertext, gcrypt_ctx=None):
    if name == "gcrypt":
        lib, handle, key_buffer, output, buf = gcrypt_ctx
        ctypes.memmove(key_buffer, key, 32)
        error = lib.gcry_cipher_setkey(handle, key_buffer, 32)
        if error:
            raise RuntimeError("gcry_cipher_setkey failed: %d" % error)
        error = lib.gcry_cipher_decrypt(handle, output, len(ciphertext), buf, len(ciphertext))
        if error:
            raise RuntimeError("gcry_cipher_decrypt failed: %d" % error)
        return output.raw[: len(ciphertext)]
    if name == "pycrypto":
        return backend.new(key, backend.MODE_ECB).decrypt(ciphertext)
    return backend.Serpent(key).decrypt(ciphertext)


def solve(ciphertext: bytes, progress=None) -> list:
    name, backend = make_backend()

    gcrypt_ctx = None
    total = FLAG_LENGTH * 255 + 1
    results: list = []
    last_dir = -1
    try:
        if name == "gcrypt":
            lib = load_libgcrypt()
            handle = ctypes.c_void_p()
            error = lib.gcry_cipher_open(
                ctypes.byref(handle), SERPENT256, GCRY_CIPHER_MODE_ECB, 0)
            if error:
                raise RuntimeError("gcry_cipher_open failed: %d" % error)
            gcrypt_ctx = (lib, handle, ctypes.create_string_buffer(32),
                          ctypes.create_string_buffer(len(ciphertext)),
                          ctypes.create_string_buffer(ciphertext))
        for seed in range(total):
            if progress is not None:
                prog = (seed + 1) / total
                per10 = int(prog * 20)  # redraw every 5%
                if per10 != last_dir:
                    last_dir = per10
                    progress(prog, "serpent256-ecb (%s)  seed=%d" % (name, seed))
            plaintext = decrypt_block(backend, name, generate_key(seed),
                                      ciphertext, gcrypt_ctx)
            if derive_seed(plaintext) == seed and is_printable_flag(plaintext):
                results.append((seed, generate_key(seed), plaintext))
    finally:
        if gcrypt_ctx is not None:
            gcrypt_ctx[0].gcry_cipher_close(gcrypt_ctx[1])
    return results


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    enable_vt()
    banner()

    parser = argparse.ArgumentParser(
        description="Solve FlagYard Cryp70 (Serpent-256/ECB + rand() key)")
    parser.add_argument("ciphertext", type=Path, nargs="?", default=None,
                        help="path to enc_flag.txt (default: next to this script)")
    args = parser.parse_args()

    cip = args.ciphertext or (Path(__file__).resolve().parent / "enc_flag.txt")
    print("  %s[ target : %s%s%s ]%s\n" % (C.GRAY, C.CYAN, cip.name, C.RESET, C.RESET))
    t0 = time.time()

    try:
        data = cip.read_bytes()
    except Exception as exc:
        fail("cannot read ciphertext: %s" % exc); return
    if len(data) != FLAG_LENGTH:
        fail("expected %d bytes of ciphertext, got %d" % (FLAG_LENGTH, len(data))); return
    ok(0.06, "ciphertext loaded (%d bytes)  %s" % (len(data), data.hex()))

    total = FLAG_LENGTH * 255 + 1
    last_dir = -1

    def progress(frac, label):
        sys.stdout.write("\r%s  %s%5.1f%%%s %s%s  %s   " %
                         (C.CYAN + bar(frac, 22) + C.RESET, C.DIM, frac * 100.0,
                          C.DIM, C.GRAY, label, C.RESET))
        sys.stdout.flush()

    try:
        matches = solve(data, progress=progress)
    except Exception as exc:
        fail(str(exc)); return
    print()

    if not matches:
        fail("no valid plaintext among %d seeds" % total); return

    seed, key, plaintext = matches[0]
    ok(0.96, "decryption recovered a seed-consistent plaintext.")
    big_flag(seed, key, plaintext.decode("ascii"), time.time() - t0)
    with open(Path(cip.parent) / "flag_from_cryp70.txt", "w") as f:
        f.write(plaintext.decode("ascii") + "\n")
    print("  %s[+] saved to %s%s" % (C.GREEN, Path(cip.parent) / "flag_from_cryp70.txt", C.RESET))


if __name__ == "__main__":
    main()