#!/usr/bin/env python3
import sys
import os
import base64
import hashlib
from secrets import randbelow, token_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

N = 64
Q = 268435399               
BOUND = 64              
MAX_SESSIONS = 96
POW_BITS = 4               


def gen_small(n):
    return [randbelow(2 * BOUND) - BOUND for _ in range(n)]


def centered(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def signal(x):
    """Reconciliation hint: is x near zero, or near +-Q/2 ?"""
    return 0 if -Q // 4 <= centered(x) <= Q // 4 else 1


def extract(x, s):
    """Robust extractor: agrees for both parties when their values are close."""
    return ((x + s * ((Q - 1) // 2)) % Q) % 2


def canon(v):
    return ",".join(str(i) for i in v).encode()


def enc(vals):
    return base64.b64encode(b"".join(int(v).to_bytes(4, "big") for v in vals)).decode()


def dec(txt, count):
    raw = base64.b64decode(txt, validate=True)
    if len(raw) != 4 * count:
        raise ValueError("bad length")
    return [int.from_bytes(raw[4 * i:4 * i + 4], "big") for i in range(count)]


def do_pow(out, inp):
    chal = token_bytes(4).hex()
    out(f"pow: sha256({chal} + X).hexdigest() must start with {'0' * POW_BITS}")
    out(f"chal = {chal}")
    x = inp().strip()
    if not hashlib.sha256((chal + x).encode()).hexdigest().startswith("0" * POW_BITS):
        out("bad pow")
        return False
    out("ok")
    return True


def main():
    out = lambda m: (sys.stdout.write(m + "\n"), sys.stdout.flush())
    inp = lambda: sys.stdin.readline()

    FLAG = os.environ.get("DYN_FLAG")
    if FLAG is None:
        with open("/flag.txt", "rb") as f:
            FLAG = f.read().strip()
    else:
        FLAG = FLAG.encode()

    out("== Handshake v2 : LWE key exchange ==")
    if not do_pow(out, inp):
        return

    s = gen_small(N)
    M = [[randbelow(Q) for _ in range(N)] for _ in range(N)]
    eS = gen_small(N)
    b = [(sum(M[i][j] * s[j] for j in range(N)) + 2 * eS[i]) % Q for i in range(N)]

    key = hashlib.sha256(canon(s)).digest()
    nonce = os.urandom(12)
    sealed = nonce + AESGCM(key).encrypt(nonce, FLAG, None)

    out(f"N = {N}")
    out(f"Q = {Q}")
    out(f"M = {enc(v for row in M for v in row)}")
    out(f"b = {enc(b)}")
    out(f"flag = {sealed.hex()}")
    out(f"sessions = {MAX_SESSIONS}")

    for _ in range(MAX_SESSIONS):
        out("send pA:")
        line = inp()
        if not line:
            return
        line = line.strip()
        if line == "exit":
            return
        try:
            flat = dec(line, N * N)
        except Exception:
            out("malformed")
            return
        if any(not (0 <= v < Q) for v in flat):
            out("out of range")
            return
        pA = [flat[i * N:(i + 1) * N] for i in range(N)]

        kB = [sum(pA[i][j] * s[j] for j in range(N)) % Q for i in range(N)]
        sig = [signal(v) for v in kB]
        shared = bytes(extract(kB[i], sig[i]) for i in range(N))
        skey = hashlib.sha256(shared).digest()
        tag = AESGCM(skey).encrypt(b"\x00" * 12, b"handshake-ok", None)

        out("sig = " + "".join(str(v) for v in sig))
        out("tag = " + tag.hex())

    out("session limit reached")


if __name__ == "__main__":
    main()
