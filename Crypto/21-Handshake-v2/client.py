#!/usr/bin/env python3
import sys
import base64
import hashlib
import socket
from secrets import randbelow
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BOUND = 64


def extract(x, s, Q):
    return ((x + s * ((Q - 1) // 2)) % Q) % 2


def enc(vals):
    return base64.b64encode(b"".join(int(v).to_bytes(4, "big") for v in vals)).decode()


def dec(txt, count):
    raw = base64.b64decode(txt)
    return [int.from_bytes(raw[4 * i:4 * i + 4], "big") for i in range(count)]


def solve_pow(chal, bits=4):
    i = 0
    while True:
        x = f"{i:x}"
        if hashlib.sha256((chal + x).encode()).hexdigest().startswith("0" * bits):
            return x
        i += 1


def main(host, port):
    s = socket.create_connection((host, port))
    f = s.makefile("rw")
    rd = lambda: f.readline().rstrip("\n")
    wr = lambda m: (f.write(m + "\n"), f.flush())

    rd()                                       
    rd()                                       
    chal = rd().split("=", 1)[1].strip()
    wr(solve_pow(chal))
    assert rd() == "ok"

    N = int(rd().split("=", 1)[1])
    Q = int(rd().split("=", 1)[1])
    M = dec(rd().split("=", 1)[1].strip(), N * N)
    M = [M[i * N:(i + 1) * N] for i in range(N)]
    b = dec(rd().split("=", 1)[1].strip(), N)
    rd()                                      
    rd()                                      

    R = [[randbelow(2 * BOUND) - BOUND for _ in range(N)] for _ in range(N)]
    E = [[randbelow(2 * BOUND) - BOUND for _ in range(N)] for _ in range(N)]
    pA = [[(sum(R[i][k] * M[k][j] for k in range(N)) + 2 * E[i][j]) % Q
           for j in range(N)] for i in range(N)]
    kA = [sum(R[i][j] * b[j] for j in range(N)) % Q for i in range(N)]

    rd()
    wr(enc(v for row in pA for v in row))
    sig = [int(c) for c in rd().split("=", 1)[1].strip()]
    tag = bytes.fromhex(rd().split("=", 1)[1].strip())

    shared = bytes(extract(kA[i], sig[i], Q) for i in range(N))
    skey = hashlib.sha256(shared).digest()
    try:
        AESGCM(skey).decrypt(b"\x00" * 12, tag, None)
        print("[+] key agreement OK - shared session key established")
    except Exception:
        print("[-] key agreement FAILED")
    wr("exit")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "localhost",
         int(sys.argv[2]) if len(sys.argv) > 2 else 5000)
