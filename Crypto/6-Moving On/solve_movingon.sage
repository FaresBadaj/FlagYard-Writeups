#!/usr/bin/env sage

from Crypto.Util.Padding import unpad
from sage.all import *

p = 0x00e675aaef519c7bdfa7e9b6d5
a = 0x00c5a83d2b9ce92d9c75a37a08
b = 0x0020cd6dc3b4b34e4332463ccd

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]

print("curve order:", E.order())
print("factorization:", factor(E.order()))
print("G =", G)

Qs = [
    E(25868279382606376233089622039, 35226758373642087968613953852),
    E(31211278741961598848732755066, 68653856268530027481128223450),
]

n = Integer(E.order())
q = Integer(24171428442137419)
cofactor = n // q

K.<u> = GF(p^2, implementation='pari_ffelt')
E2 = EllipticCurve(K, [K(a), K(b)])

G2 = E2(K(G[0]), K(G[1]))

Qs2 = [
    E2(K(Q[0]), K(Q[1])) for Q in Qs
]

P = cofactor * G2

while True:
    R = E2.random_point()
    R = cofactor * R

    if R != E2(0):
        w = P.weil_pairing(R, q)

        if w != 1:
            break

print("[+] MOV setup ready")

secrets = []

for i, Q in enumerate(Qs2, 1):
    print(f"[*] Solving Q{i} ...")

    Qq = cofactor * Q
    target = Qq.weil_pairing(R, q)

    s = target.log(w, q)
    s = Integer(s)

    print(f"[+] q-residue{i}: {s}")

    small_mods = [2, 5, 757, 1627, 239579]
    residues = []

    Q_orig = Qs[i - 1]

    for m in small_mods:
        Gm = (n // m) * G
        Qm = (n // m) * Q_orig

        r = discrete_log(
            Qm,
            Gm,
            ord=m,
            operation='+'
        )

        residues.append(Integer(r))

    s_full = crt(
        residues + [s],
        small_mods + [q]
    )

    s_full = Integer(s_full)

    print(f"[+] secret{i}: {s_full}")

    secrets.append(s_full)

flag_bytes = b''.join(
    int(s).to_bytes(12, 'big')
    for s in secrets
)

print("[+] raw:", flag_bytes)

try:
    print("[+] flag:", unpad(flag_bytes, 12))
except Exception:
    print("[+] flag:", flag_bytes)