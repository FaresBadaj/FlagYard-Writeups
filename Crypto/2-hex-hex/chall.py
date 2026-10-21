import os
import secrets

E = 127
BITS = 512                     
HEXLEN = BITS // 4              


def _is_prime(m):
    if m < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if m % sp == 0:
            return m == sp
    d = m - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, m)
        if x in (1, m - 1):
            continue
        for _ in range(r - 1):
            x = x * x % m
            if x == m - 1:
                break
        else:
            return False
    return True


def gen_prime():
    while True:
        cand = secrets.randbits(BITS) | (1 << (BITS - 1)) | 1
        if (cand - 1) % E and _is_prime(cand):
            return cand


def read_flag():
    flag = os.environ.get("FLAG")
    if flag is None:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "flag.txt")) as f:
            flag = f.read().strip()
    return flag.encode()


def main():
    p, q = gen_prime(), gen_prime()
    n = p * q
    dp = pow(E, -1, p - 1)
    dq = pow(E, -1, q - 1)

    alphabet = list("0123456789abcdef")
    shuffled = alphabet[:]
    secrets.SystemRandom().shuffle(shuffled)
    sigma = {a: b for a, b in zip(alphabet, shuffled)}

    def hexed(v):
        return "".join(sigma[c] for c in format(v, f"0{HEXLEN}x"))

    flag = read_flag()
    block = (n.bit_length() // 8) - 1
    assert len(flag) < block, "flag too long"
    m = int.from_bytes(secrets.token_bytes(block - len(flag)) + flag, "big")
    ct = pow(m, E, n)

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "output.txt"), "w") as f:
        f.write(f"n  = {n}\n")
        f.write(f"e  = {E}\n")
        f.write(f"dp = {hexed(dp)}\n")
        f.write(f"dq = {hexed(dq)}\n")
        f.write(f"ct = {ct}\n")
    print("wrote output.txt")


if __name__ == "__main__":
    main()
