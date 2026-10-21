from os import urandom
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse
from hashlib import sha256

FLAG = b"FlagY{draft}"

Point = namedtuple("Point", "x y")
Curve = namedtuple("Curve", "p a b G")
O = "Origin"

p = 30147047372537667543227596509433268914148160199933678584277532878812522173123
a = 4295866710341558381730993001337260151326704354119856057045858346018488917551
b = 27915475329982779370228189153614202544988456477009880605661666567636553859719
G = Point(
    23660607485931404474159157392651047549672758508793488070957915230753900420346,
    8315837926899275371387974820365523190632259447349013169853248963499139967386,
)
CHECKPOINT = Curve(p, a, b, G)


def point_inverse(P, C):
    if P == O:
        return P
    return Point(P.x, -P.y % C.p)


def point_addition(P, Q, C):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P, C):
        return O
    else:
        if P == Q:
            lam = (3 * P.x**2 + C.a) * inverse(2 * P.y, C.p)
            lam %= C.p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), C.p)
            lam %= C.p
    Rx = (lam**2 - P.x - Q.x) % C.p
    Ry = (lam * (P.x - Rx) - P.y) % C.p
    return Point(Rx, Ry)


def double_and_add(P, n, C):
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q, C)
        Q = point_addition(Q, Q, C)
        n = n // 2
    return R


class Server:
    def __init__(self, curve):
        self.C = curve
        self.s = int.from_bytes(urandom(32), byteorder="little")
        self.P = double_and_add(self.C.G, self.s, self.C)

    def ecdh_kex(self, Q, ciphersuite):
        if ciphersuite != "ECDHE_CHECKPOINT_WITH_AES_128":
            raise Exception("Ciphersuite not supported.")
        shared_point = double_and_add(Q, self.s, self.C)
        self.shared_key = sha256(str(shared_point.x).encode()).digest()[:16]

    def send_msg(self, pt):
        iv = urandom(16)
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(pt, 16))


if __name__ == "__main__":
    S = Server(CHECKPOINT)
    client_secret_key = int.from_bytes(urandom(32), byteorder="little")
    client_public_key = double_and_add(S.C.G, client_secret_key, S.C)
    S.ecdh_kex(client_public_key, "ECDHE_CHECKPOINT_WITH_AES_128")

    transcript = (
        "Eavesdropping on a TLS-like handshake ...\n"
        "client initiating key agreement:\n"
        f"client->server : {client_public_key}\n"
        f"server->client : {S.P}\n"
        f"server->client : {S.send_msg(FLAG).hex()}\n"
    )
    print(transcript, end="")
    with open("output.txt", "w") as f:
        f.write(transcript)
