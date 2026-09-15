import sys
import hashlib
import secrets
import os


p = 113922386694983050382912391517437431439572639334235676622418446302583918640667
q = 56961193347491525191456195758718715719786319667117838311209223151291959320333
N = 256  


def H(member_id):
    h = int.from_bytes(hashlib.sha256(f"id={member_id}".encode()).digest(), "big") % p
    if h == 0:
        h = 1
    return pow(h, 2, p)


class RollCallServer:
    def __init__(self, roster):
        self.R = roster

    def handle(self, c):
        k = 1 + secrets.randbelow(q - 1)
        eids = [pow(H(m), k, p) for m in self.R]
        deid = pow(c % p, k, p)
        return eids, deid


def round_once():
    absent = secrets.randbelow(N)
    roster = [m for m in range(N) if m != absent]
    server = RollCallServer(roster)

    for _ in range(3):
        line = sys.stdin.readline()
        if not line:
            return False
        parts = line.split()
        if not parts:
            return False
        op, args = parts[0], parts[1:]

        if op == "handle":
            c = int(args[0])
            eids, deid = server.handle(c)
            print(eids, flush=True)
            print(deid, flush=True)
        elif op == "submit":
            return int(args[0]) == absent
        else:
            return False
    return False


def main():
    FLAG = os.getenv("DYN_FLAG")

    print("Roll Call: name the absent member 16 times.", flush=True)
    for _ in range(16):
        if round_once():
            print("Correct!", flush=True)
        else:
            print("Nope.", flush=True)
            break
    else:
        print(FLAG, flush=True)


if __name__ == "__main__":
    main()
