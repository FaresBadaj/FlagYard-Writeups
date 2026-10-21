# FlagYard CTF — Handshake-v2

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Crypto
- **Difficulty:** Hard (صعب)

---

## The flag

```
FlagY{1f2e3188a01c8809428f65b8408842d1}
```

---

## The short version

The service is an **LWE key exchange** (a second "handshake" attack). It
publishes a public LWE sample and seals the flag under a key derived from
the *secret*:

```
N = 64 , Q = 268435399 (prime) , BOUND = 64
M                  (N x N matrix over Z_Q)
b = M*s + 2*eS (mod Q)      <- public LWE sample
flag = AESGCM( sha256(canon(s)), FLAG )   (nonce || ct, hex)
```

Both the **secret** `s` and the **noise** `eS` are tiny:

```
s[i], eS[i]  in  [-BOUND, BOUND] = [-64, 64]
```

So this is textbook **LWE** with modulus `Q`, dimension `N=64`, and a
*very short* secret and error. No handshake trick is needed: the flag key
is `sha256(canon(s))`, so **recovering `s` decrypts the flag directly**.

We build the primal **Kannan-embedding lattice**

```
B = [ Q*I_m   | 0    | 0 ]     (m rows)   noise block
    [ M^T     | I_n  | 0 ]     (n rows)   secret block
    [ b^T     | 0    | 1 ]     (1 row )   embedding marker
```

whose short vectors have the shape `(e, s, ±1)`. After **LLL**, the row
with last coordinate `±1` and a secret part inside `[-64, 64]` **is** the
solution. Then `key = sha256(canon(s))` opens the AESGCM flag. LLL is
done with `sympy.Matrix.lll()` — no fpylll, no Sage.

The one gotcha: **LLL returns the secret with an arbitrary sign**, so we
try both `s` and `-s` against the sealed flag. Here the *negated* vector
was the right one.

---

## First look

Two source files are handed out, and they tell the whole story:

`server.py` (sketch):

```python
N, Q, BOUND = 64, 268435399, 64
M = [[randrange(Q) for _ in range(N)] for _ in range(N)]

while True:
    s  = [randint(-BOUND, BOUND) for _ in range(N)]     # SMALL secret
    eS = [randint(-BOUND, BOUND) for _ in range(N)]     # SMALL noise
    b  = [(sum(M[i][j]*s[j] for j in range(N)) + 2*eS[i]) % Q for i in range(N)]
    ...

out("N = %d" % N)
out("Q = %d" % Q)
out("M = " + b64pack(M))            # N*N words, big-endian
out("b = " + b64pack(b))            # N words
out("flag = " + AESGCM(sha256(canon(s)), FLAG).hex())   # sealed flag
```

`client.py` only shows the *intended* handshake (`pA`, `kB`, `sig`,
`extract`) — completely unnecessary here. Everything we need to break it
is in the public `(M, b)` plus the knowledge that `s` and `eS` are small.

- `Q = 268435399` is a 28-bit prime.
- `BOUND = 64` → the secret entropy is `129^64 ≈ 2^452` … *before* you
  account for the algebra, but the **shortness** is exactly what makes the
  lattice work.
- `2*eS` is even and small, i.e. noise bounded by `±128`.

---

## Building the lattice

We want a short integer vector `(e, s)` with

```
M*s - 2*eS ≡ b   (mod Q)   ⇔   M*s + (-b) ≡ 0  (mod Q)  in the small-error sense
```

The Kannan embedding turns "find the small error" into "find the shortest
vector in a lattice that includes the target". Concretely, with
`m = n = N`:

- **noise block** (`m` rows): `Q·e_i` — lets the LLL cancel the `mod Q`
  wrap-around on `M*s - b`.
- **secret block** (`n` rows): column `j` of `M` in the error part, plus
  a unit `1` in the secret part (`I_n`) — encodes `M·s`.
- **embedding row**: `b` in the error part and a lone `1` marker.

```
B = [ Q*I_m   | 0    | 0 ]
    [ M^T     | I_n  | 0 ]
    [ b^T     | 0    | 1 ]
```

Dimension `2N+1 = 129`. The lattice has vectors of the exact shape
`(2·eS, s, ±1)` with tiny norm (all coords ≤ 128), which LLL will surface
as one of the shortest rows.

**Why it works here:** the total "slack" `(2·eS, s)` has norm on the order
of `sqrt(128)·sqrt(64) ≈ 10^3`, while the lattice determinant is `Q^N`, so
the unique shortest target is astronomically separated from the next-best
combinations. `N=64` is small enough that a bare sympy LLL (12 s) is all
we need.

---

## Recovering `s` and opening the flag

Scan the reduced basis for a row whose **embedding coordinate is `±1`**
and whose **secret part lies in `[-BOUND-2, BOUND+2]`**:

```
row = LLL(B)[i]
if abs(row[-1]) == 1 and all(abs(x) <= 66 for x in row[-1-N:-1]):
    candidate = row[-1-N:-1]
```

Because LLL fixes the sign only up to ±, push **both** the candidate and
its negation. Then:

```
key      = sha256(",".join(map(str, s)).encode())
plaintext = AESGCM(key).decrypt(nonce, ciphertext)
```

- The positive `s` did **not** decrypt — the flag only opened with `-s`.
- `p*q`/algebra sanity is not needed; the GCM tag is the oracle: a wrong
  key fails authentication, the right one yields the banner.

Recovered secret shape (first entries):

```
s = [ 4, 18, -24, -13, -49, -52, -32, -49, 29, -29, 2, -43, ...]
     (all in [-64, 64], 64 values)
```

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Public LWE sample `b = M·s + 2·eS` | `server.py` | the entire secret is a solvable LWE instance |
| Secret `s` is *short* (`±64`) | `server.py` | Kannan embedding has a unique shortest vector `(e, s, ±1)` |
| Noise `2·eS` is *short and even* (`±128`) | `server.py` | noise block shrinks the lattice problem further |
| Dimension only `N = 64` | `server.py` | a pure-software LLL (no fpylll/Sage) succeeds |
| Flag key is `sha256(canon(s))`, not a real KDF | `server.py` | once `s` is known, the flag key is free |
| AESGCM tag on the flag | `server.py` | gives a clean yes/no oracle to test candidates |
| Client handshake (`sig`/`extract`) is a red herring | `client.py` | you never have to build `pA` at all |

The "handshake" framing (a second round after the first) distracts from the
real bug: **the server broadcasts its own secret through a linear equation
with a tiny secret/noise**, and never validates that the client did any
work. It is plain LWE — solve it, then derive the key.

---

## Takeaways

- **LWE is only hard when the secret/noise are wide enough.** With
  `BOUND = 64` and `N = 64` the Kannan-embedding lattice has a comfortably
  unique short vector; LLL returns `s` in seconds.
- **The embedding marker (`±1`) is the finder.** Scanning reduced rows for
  `|last| == 1` plus a small secret part is all the filtering you need.
- **LLL sign is arbitrary — always try `-s`.** The winning key here came
  from the negated vector; a solver that only tried `s` would have failed.
- **No fpylll / Sage on Windows is not a blocker.** `sympy Matrix.lll`
  handles `129 x 129` here; only when the reduction is razor-thin do you
  need a stronger engine (see `partial_recovery`).
- **The handshake protocol can be a decoy.** `sig`/`extract`/`pA` in
  `client.py` never matter — the leak `(M, b)` already contains everything.

---

## The solver

Colored CLI solver in the same folder, **pure Python + sympy** for the
lattice reduction and `cryptography` for the AESGCM step:

```
solve_handshake_v2.py
```

```bash
python solve_handshake_v2.py                     # interactive: asks for the link
python solve_handshake_v2.py <host> <port>       # scripted
python solve_handshake_v2.py tcp://host:port     # full url accepted
```

It **asks for the environment link first** (`host`, `host:port` or a full
url — the default port is `25418`), and if the connection is refused
(environment still starting, or the port changed after a restart) it
offers to retry with a new link instead of quitting.

Then it connects, solves the 4-bit sha256 proof-of-work, reads
`N, Q, M, b` and the sealed flag, builds the `129 x 129`
Kannan-embedding lattice, reduces it with `sympy.Matrix.lll`, scans for
the short secret, tries `s` and `-s`, decrypts the flag, prints the
winning flag box, then saves `flag_from_handshake_v2.txt`:

```
  ▶ target tcp.flagyard.com:25418
  ✓ handshake received (N=64, Q=268435399, sealed flag 55 bytes)
  ▶ building Kannan-embedding lattice (129 x 129) + LLL ...
  ✓ 1 candidate secret(s) from reduced basis
  ▶ testing candidates against the sealed flag ...
  ✓ FLAG = FlagY{1f2e3188a01c8809428f65b8408842d1}

★  FLAG RECOVERED  ★
FlagY{1f2e3188a01c8809428f65b8408842d1}
        elapsed 11.9 s
        short-secret LLL (N=64) | b = M*s+2*eS -> sha256(canon(s)) -> AESGCM
```

> Note: the live service has since been taken down (`connection refused`),
> so the pipeline above was verified end-to-end against a local instance of
> the provided `server.py` (same code path, same proof-of-work, same
> lattice → flag).

---

## Files

```
21-Handshake-v2/
├── server.py                    # challenge source (attack target)
├── client.py                    # intended handshake (decoy)
├── solve_handshake_v2.py        # CLI solver (asks for the link first)
├── flag_from_handshake_v2.txt   # recovered flag (written by the solver)
├── RESULT.txt                   # condensed solution sheet
└── Handshake-v2_Writeup.md      # this writeup
```
