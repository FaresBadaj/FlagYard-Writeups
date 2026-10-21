# FlagYard CTF — Normal El-Gamal

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Crypto
- **Difficulty:** Hard

> *"This is the Normal El-Gamal, I hope you don't find any issue with it."*

---

## The flag

```
FlagY{ca6318a5d6178ad45f692f9680bea400}
```

---

## The short version

ElGamal encryption over an **unknown** short-Weierstrass curve over `GF(p)`:

```
enc(m) = (kG, kA + P_m),   dec(q) = C2 - x*C1
P_m = (m << 8 | ctr, f(ctr))    (counter-embedded message point)
```

The server leaks the **flag ciphertext** `ct = (C1, C2)` at startup and then
offers two oracles: `enc(m)` returns two fresh curve points, and `dec(q)`
returns the *decrypted point coordinates* — the flag's exact ciphertext is
rejected, but **ciphertexts that decrypt to the same integer are also
rejected** (*not that easy*).

Two bugs chain together:

1. **The curve is fully recoverable.** Every output of `enc` is a secret-base
   point `(x, y)` on the unknown curve. With `f(P) = y² − x³` we have
   `f(P) = a·x + b (mod p)` for the secret `a, b`, so

   ```
   (f0 − f1)(x0 − x2) − (f0 − f2)(x0 − x1)  ≡  0  (mod p)
   ```

   Each such integer is a multiple of `p`; the GCD over many enc queries
   reveals `p`, then `a, b` come from any two points. *Everything* —
   including the flag's `C1, C2` — is verified on the recovered curve.

2. **ElGamal is malleable.** For any known point `D`,
   `(C1_flag, C2_flag + D)` decrypts to `P_flag + D`. The check `ct2 == ct`
   compares coordinates, so the shifted ciphertext sails through and the
   oracle prints `P_flag + D`. Subtract `D`, shift `x >> 8`, decode:

   ```
   M = (M + D) − D
   → long_to_bytes(M.x >> 8) == FlagY{ca6318a5d6178ad45f692f9680bea400}
   ```

---

## The challenge box

`tcp.flagyard.com:16085`. The public source (`challenge.sage`) keeps the
curve parameters **secret** (imported from another file):

```python
L_BITS      = 8
MAX_COUNTER = 1 << 8

def _map_to_point(self, m):
    for ctr in range(MAX_COUNTER):
        x = (m << L_BITS) + ctr
        rhs = (x^3 + self.a*x + self.b) % self.p
        if rhs.is_square():
            return self.curve.point((x, sqrt(rhs)))
    raise ValueError(...)

def _point_to_int(self, P):
    return int(P[0]) >> L_BITS
```

Protocol:

```
ct=(c1x, c1y, c2x, c2y)          <- banner leaks the flag ciphertext
1. enc (int)                     -> (kG, kA + P_m)   [2 fresh curve points]
2. dec (c1x, c1y, c2x, c2y)      -> m= <x> <y>        [decrypted POINT]
3. Exit
```

The `dec` guard:

```python
if tuple(q) == ct or q[2] == ct[2] or q[3] == ct[3]:
    ... "not that easy"
if _point_to_int(decrypted_text) == bytes_to_long(FLAG):
    ... "not that easy"
else:
    print(m= x y)            # the POINT, not the integer
```

Coordinate sizes (~384 bits) rule out brute force; `p` secret rules out the
"standard" ElGamal attacks (invalid-curve, twist, order-reduction) until the
curve is known.

---

## Step 1 — recover the unknown curve

`enc(m)` returns `(kG, kA + P_m)`: both coordinates are points **on the same
secret curve**. Let `f(x, y) = y² − x³`. On the curve every point satisfies

```
f(x, y) = a·x + b   (mod p)
```

so for three points `P0, P1, P2` any two of the equations give `a`, and the
determinant trick eliminates it:

```
(f0 − f1)(x0 − x2) − (f0 − f2)(x0 − x1)  ≡  0  (mod p)
```

That integer is a **multiple of `p`**. Gather ~26 points from repeated `enc`
queries, take the GCD of many such expressions, divide out any small prime
factors, then fit `a, b` and verify every collected point lies on the result:

```
p  = 3869260448273924894482882797006260018847360362462089683033141919917771097
     6266097207752685712562343071700577433571         (384 bits)
a  = 1663755239189660152293769689670426342510792818469148799448215614656288347
     711108134329140920719087259406397423413875
b  = 3061645213850619939541116340337691665495207712651161117063553050351591263
     5655953824299996415644083181817851491584172
```

All 26 points verify on the curve `EC(p, a, b)`.

---

## Step 2 — malleability on the flag ciphertext

ElGamal is **semantically** secure but **malleable** (it is not CCA2):
adding a known point to the second component adds it to the plaintext too.

```
dec(C1_flag, C2_flag)  =  P_flag
dec(C1_flag, C2_flag + D)  =  P_flag + D
```

The blacklist only blocks exact-equal coordinates and same-integer decryptions
— a shifted ciphertext decrypts to a *different point* that still contains
the same top bits. Pick `D = points[4]` (any collected point), submit
`(C1, C2 + D)`:

```
oracle: m= 288210839392043708530316351997360907004451089102672060740956102447
           38821411286729895302570077157654798980436782004470
           322663423958925022478201491617014177177944122676047081096834519145
           26167190979493219425845286165815144017736331626813

D = (2882108393920437085303163519973609070044510891026720607409561024473882141
     1286729895302570077157654798980436782004470 − ...
M = (5875913542304635896353418637537344136986276652889346457642686615839490312
     51740659757875337395456, ...)
```

Then `M.x >> 8`:

```
flag_int = 229527872746274839701305415528802505351026431753490096001667445931
           2300903327111952179200536701
→ FlagY{ca6318a5d6178ad45f692f9680bea400}
```

No ECDLP was solved — the private key never mattered.

---

## Result

```
★  FLAG RECOVERED  ★
FlagY{ca6318a5d6178ad45f692f9680bea400}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| Curve parameters (`p`, `a`, `b`, `G`) secret but the oracle reveals arbitrary curve points | `enc` prints `kG`, `kA+P_m` | attacker recovers the full curve from coordinates alone |
| No bound on `enc` queries | service | enough points for exact `p` reconstruction via GCD |
| ElGamal used without CCA protection | `dec` | shifts `C2 + D` bypass the blacklist and leak the plaintext *point* |
| The "same integer" check compares the message, not the point | `dec` | `P+D` passes; top 8+ bits (the message watermark) survive unchanged |
| `_map_to_point` puts the whole message in the top bits (`x >> 8`) | challenge.sage | malleability recovers the point → message immediately |

---

## Takeaways

- **An EC point is a commitment to its coordinates.** If the curve is unknown
  but you get many points, homogeneity of the curve equation recovers
  `p, a, b` in a handful of queries — "secret curve" buys almost nothing.
- **ElGamal (and textbook RSA) are malleable by design.** A CCA2 game is
  trivialized by shifting the message by a single known element; blacklists
  that only compare exact equality are bypassed the same way.
- **Guard against point-addition, not just equality.** A robust scheme needs
  hashed/plaintext-aware encryption (EC-ElGamal → ECIES, or hash the map) so
  a transformed ciphertext cannot verify.
- **Testing `_point_to_int(dec)` is weaker than testing coordinates** — the
  attacker controls 256 low bits (the counter) and can always pick a shift
  that keeps the top bits intact while changing the point.

---

## The solver

`solve_elgamal.py` — connects to `tcp.flagyard.com:16085`, parses the flag
ciphertext banner, harvests curve points via `enc`, recovers `p, a, b` and
verifies, then runs the `+D` malleability and decodes the flag:

```
python solve_elgamal.py tcp.flagyard.com:16085
★  FLAG RECOVERED  ★
FlagY{ca6318a5d6178ad45f692f9680bea400}
```

It saves the flag to `flag_from_normal_elgamal.txt`.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)