# FlagYard CTF — partial_recovery

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
FLAGY{Partial_key_exposure_Attack!!}
```

---

## The short version

A 2048-bit RSA server with a **small public exponent** leaks only the
**lower 512 bits** of the CRT exponents:

```
dp = dp % 2^512     (this is all we know, "dp_low")
dq = dq % 2^512     (this is all we know, "dq_low")
N (2048 bits)  ,  e = 0xa4ff = 42239 (16-bit prime)
```

Writing the key-generation equations with the *truncated* exponents and
multiplying them together fixes `(k, l)` — the same small unknowns that
appear in `e*dp = 1 + k(p-1)` and `e*dq = 1 + l(q-1)`:

```
A  = e*(dp_low + dq_low) - e^2*dp_low*dq_low - 1
f(x,y) = (N-1)*x*y - (e*dq_low-1)*x - (e*dp_low-1)*y + A

f(k,l) == 0   (mod e*2^512)      ->   (k,l) = (36031, 3334)
```

With odd `k` in hand, the equation

```
e*(h_dp*2^512 + dp_low) + k - 1 == 0   (mod k*p)
```

becomes a modular-root problem for the **unknown upper half** of `dp`,
`h_dp` (`0 < h_dp < 2^512`). "Standard small_roots" only *just* touches
this theoretical boundary (`beta ~ 0.504`, `X = 2^512`), so we build the
CUSTOM lattice from the paper *Factoring with Only a Third of the Secret
CRT-Exponents* (eprint 2022/271), LLL it, and the reduced rows give us
`h_dp` directly. Then:

```
p = gcd(e*(h_dp*2^512 + dp_low) + k - 1, N)    ->    q = N // p
d = e^{-1} mod (p-1)(q-1)                       ->    pow(c, d, N)   ->   flag
```

---

## First look

- One relevant file: `output.txt` — 2048-bit `N`, tiny `e`, `c`, and two
  "half" exponents `dp`, `dq` (each `mod 2^512` in the file).
- `server.py` tells the story: it prints the **raw** bytes of `dp`/`dq`,
  not the value themselves:

  ```
  f.write(f'dp = 0x{(dp % 2**(512)):x}\n')   # LOWER 512 bits only
  f.write(f'dq = 0x{(dq % 2**(512)):x}\n')
  ```

- `e` is only **16 bits**, so the multipliers `k` and `l` live in
  `1 .. e-1` — a tiny search space (at most `65535` values).
- Classic partial-key-exposure: with `delta = 1/4` known, the lattice
  bound is *exactly at* the edge — hence the custom lattice, not
  `small_roots`.

---

## Recovering (k, l) — the "two unknowns in one equation"

From key generation:

```
e*dp = 1 + k*(p-1)      =>      k*p = e*dp + k - 1
e*dq = 1 + l*(q-1)      =>      l*q = e*dq + l - 1
```

The product `p*q = N` therefore gives an equation purely in `k, l`:

```
(e*dp + k - 1)(e*dq + l - 1) = k*l*N
```

We only know `dp`, `dq` modulo `M = 2^512`. Reducing both sides `mod M`
and substituting `dp_low, dq_low` turns it into a quadratic in `(k, l)`:

```
A  = e*(dp_low + dq_low) - e^2*dp_low*dq_low - 1
f(x,y) = (N-1)*x*y - (e*dq_low-1)*x - (e*dp_low-1)*y + A

f(k,l) ≡ 0   (mod e*M)     since k < e, l < e
```

The official writeup (and the paper) solve this with *bivariate
Coppersmith*; but because `e` is tiny we simply scan `k`:

- for every `x` we solve the linear congruence for `y` mod `e`,
- the surviving pair must also satisfy `f(x,y) ≡ 0 (mod M)`.

```
candidates: [(36031, 3334)]
```

That's the attack on "only 1/4 of the exponents": two unknowns, one
truncated equation — the smallness of `e` collapses it to a scan.

---

## Recovering h_dp — the custom lattice

Rewrite the `p`-side equation with `dp = h_dp*M + dp_low`:

```
k*p = e*(h_dp*M + dp_low) + k - 1
    = (e*M)*h_dp + (e*dp_low + k - 1)
```

`k` is odd and `gcd(e*M, k*N) = 1`, so it is **invertible mod `k*N`**
(the `p` side is usable; the `q` side with even `l = 3334` is not):

```
a = (e*dp_low + k - 1) * (e*M)^{-1}  mod k*N
f(x) = x + a ,     f(h_dp) ≡ 0 (mod k*p) ,   0 < h_dp < X = 2^512
```

`p` is an unknown divisor of `k*N` with `beta = log(k*p)/log(k*N) ≈ 0.504`.
Standard `small_roots` sits right on the success boundary, so we use the
custom lattice of the paper (`eprint 2022/271`):

```
row i  =  f(x)^i * k^(m-i) * N^max(0, t-i)      (evaluated at x*X)
```

The shorter rows after LLL are polynomials whose tiny integer root **is**
`h_dp`. Checking every reduced row with the test
`gcd(e*(h_dp*M + dp_low) + k - 1, N)` confirms the real root:

```
m = 35, t = 17  (LLL)   ->  h_dp = 1010038...74788679
p = gcd(...)    = 1587570...43755999
```

> Practical note: the reference solution uses the same lattice with
> `m = 20/25/30`, which works under **fplll** (Sage's engine). In-process
> we run **python-flint's** `fmpz_mat.lll` which is slightly weaker near
> the theoretical limit — bumping `m` to `35` tips it over the edge.

---

## Decryption

```
phi = (p-1)*(q-1)
d   = e^{-1} mod phi
m   = pow(c, d, N)
flag = bytes(m)  =  b'FLAGY{Partial_key_exposure_Attack!!}'
```

`p*q == N` verified, both primes primality-verified, plaintext is clean
UTF-8 — no key-swap fallback needed.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| CRT exponents stored in full, then printed `mod 2^512` | `server.py` | the attacker gets 1/2 of `dp` and 1/2 of `dq` |
| `e` is only 16 bits | `server.py` | `k, l < e` make the (k,l)-search trivial (≤ 65535) |
| `k` came out odd | keygen randomness | `e*2^512` is invertible mod `k*N` → usable lattice side |
| Truncated product of both CRT equations still pins `k,l` | `f(k,l) ≡ 0 (mod e*M)` | two unknowns collapse to one scan + one linear solve |
| 2048-bit modulus with β≈0.504 sits exactly at Coppersmith's bound | `e*dp + k - 1 ≡ 0 (mod k*p)` | `small_roots` is borderline → custom lattice wins |
| The half-known `dp` reconstructs `p` directly as a gcd | `p = gcd(..., N)` | once `h_dp` is found, factoring is one `gcd` |

The "hard" part is only that the lattice root is caught at the exact
theoretical boundary — the happy accident of an *odd* `k` decides which
side of the CRT pair you can use.

---

## Takeaways

- **Partial CRT-exponent leaks are exploitable with "1/4" of the bits.**
  The multi-point/paper attack (eprint 2022/271) recovers `p` from half of
  `dp`/`dq` using a custom Coppersmith lattice.
- **The small public exponent is the real gift.** `e` being 16-bit shrinks
  `k` and `l` to a scan; the whole "bivariate" step becomes arithmetic.
- **`gcd(e*M, k*N) != 1` decides your lattice side.** With even `k` / `l`
  (like `l = 3334`) the inverse doesn't exist — pick the odd one.
- **`small_roots` isn't magic at the boundary.** At `beta ≈ 0.504` the
  bound is razor-thin; a custom "shifted" lattice with powers of both
  `k` and `N` is what actually factors the modulus.
- **Engine quality shows near the edge.** fplll (Sage) needs `m=20-30`;
  python-flint needs `m≥35`. Same lattice, same math — just a bigger
  matrix when your LLL is weaker.
- **Every "failed" parameter is information.** `m=20/25/30` returning no
  root told us the answer lives one step further out (`m=35`).

---

## The solver

Colored CLI solver in the same folder, **pure Python (stdlib only) + 
python-flint** for the lattice reduction:

```
solve_partial_recovery.py
```

```bash
python solve_partial_recovery.py            # scans the challenge folder next to it
python solve_partial_recovery.py <folder>   # or point at any challenge folder
```

It reads `output.txt`, recovers `(k, l)` with the `O(e)` scan, builds the
custom lattice, reduces it with `flint.fmpz_mat.lll`, finds `h_dp`,
factors `N`, decrypts the ciphertext and prints the winning flag box, then
saves `flag_from_partial_recovery.txt`:

```
  ✓ python-flint 0.9.0 (LLL engine)
  ✓ (k, l) candidates: [(36031, 3334)]
  ✓ using  k = 36031   (l = 3334)
  ▶ custom lattice (eprint 2022/271) + flint LLL
    ▶ LLL m=35 t=17 ...
  ✓ h_dp = 1010038...74788679
  ✓ p    = 1587570...43755999
  ✓ recovered both primes  (p*q == N: True)
  ✓ flag recovered: FLAGY{Partial_key_exposure_Attack!!}

★  FLAG RECOVERED  ★
FLAGY{Partial_key_exposure_Attack!!}
        elapsed 182.2 s
        custom lattice m>=35 | h_dp recovered -> p -> d -> flag
```

---