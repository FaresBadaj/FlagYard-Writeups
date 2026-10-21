# FlagYard CTF — League-Lorem-Legends

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Crypto
- **Difficulty:** Medium

> *"I'm not sure why I'm still playing League, even if it's only occasionally—any idea why?"*

---

## The flag

```
FlagY{LLL_and_C0pp3rsm1th_is_nuf_i_mean_fun?!_!!!!}
```

---

## The short version

A normal RSA key (two 1024-bit primes, `e` a 128-bit prime) — but the server
leaks the **top 816 bits of the CRT exponent** `dp = d mod (p-1)`:

```python
dp      = pow(e, -1, p - 1)
dp_high = dp >> 205          # top (bits - 205) bits leaked
```

`e*dp - 1 = k*(p-1)` bounds the missing pieces: write
`dp = dp_high * 2^205 + x` with `x < 2^205`, then

```
k*p = [e*dp_high*2^205 - 1] + [e*x + k]
       \_______B________/      \___u___/
```

so `p | (B + u)` with `u = e*x + k < 2^333`. Because the hidden factor
`p ~ n^0.5` satisfies the Howgrave–Graham budget `n^(β²) = n^0.25 ≈ 2^512`,
the unknown `u` is small enough for a **univariate Coppersmith lattice**
over the unknown divisor `p`:

1. Build the `m=2, t=2` shift-polynomial lattice (dim 4).
2. LLL-reduce (pure-Python, exact `Fraction` arithmetic).
3. The shortest vector is a degree-3 polynomial whose integer root `u_0`
   is found by **sign-based binary search** (mpmath `polyroots` is unstable
   at these magnitudes).
4. `p = gcd(n, B + u_0)`, `q = n/p`, then `m = c^d mod n` decrypts.

**Flag:** `FlagY{LLL_and_C0pp3rsm1th_is_nuf_i_mean_fun?!_!!!!}`

---

## First look

The output file leaks almost the whole CRT exponent:

```
n       = 2952268545851336046131544546893831803628...
e       = 237586866747885678899273389705470044647
c       = 10410414785442119816991514222134427291...
dp_high = 2517975006688045684913081951792219450194...   (816 bits)
```

Direct factoring of `n` (2048-bit) is out, and the {820 missing bits} of
`dp` out of 1021 can't be brute-forced. The trick is that with `k` so small
(`k < e < 2^128`) the *whole* uncertainty collapses into one integer `u` of
just 333 bits — tiny compared to the Coppersmith budget.

## The whole trick: partial dp leak + Coppersmith lattice

`dp = e^-1 mod (p-1)` means `e*dp ≡ 1 (mod p-1)`, i.e. there is an integer
`k` with

```
e*dp - 1 = k*(p-1)        =>        k*p = e*dp + k - 1
```

Splitting off the known top bits `dp = dp_high*2^205 + x`:

```
k*p = [e*dp_high*2^205 - 1] + e*x + k
      \___________B_________/   \___u___/
```

`p | (B + u)` with `B` fully known and `u = e*x + k`. Since
`x < 2^205` and `k < e < 2^128`, `u < 2^333`. For a factor `p ≥ n^0.5`
(β = 0.5) Coppersmith recovers roots of a linear polynomial up to
`X = n^(β²) = n^0.25 ≈ 2^512`, so `u < 2^333` is comfortably in range.

The standard Heninger–Shacham / May construction for univariate Coppersmith
with unknown divisor uses the shift polynomials:

```
g_i(u) = n^(m-i) * f(u)^i        i = 0 .. m-1
g_j(u) = u^j * f(u)^m            j = 0 .. t-1
```

Every `g` vanishes `mod p^m` at the true root. With `m=2, t=2` that is a
`4×4` lattice whose determinant satisfies Howgrave–Graham. After LLL the
shortest vector is a degree-3 polynomial `h` with `h(u_0) = 0`.

```python
# f(x) = B + x     (monic linear)
# rows: n^2, n*f, f^2, x*f^2   scaled by X^i
red = lll([[cf * X**i for i, cf in enumerate(poly)] for poly in GG])
```

Two implementation notes that mattered:

1. **Numerical root-finding fails silently here.** `mpmath.polyroots` sees
   coefficients around `2^(6000+)` and converges to a cluster near zero,
   missing the ~333-bit root. The fix is an exact-integer **sign binary
   search** on `h` over `[0, X]` — 337 Horner evaluations of Python big
   ints, instant and exact.
2. **LLL in pure Python.** No `fpylll`/`gmpy2` on the target box, so the 4×4
   LLL ran on exact `Fraction` arithmetic (~50 s, negligible for one
   instance).

Once `u_0` is in hand, the factorization falls out immediately:

```
p = gcd(n, B + u0)
q = n // p
```

## Result

```
u0   = 23086652051403983985097607336059244306758355506926513574554151195161
        6267800841811330343404564120649
B+u0 = 88493579664358823184555847703384756611629...
```

```
p = 1394475170971662423008681972684671348542901552933848040321523725112347416256
    6692659019431959298189778012263434654193490817717594761639270704903466927426
    9784797543509040727858501959952734706874102171046520364007224593741545981581
    2510109769233848197234853962134993472633212228612556652460506552842500665076
    4603
q = 1733511403467123006244690274675985987399685154555223735520732978459940932959
    6443927825136555260101508258917366099800279468527350219829597942344688031480
    2798930868655457226634631459105955321408904568936301991936314207739608767116
    9728026132161655443198742051917643789440102337323172663993877165532815469926
    69847
```

With `phi = (p-1)(q-1)` and `d = e⁻¹ mod phi`, `m = c^d mod n` is the
plaintext `bytes_to_long(flag)`, so the flag is that big-int serialized
back to bytes:

```
FLAG = FlagY{LLL_and_C0pp3rsm1th_is_nuf_i_mean_fun?!_!!!!}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| CRT exponent `dp` leaked (top 816/1021 bits) | output.txt | attacker recovers `p`,`q` with a small Coppersmith lattice |
| `e` unusually small (128-bit prime) | chall | tiny cofactor `k < e`, so the unknown `u` fits `n^0.25` budget |
| No sanity check that the leak is insufficient | chall | no guard against partial-key disclosure |

---

## Takeaways

- **Leaking the top ~80% of `dp` is a total private-key leak.** The
  remaining 205 bits become a small modular root problem LLL solves in
  minutes.
- **Lattice attacks have a clean bound:** for degree-1 polynomials mod an
  unknown factor `p ≥ n^0.5`, recover roots up to `n^0.25` (~512 bits for a
  2048-bit `n`).
- **Numerical root-finding on huge-coefficient polynomials can fail
  silently.** For integer polynomials with a known root interval, exact-sign
  binary search over Python big ints is fast and guaranteed.
- **Pure-Python LLL is plenty** for low dimensions (4–6) with ~6000-bit
  entries — under a minute on modest hardware.

---

## The solver

`solve_league.py` — parses `output.txt`, builds the 4-row Coppersmith
lattice, LLL-reduces with exact `Fraction` arithmetic, binary-searches the
integer root, and decrypts:

```
python solve_league.py
★  FLAG RECOVERED  ★
FlagY{LLL_and_C0pp3rsm1th_is_nuf_i_mean_fun?!_!!!!}
```

It reads `output.txt` next to it and saves the flag to
`flag_from_league_lorem_legends.txt`.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)