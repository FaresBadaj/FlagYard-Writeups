# FlagYard CTF — hex-hex

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Crypto
- **Difficulty:** Easy

> *"A witch hexed our RSA key."*

---

## The flag

```
FlagY{h3x_subst1tut10n_c4nt_h1de_crt_3xp0n3nts}
```

---

## The short version

A normal RSA key (`e = 127`, 512-bit primes) — but the CRT exponents
`dp`/`dq` are printed through a **random hexadecimal substitution**:

```python
dp = pow(E, -1, p - 1)      # e^-1 mod (p-1)
dq = pow(E, -1, q - 1)      # e^-1 mod (q-1)

sigma = {a: b for a, b in zip(alphabet, shuffled)}   # one random shuffle

def hexed(v):
    return "".join(sigma[c] for c in format(v, f"0{HEXLEN}x"))
```

Both 128-char outputs below are written with the **same** `sigma`, so the
underlying math is untouched:

1. From `e*dp - 1 = k*(p-1)` and `e*dq - 1 = l*(q-1)` we know
   `p = (e*dp+k-1)/k`, `q = (e*dq+l-1)/l` with **`k,l < e = 127`** — only
   `126 × 126 = 15876` candidate pairs.
2. For a fixed `(k,l)`, the product `(e*dp+k-1)(e*dq+l-1) = k*l*n` lets us
   recover the substitution **digit-by-digit from the LSB side**: at hex
   position `t` the equation must hold `mod 16^(t+1)`, and only the *new*
   substitution symbols need guessing at each step.
3. Wrong `(k,l)` pairs die within a couple of DFS nodes; the true pair
   (`k=48, l=38`) completes. Then `p`, `q`, `d`, and `m = ct^d mod n` follow
   directly — the flag is the trailing bytes of the plaintext.

**Flag:** `FlagY{h3x_subst1tut10n_c4nt_h1de_crt_3xp0n3nts}`

---

## First look

The output file leaks everything except the permutation:

```
n  = 11220624602109993501738465934070531053663848...
e  = 127
dp = b7bff45e1ddffed3050ef3f51a92f7df79c8e15afb85c0e...   (128 chars)
dq = c11900ace5da199f37c1bce2ffdad8c121b4f14bde0a55...   (128 chars)
ct = 25959404289822796069969570703864526476532...
```

Direct factoring of `n` (1024-bit) is out. `dp`/`dq` are useless until the
substitution is undone, and brute-forcing the permutation itself is
`16! ≈ 2×10^13` — no. The trick is that we never need the full permutation as
a *guess*; the RSA structure lets us **verify it incrementally**.

## The whole trick: CRT relations + LSB-first DFS

`dp = e^-1 mod (p-1)` means `e*dp ≡ 1 (mod p-1)`, i.e. there is an integer
`k < e` with

```
e*dp - 1 = k*(p-1)     =>     p = (e*dp + k - 1) / k
e*dq - 1 = l*(q-1)     =>     q = (e*dq + l - 1) / l
```

Multiplying the two:

```
(e*dp + k - 1) * (e*dq + l - 1) = k * l * n
```

Now read the substituted outputs from the **least significant** hex digit.
Once the low `t` digits of `dp` and `dq` are fixed, both sides of the product
equation are fully determined `mod 16^(t+1)` — so a candidate digit
assignment that violates it is pruned immediately, before any deeper guesses:

```python
# D, Q = dp, dq restricted to the low t digits (mod 16^t)
if (E*D + k - 1) * (E*Q + l - 1) % modulus != k*l*n % modulus:
    continue          # wrong assignment, prune
```

The DFS scans the 128 positions from LSB to MSB. At each position only the
substitution symbols that were **not seen before** need a guess (each unmapped
symbol can still be any unused original digit `0..15`); already-seen symbols
are forced. The search per `(k,l)` is therefore:

1. guess the (at most two) fresh substitution symbols at position `t`
2. check the product congruence `mod 16^(t+1)` — prune if it fails
3. at the end verify `p*q == n` exactly

Wrong `(k,l)` candidates exhaust themselves within a handful of nodes; the
true one completes almost instantly. All 15876 pairs were swept in parallel
with a `multiprocessing.Pool` (~29 s on this machine).

## Result

```
k    = 48
l    = 38

sigma (original -> encrypted):
  0->7  1->9  2->2  3->c  4->5  5->b  6->4  7->6
  8->3  9->1  a->f  b->0  c->d  d->e  e->8  f->a
```

```
p = 1113495175953049901338948829373165806484717743146762801378006420189140000
    7403154679227228894713716249062028560689059003844342088660371031776036452351
    562039
q = 1007694047035827198861912823708013161537285861805381757957281085276491469
    7062252817755854295538692774379859001134027913176037316031062291018046365738
    856671
```

With `phi = (p-1)(q-1)` and `d = e⁻¹ mod phi`, `m = ct^d mod n` is the
plaintext `random_bytes || flag`, so the flag is the trailing bytes:

```
FLAG = FlagY{h3x_subst1tut10n_c4nt_h1de_crt_3xp0n3nts}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| `dp`/`dq` leaked at all | output.txt | attacker recovers `p`,`q` with only a `k,l < e` sweep |
| Hex-digit substitution instead of real encryption | `hexed()` | a plain permutation, undone cheaply |
| Substitution shared between `dp` and `dq` | chall | two equations, single unknown permutation |
| `m = random_bytes + flag` kept flag at the end | construction | flag survives RSA padding semantics intact |

---

## Takeaways

- **Leaking `dp`/`dq` — even hex-mangled — is a full private-key leak.** The
  permutation is cosmetic; `e*dp - 1 = k(p-1)` holds on the decoded integers
  no matter how the digits are renamed.
- **LSB-first modular pruning turns a `16!` permutation search into a few
  hundred nodes.** The product equation `mod 16^(t+1)` is a perfect
  incremental verifier because it only depends on already-recovered digits.
- **Bounding multipliers matters.** `k,l < e` made the whole CRT sweep 15876
  candidates — seconds in parallel.

---

## The solver

`solve_hexhex.py` — DFS over all `(k,l)` pairs with LSB-first substitution
recovery and modular pruning, run in parallel:

```
python solve_hexhex.py
★  FLAG RECOVERED  ★
FlagY{h3x_subst1tut10n_c4nt_h1de_crt_3xp0n3nts}
```

It reads `output.txt` next to it and saves the flag to
`flag_from_hexhex.txt`.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)