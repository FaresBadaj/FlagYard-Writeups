# FlagYard CTF — Incunabula

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Crypto
- **Difficulty:** Hard (صعب)
- **Endpoint:** `tcp.flagyard.com:26167` — *"Just another good and strong cryptosystem. Please, decrypt the flag."*

---

## The flag

```
FlagY{aa78a3b3cfc9bf5b46b24e28d415246c984b186742bde392bd17d9ec6675d97c}
```

---

## The short version

`incunabula.py` implements the **Naccache–Stern public-key knapsack**: a random
256-bit prime `p`, the first 64 primes and a hidden exponent `s` (
`gcd(s, p−1) == 1`) are used to build 64 public `roots[i]` with the property

```
roots[i]^s ≡ primes[i]  (mod p)
```

**Encryption** is a subset product: the 64-bit message chunk defines a bitmask,
and the ciphertext is the product of `roots[i]` over the set bits. The server
prints `{p, primes, roots}` and then the ciphertexts for the flag chopped into
64-bit chunks — and **runs fresh parameters per connection**, but always
re-encrypts the *same* `flag.txt`.

**Weakness:** the Legendre symbol is multiplicative, and because `s` and `s⁻¹`
are both odd, every root is *quadratic-residue-equivalent* to its prime:

```
(−1)^? = (roots[i] | p)  <->  (primes[i] | p)   ...
L(roots[i]) = L(primes[i])  (mod 2)
```

So each connection leaks one **GF(2) parity equation per bit of every chunk**:

```
L(c) = Σ_i  b_i · L(root_i)  (mod 2)
```

`L(root_i)` is public (we know `p` and `roots`); `L(c)` is public (we know the
ciphertext). Only the bits `b_i` of the flag chunk are unknown. With enough
connections the 64×64 system per chunk has full rank → Gaussian elimination
over GF(2) recovers every chunk. Then round-trip re-encryption proves the flag.

A single clever connection is all the **data** leaking, but you need **64+**
independent connections to see all 64 unknown bits — each new pair `(p, s)`
gives a brand-new independent equation.

---

## First look

- `incunabula.py` — 107 lines, zero obfuscation, textbook Naccache–Stern.
- `generate_params(256, 64)` builds `roots = [pow(prime, s⁻¹, p−1, p)]`
  (`gmpy2.next_prime` for the prime list: `2,3,5,7,…,311`).
- `encrypt(part, params)` walks 64 bits, raising `roots[i]` to bit `i` and
  multiplying mod `p`:
  ```python
  for i in range(len(params.roots)):
      bit = plaintext & 1
      ciphertext = ciphertext * pow(params.roots[i], bit, params.p) % params.p
      plaintext >>= 1
  ```
- `main()` reads `flag.txt` once, converts to a big int, chops it into 64-bit
  chunks *from the least significant side*, encrypts each, and prints:
  ```
  {'p': …, 'primes': […64…], 'roots': […64…]}
  [c_0, c_1, …, c_8]
  ```
- The running service (`nc tcp.flagyard.com 26167`) prints exactly this then
  hangs for the next connection: **the secret `s` changes every run**, but the
  flag never changes.

---

## Understanding the "three-line" math

Let `(x|p) = x^((p−1)/2) mod p ∈ {±1} / {0,1}` be the Legendre symbol, and write
`L(x) = 0/1` for "is a quadratic residue". Two facts do all the work:

**1. Multiplicativity.**
`L(a·b) = L(a) + L(b) (mod 2)`. Since `c ≡ ∏ roots[i]^b_i`, taking `L` on both
sides turns the subset product into a **linear equation over GF(2)** in the flag
bits `b_i`:

```
L(c) = Σ_i b_i · L(roots[i])   (mod 2)
```

**2. `s` is odd, so `L(roots[i]) == L(primes[i])`.**
`roots[i] = primes[i]^(s⁻¹)`. Legendre of a power is the power of the Legendre
symbol, and raising to an *odd* exponent does not change a ±1 (≡ power of odd
integer mod 2 is the identity):

```
L(roots[i]) = L(primes[i])^(s⁻¹) = L(primes[i])   (s⁻¹ odd)
```

Even better — we never need `s` at all: on each connection,

```
[known]  row_i = L(roots[i]; p)         from the printed roots
[known]  rhs_j = L(c_j; p)              from the printed ciphertexts
[asked]  b_i    chunk_0..8 bits

gives:  rhs_j = Σ_i row_i · b_i  (mod 2),   for j = 0..8
```

The coefficient rows `row` are the *same for all 9 chunks* (they depend only on
`roots`, not on the ciphertext), so one connection yields **9 equations** — one
per chunk — all sharing the same 64-wide coefficient vector. Each fresh
connection is a fresh `p`, so each connection is an independent equation per
chunk.

Recovering chunk 8 needs no equations at all, by the way: the first 8 flag
bytes are `FlagY{aa…` from the prefix — but we recover it honestly from the
linear system together with the rest.

---

## The attack — Legendre parity oracle / chosen-instance linear algebra

1. **Connect** to `tcp.flagyard.com:26167`, read the two printed lines
   (dict `{p, primes, roots}` then list of ciphertexts — careful, the list
   begins *after* the dict's closing `}`; `text.index('[')` alone finds the
   `primes` list *inside* the dict).
2. For each connection compute `row[i] = L(roots[i])`, `rhs[j] = L(c_j)` and
   store them. Repeat until the shared coefficient matrix has rank **64**
   (that always happens quickly — each connection is effectively a random
   GF(2) row).
3. For each chunk `j`, solve `A·x = rhs_j` over GF(2) with Gaussian
   elimination on packed 64-bit integers (RHS parked at bit 64, pivoting on
   bits 0..63).
4. Rebuild the flag big-endian: `flag = Σ_j chunk_j << (64·j)`.
5. **Prove it:** re-encrypt every recovered chunk on one captured instance and
   check the products match the observed ciphertexts exactly.

```
chunk  0: 0x3735643937637d0a     ─┐  LSB chunk ("…c}…")
chunk  1: 0x3137643965633636      │
chunk  2: 0x6264653339326264      │
chunk  3: 0x3462313836373432      │
chunk  4: 0x3135323436633938      │  ≥ 9 chunks require a 65–72-byte flag
chunk  5: 0x6232346532386434      │
chunk  6: 0x6339626635623436      │
chunk  7: 0x3738613362336366      │
chunk  8: 0x466c6167597b6161     ─┘  MSB chunk ("FlagY{aa")
```

---

## Solve

```python
# gathering (one instance = one GF(2) equation per bit per chunk)
def legendre_bit(x, p):
    return 0 if pow(x, (p - 1) // 2, p) == 1 else 1

samples = []
while rank(A) < 64:
    data    = netcat("tcp.flagyard.com", 26167)
    d       = data[data.find("{") : data.rfind("}") + 1]
    params  = ast.literal_eval(d)
    cts     = ast.literal_eval(data[data.find("[", data.rfind("}")) : data.rfind("]") + 1])
    samples.append({
        "row": [legendre_bit(r, params["p"]) for r in params["roots"]],
        "rhs": [legendre_bit(c, params["p"]) for c in cts],
    })

# solving — packed GF(2) Gaussian elimination, RHS at bit 64
def gauss_solve(A, b, nbits):
    mat = [m | ((r & 1) << nbits) for m, r in zip(A, b)]
    piv = {}; r = 0
    for c in range(nbits):
        sel = next((i for i in range(r, len(mat)) if (mat[i] >> c) & 1), None)
        if sel is None: continue
        mat[r], mat[sel] = mat[sel], mat[r]
        piv[c] = r
        for i in range(len(mat)):
            if i != r and ((mat[i] >> c) & 1):
                mat[i] ^= mat[r]
        r += 1
    for i in range(r, len(mat)):
        assert (mat[i] >> nbits) & 1 == 0          # consistency check
    sol = 0
    for c, rr in piv.items():
        if (mat[rr] >> nbits) & 1:
            sol |= 1 << c
    return sol, len(piv)

Abits   = [sum(s["row"][i] * (1 << i) for i in range(64)) for s in samples]
chunks  = [gauss_solve(Abits, [s["rhs"][j] for s in samples], 64)[0]
           for j in range(9)]
plain   = sum(c << (64 * j) for j, c in enumerate(chunks))   # chunk 0 = LSB side
flag    = plain.to_bytes((plain.bit_length() + 7) // 8, "big").rstrip(b"\n")
print(flag)
# b'FlagY{aa78a3b3cfc9bf5b46b24e28d415246c984b186742bde392bd17d9ec6675d97c}\n'
```

The round-trip check compares `∏ roots[i]^bit_i mod p` against the observed
ciphertext per chunk — all 9 match, which confirms the recovered bits, not just
the format.

**Offline note.** The service rate-limits after a few hundred connections.
The solver persists every captured instance to `incunabula_samples.jsonl` and
**gracefully falls back to that cache** (198 instances, rank 64/64) when the
server refuses a connection — the flag never changes, so cached instances stay
valid forever.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Legendre symbol is multiplicative | `encrypt()` builds ciphertext as a subset product mod `p` | the cipher becomes **linear over GF(2)** |
| `s` is chosen odd (must be, for `gcd(s, p−1)==1` with even `p−1`) | `generate_params()` | `L(roots[i]) == L(primes[i])` — oracle is free, no `s` needed |
| Public parameters per connection | server prints `{p, primes, roots}` | rows of the GF(2) system are public |
| Same flag, fresh keys | `flag.txt` read once, keys regenerated per run | each connection is an independent equation for the *same* unknowns |
| No chosen-message protection / oracle-free ciphertext handling | service | every ciphertext is a usable equation (`rhs = L(c)`) |
| 64-bit chunk size ⇔ 64 unknown bits | `nprimes = 64` | only ~64 independent equations needed, then full rank |

Naccache–Stern is a public-key scheme, so the secret exponent should never
leak into the parameters; here the parameters *are* published, but the real
mistake is using a **multiplicatively-homomorphic knapsack** to encrypt a
**static message** across many re-keys: every new key is a new leak, which
turns a strong knapsack into a linear algebra quiz.

---

## Takeaways

- **Multiplicative homomorphism ⇒ GF(2) linearization.** Any "subset product"
  cipher that publishes its generator set becomes a linear system under the
  Legendre symbol — a well-known attack (ASIS 2020 "Dead Drop" uses exactly
  this for a hidden-`s` ElGamal twist).
- **Legendre is an oracle for odds.** Since `p−1` is even, `gcd(s,p−1)=1`
  forces `s` odd, and odd powers never flip a residue symbol: `L(x^s)=L(x)`.
- **Re-keying a static plaintext is a parity source.** Every independent key
  adds an independent GF(2) equation; the attacker only needs as many keys as
  unknown bits.
- **Pack GF(2) rows into machine words.** Rows fit in 64-bit integers, RHS
  parked above bit 64, pivoting is pure integer XOR — no big-int Gaussian
  needed, thousands of equations solve instantly.
- **Correctness ≠ format.** Solving 9 chunks that *look* like 72 bytes of hex
  is not enough — re-encrypting them and matching the ciphertexts is what
  proves the flag.
- **Cache your captures.** On a rate-limited service, saving raw instances to
  disk (`incunabula_samples.jsonl`) makes the solver re-runnable offline and
  the proof reproducible.

---

## The solver

Colored CLI solver in the same folder, **pure Python (stdlib only)**:

```
solve_incunabula.py
```

```bash
python solve_incunabula.py
```

It connects to `tcp.flagyard.com:26167`, keeps a running GF(2) rank counter and
stops as soon as the shared coefficient matrix is full rank (64), falls back to
the bundled `incunabula_samples.jsonl` cache if the server is transiently
offline, solves all 9 chunks, rebuilds the flag big-endian, **proves** it by
re-encrypting every chunk on a captured instance, and saves
`flag_from_incunabula.txt`:

```
FlagY{aa78a3b3cfc9bf5b46b24e28d415246c984b186742bde392bd17d9ec6675d97c}   🏁
```