# FlagYard CTF — Moving On

**Writeup by [General]**

> **General** — *CTF Player | Crypto & Web Security*
>
> **Platform:** [FlagYard](https://flagyard.com) · **Lab:** Training Labs

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** FlagYard
- **Category:** Crypto
- **Difficulty:** Medium

> *"Elapsed modules are no match for the elapsed-curve of the moving on."*

---

## The flag

```
FlagY{SuperSingle_M0Vs}
```

---

## The short version

The box ships an elliptic curve over `F_p` and two public points. One
flag is PKCS#7-padded to a multiple of **12 bytes**, split into two
scalars `s1`, `s2`, and the points are

```
Q1 = s1 * G ,   Q2 = s2 * G ,   G = E.gens()[0]
```

Recovering the flag means solving two discrete logs on the curve. The
one-liner that kills this box: **`#E = p + 1`**, i.e. the curve is
**supersingular**, so the ECDLP can be moved, via the **MOV attack**
(Weil pairing with embedding degree `k = 2`), into the multiplicative
group of `F_{p^2}` — where the discrete log is easy.

- `G = E.gens()[0]` is just the first generator PARI returns from
  `ellgroup(E, p, 1)` — the exact generator Sage lazily calls when you
  type `E.gens()`.
- Lifting each `Qi` to a point of order `q` (`cofactor * Qi`, where
  `cofactor = n/q`) and pairing it against a random order-`q` point `R`
  hands us a log equation `target = w^s` in `F_{p^2}^*`.
- `fflog` (index calculus in the finite field) returns `s mod q` in
  seconds, and the tiny factors `2,5,757,1627,239579` are solved by
  direct DLP on the curve. CRT stitches the flag scalars together.

```
FlagY{SuperSingle_M0Vs}
```

---

## The challenge box

```
p = 0x00e675aaef519c7bdfa7e9b6d5          (96-bit prime, p % 4 == 1)
a = 0x00c5a83d2b9ce92d9c75a37a08
b = 0x0020cd6dc3b4b34e4332463ccd
E : y^2 = x^3 + a*x + b        (mod p)

Q1 = (25868279382606376233089622039, 35226758373642087968613953852)
Q2 = (31211278741961598848732755066, 68653856268530027481128223450)

flag -> PKCS#7 pad -> split in two ->  s1  |  s2
Q1 = s1*G ,  Q2 = s2*G ,  G = E.gens()[0]
```

| Quantity | Value |
|---|---|
| `n = #E(F_p)` | `71323803796758910290373490390` |
| `n = p + 1` | ✅ supersingular (`embedding degree k = 2`) |
| `factor(n)` | `2 · 5 · 757 · 1627 · 239579 · 24171428442137419` |
| big prime `q` | `24171428442137419` (55 bits) |
| `cofactor` | `2950748399810` |

The largest structure one has to grind is **55 bits**; everything below
`q` is trivially distributed. This is a textbook MOV homework curve.

---

## Step 1 — read the generator (why `G` matters)

`E.gens()[0]` is Sage delegating straight into PARI's `ellgroup`:

```python
card, ords, pts = self.__pari__().ellgroup(flag=1)
G = pts[0]                 # first generator, order ords[0]
```

In GP that is exactly

```gp
grp = ellgroup(E, p, 1);
n   = grp[1];
G   = grp[3][1];
```

so a plain PARI/GP binary can reproduce the Sage generator bit-for-bit
— no Sage install required. We get

```
G = (30886797783869397469527651348, 47490012782780803768786078514)
```

## Step 2 — detect the trap (`#E == p+1`)

`ellcard` gives `p + 1` exactly. A supersingular curve has embedding
degree `k = 2`, meaning all of the `q`-torsion lives over `F_{p^2}` and
the Weil pairing is *defined*:

```gp
u  = ffgen(p^2, 'u);
E2 = ellinit([u^0*a, u^0*b]);
```

## Step 3 — MOV setup

Reduce everything into the order-`q` subgroup, then find one pairing
`w != 1` to act as the discrete-log base:

```gp
P = ellmul(E2, G2, cofactor);        // order q
for (i = 1, 1000000,
  x = random(p) + u*random(p);
  ys = ellordinate(E2, x);
  Rtmp = ellmul(E2, [x, ys[1]], cofactor);   // order q (or 0)
  wtry = ellweilpairing(E2, P, Rtmp, q);
  if (wtry != 1, R = Rtmp; w = wtry; break));
```

After a handshake pulls instantly:

```
[+] MOV setup ready   w = 14974498185359555517450742930*u + 26061011752173361288191803667
```

## Step 4 — solve the log *in the field*

For each point: pair `cofactor*Qi` against `R`, then take the discrete
log in `F_{p^2}^*` with index calculus — `fflog(value, base, q)`:

```gp
target = ellweilpairing(E2, Qq, R, q);
s      = lift(fflog(target, w, q)) % q;      // -> s mod q
```

Two calls, a couple of seconds each:

```
q-residue1: 503068454814206
q-residue2: 17479345517791239
```

## Step 5 — tiny subgroups + CRT

The small prime factors `[2,5,757,1627,239579]` are solved by direct
`elllog` on `E(F_p)` (`m` iterations max), giving residues mod each `m`:

```
mod 2 -> 1     mod 5 -> 0     mod 757 -> 429
mod 1627 -> 646              mod 239579 -> 2701          (Q1)
mod 2 -> 1     mod 5 -> 4     mod 757 -> 573
mod 1627 -> 907              mod 239579 -> 98454         (Q2)
```

Chinese-remainder each residue with `s mod q`:

```
secret1 = 21794974652023851764645458515
secret2 = 32629396274699578950030687489
```

## Step 6 — the flag

Every secret is a big-endian 12-byte block; unpad the PKCS#7 tail:

```
secret1 -> [70 108 97 103 89 123 83 117 112 101 114 83]  <- "FlagY{SuperS"
secret2 -> [105 110 103 108 101 95 77 48 86 115 125 1]   <- "ingle_M0Vs}\x01"
unpad   -> FlagY{SuperSingle_M0Vs}
```

---

## The calculation

```
build the curve        : E over F_p,   n = #E = p + 1   (supersingular)
generator              : G = ellgroup(E, p, 1)[3][1]    (= sage E.gens()[0])
lift to F_{p^2}        : E2,  P = cofactor*G,  random R of order q
pairing base           : w = P.weil_pairing(R, q) != 1
for each Qi            : s (mod q) = fflog(cofactor*Qi .weil_pairing(R,q), w, q)
small factors          : DLP on E(F_p) for {2,5,757,1627,239579}
CRT                    : s1, s2 (mod n)
flag                   = s1(12 bytes) || s2(12 bytes)  ->  PKCS#7 unpad
```

```
★  FLAG RECOVERED  ★
FlagY{SuperSingle_M0Vs}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| Supersingular curve (`#E = p+1`) with embedding degree `k = 2` | `chall.sage` | ECDLP transfers into `F_{p^2}^*` via the Weil pairing (MOV) and collapses |
| Large prime factor only **55 bits** | `factor(#E)` | End game is `fflog` in a field / DLP in a tiny quotient — seconds |
| Flag split into scalars, not encoded bytes | `chall.sage` | Hides the flag from a `grep`, but scalars are just base-256 chunks |
| `G = E.gens()[0]` | Sage→PARI `ellgroup` bridge | Reproducible in plain GP, so no Sage dependency locks the solve |
| No pairing-prevention (e.g. embedding degree check) | `chall.sage` | MOV is the whole point of the box |

> The real hook: the flag only exists as *two scalars on a mismanaged
> curve*. The moment `#E = p+1` is spotted, the challenge reads itself.

---

## Takeaways

- **`#E = p + 1` is the smell.** Supersingular curves have embedding
  degree 2; every log on them is a field log away. Always run
  `factor(E.order())` before attacking an ECDLP box.
- **MOV is your friend.** Weil + a random point gives a pairing base;
  `fflog` in `F_{p^2}` beats `elllog` on the curve by orders of
  magnitude when a big prime sits atop tiny factors.
- **Generator matters — and it's PARI.** Sage `E.gens()[0]` is literally
  `ellgroup(flag=1)`'s first generator. Anyone with a plain `gp` binary
  reproduces the official generator.
- **CRT is the glue.** Field log gives `s mod q`; small subgroup logs
  give the rest; CRT reconstructs the flag scalar exactly.
- **The setup is the slow part.** Picking a good random `R` with
  `w != 1` is a lottery; everything after it is fast.

---

## The solver

`solve_movingon.py` — drives either **SageMath** or a **plain PARI/GP**
binary (`gp.exe` / `gp` on PATH), performs the full MOV reduction, and
prints the flag:

```
python solve_movingon.py
★  FLAG RECOVERED  ★
FlagY{SuperSingle_M0Vs}
        elapsed ~790 s
        MOV attack | F_{p^2} Weil pairing | CRT
```

It saves the flag to `flag_from_movingon.txt`. The two backends are also
shipped standalone: `solve_movingon.gp` (PARI) and `solve_movingon.sage`
(SageMath).

---

## Credit

- **Writeup by:** General
- **Challenge author:** FlagYard (Lab: *Moving On*).