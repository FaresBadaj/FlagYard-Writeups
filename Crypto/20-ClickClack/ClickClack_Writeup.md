# FlagYard CTF — ClickClack

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Crypto
- **Difficulty:** Medium
- **Endpoint:** offline — solved from the captured transcript in `output.txt` (*"clickclack means a single way you get me"*)

---

## The flag

```
FlagY{best_vuln_P3rf3ct_f0rw@rd_S3cr3cy_1mpl3m3nt3d}
```

---

## The short version

An "ECDH" handshake is eavesdropped in `output.txt`: both public points, plus an
AES-128-CBC blob of the flag. The curve is called `CHECKPOINT` and has a
255-bit prime. Everything looks standard, and the shared secret looks like it
needs a 255-bit ECDLP.

It doesn't. **The curve is singular.**

```
4a^3 + 27b^2  =  0   (mod p)
```

The discriminant is zero, so `y^2 = x^3 + ax + b` is not an elliptic curve —
it's a **nodal cubic**. Its rational points form a group isomorphic to
`(F_p*, *)`, of order `p-1`, and `p-1` is *completely smooth*:

```
p-1 = 2 * 2757875111 * 2881450211 * 3753286421 * 3997403287
        * 4231024097 * 2936391401 * 3533373847 * 2879985937
```

Nine factors, the largest ~32 bits. So the "ECDLP" is a **Pohlig-Hellman +
baby-step giant-step in a multiplicative group** — a few seconds of work, and
the hard part (recovering the group secret) was never the bottleneck anyway.

The whole flag:

```
double root  -> translate -> explicit isomorphism to F_p*
             -> PH/BSGS on nine smooth subgroups -> server secret
             -> ECDH shared point -> sha256(str(x))[:16] -> AES-CBC
```

---

## The challenge box

`clickclack.py` prints the transcript of a "TLS-like handshake" it just
eavesdropped on:

```
Eavesdropping on a TLS-like handshake ...
client initiating key agreement:
client->server : Point(x=20730353746771923164183855546918927514052200667457888753036022790610499001387, y=11023214354676535187264261449659989136982591573877538141550684119908521037491)
server->client : Point(x=16661893300385393873168299612904527389254804345363326945433170387510525597777, y=10748783436092281707269388140779922183841038594517620816106589836924805342512)
server->client : 44c475dbf81e17fa8bcc09d7ddfe830b8...
```

The curve, hard-coded:

```python
p = 30147047372537667543227596509433268914148160199933678584277532878812522173123
a = 4295866710341558381730993001337260151326704354119856057045858346018488917551
b = 27915475329982779370228189153614202544988456477009880605661666567636553859719
G = Point(23660607485931404474159157392651047549672758508793488070957915230753900420346,
          8315837926899275371387974820365523190632259447349013169853248963499139967386)
```

and the protocol:

```python
self.s   = int.from_bytes(urandom(32), "little")
self.P   = double_and_add(G, self.s, curve)          # server public key

def ecdh_kex(self, Q, ciphersuite):                   # Q = client public key
    if ciphersuite != "ECDHE_CHECKPOINT_WITH_AES_128":
        raise Exception("Ciphersuite not supported.")
    shared_point = double_and_add(Q, self.s, curve)
    self.shared_key = sha256(str(shared_point.x).encode()).digest()[:16]

def send_msg(self, pt):
    iv = urandom(16)
    return iv + AES.new(self.shared_key, AES.MODE_CBC, iv).encrypt(pad(pt, 16))
```

So we know `Q_client`, `P_server = s·G`, and `AES-128-CBC(key, FLAG)` where
`key = sha256(str(x-coordinate of s·Q_client))[:16]`. The only missing piece is
`s` (or directly the shared point).

The "one way you get me" line in the challenge description is the hint: there is
exactly one right tool, and it is *not* a generic ECDLP solver.

---

## Step 1 — check the discriminant (this is the whole challenge)

Before any attack, look at the curve. A short Weierstrass curve
`y^2 = x^3 + ax + b` is a **non-singular** elliptic curve iff

```
4a^3 + 27b^2  !=  0   (mod p)
```

One modular exponentiation, or even simpler — just multiply:

```
4a^3 + 27b^2 = 0
```

The discriminant is `Δ = -16(4a³ + 27b²) = 0`. **The curve is singular.** There
is no elliptic curve group here at all, so the ECDLP literature
(Pohlig-Hellman on `#E`, Pollard rho, anomalous curves, MOV, ...) does not apply
in the form you'd expect.

A singular `y^2 = x^3 + ax + b` factors as a polynomial:

```
f(x) = (x - x1)^2 * (x - x2)      with   2*x1 + x2 = 0
```

with a **double root** `x1`. Find it from `f'(x) = 3x^2 + a = 0`:

```
x1 = sqrt( -a / 3 )   mod p
```

Since `p ≡ 3 (mod 4)` we get the square root with a single exponentiation,
`(-a/3)^((p+1)/4)`:

```
x1 = 28681707882171910318735755084384649303003217724290723820373646857737676416087
x2 = -2*x1 = 2930678980731514448983682850097239222289884951285909527807772042149691514072
```

The singular point is `(x1, 0)`, and because the root is **double**, the
tangent cone at `(x1, 0)` has two distinct lines — this is a **node**, not a
cusp. A nodal cubic over `F_p` is isomorphic to the multiplicative group
`(F_p*, ·)`, of order `p-1`. (A cuspidal cubic would give the *additive* group
`(F_p, +)` instead — that one is even easier, since the DLP is linear.)

---

## Step 2 — translate the node to the origin

Shift `X = x - x1`, `Y = y`. Substituting `x = X + x1` into
`(x - x1)^2 (x - x2)`:

```
Y^2 = X^2 * (X + x1 - x2) = X^2 * (X + 3*x1)
```

so in standard form `Y^2 = X^3 + a2'*X^2` with

```
a2' = 3*x1 = 25751028901440395869752072234287410080713332773004814292565874815587984902015
```

Now the useful part — the node splits over `F_p` iff `a2'` is a quadratic
residue, because the tangent lines are `Y = ±sqrt(a2')*X`:

```
legendre(a2') = +1     ->  split node  ->  E(F_p)  ~=  F_p*
```

(had it been `-1`, the node would be a single point over `F_p²` and the group
would be a subgroup of order `p+1` — solvable the same way, just with `p+1`.)

So take `s = sqrt(a2') = a2'^((p+1)/4)`:

```
s = 7846483633729359298559966827948991490730332339182224980757167184419692758342
```

### The trap: the group law changes form

A subtlety worth flagging, because it silently breaks naive solvers. The
original curve is `a2 = 0`, so the familiar short-Weierstrass doubling

```python
lam = (3*x**2 + A) * inverse(2*y, p)
X3  = (lam**2 - x1 - x2) % p          # <-- no a2 term
```

is correct *there*. After translating, `a2' = 3*x1 ≠ 0` and the formula becomes

```python
lam = (3*X**2 + 2*a2p*X) * inverse(2*Y, p)
X3  = (lam**2 - a2p - X1 - X2) % p   # <-- the -a2' term appears
```

Using the classic formula after the translation gives points that are **not on
the curve**, and any homomorphism test fails with no obvious error message.
The solver asserts `on_curve()` on every intermediate point so this can't
silently pass.

---

## Step 3 — the explicit isomorphism `E(F_p) -> F_p*`

For `Y^2 = X^3 + a2'*X^2` with node at the origin, write `Y = X·u`. Then

```
u^2 = X + a2'    =>    X = u^2 - a2'
```

which parameterises the curve by `u = Y/X`. The group law on the nodal cubic
becomes multiplication in `u`, and a change of variable turns that into
multiplication in `F_p*`. Concretely:

```
phi(X, Y) = (Y - s*X) / (Y + s*X)      phi(O) = 1
```

Check it is a homomorphism (the solver does exactly this):

```
phi(k*G) == phi(G)^k      for k = 1..5        OK
(p-1)*G  == O                                OK
```

Sanity checks on the three public values:

```
phi(G)      = 2
phi(client) = 26612341732003122808373489180654561979100004335052993484598158152283106291260
phi(server) = 12095922240933555879880606429445403379359782336353882088305390721692907447329
```

`phi(G) = 2` is a nice accident: the map lands the generator on the smallest
possible integer, which makes the PH subgroups easy to eyeball.

---

## Step 4 — recover the server secret (Pohlig-Hellman + BSGS)

The server public key is `P_server = s·G`, so in the multiplicative group

```
phi(server) = s^k      with   k = phi(G) = 2
```

`p-1` is smooth, so PH decomposes it:

```
p-1 = 2^1 * 2757875111 * 2881450211 * 3753286421 * 3997403287
        * 4231024097 * 2936391401 * 3533373847 * 2879985937
```

Each subgroup has a ~32-bit order, so each one is a baby-step giant-step with
~65k table entries and a single pass. Per-subgroup results:

```
s mod 2            = 0
s mod 2757875111   = 657757874
s mod 2881450211   = 1808016265
s mod 3753286421   = 1164289119
s mod 3997403287   = 3523950723
s mod 4231024097   = 515524543
s mod 2936391401   = 2699834652
s mod 3533373847   = 726157252
s mod 2879985937   = 1799857875
```

CRT:

```
s = 24463082242328042600680328545930156477892769117871296019487801984291293436706
```

Verified: `2^s mod p == phi(server)`.

Total cost: nine BSGS instances on 32-bit groups. No index calculus, no
`sympy.discrete_log`, no elliptic-curve machinery at all.

---

## Step 5 — shared secret and the flag

Recompute the ECDH shared point (back in original coordinates, `a2 = 0`
again) and derive the key exactly as the server does:

```
shared_point = s * Q_client
             = (16822401572492084467154572789636672826286385095636651522854387863394641943272,
                29953892936362419353200909610538583494040292862557551850806306958971478141781)

shared_key = sha256(str(shared_point.x)).digest()[:16]
           = 6ab3a76e2945acfc2c3d2c4ee829a1d4
```

The blob is `iv (16 bytes) || AES-128-CBC(shared_key, pad(FLAG, 16))`:

```
iv = 44c475dbf81e17fa8bcc09d7ddfe830b
```

```
FlagY{best_vuln_P3rf3ct_f0rw@rd_S3cr3cy_1mpl3m3nt3d}
```

---

## Result

```
  ╔══════════════════════════════════════════════════════════╗
  ║                   ★  FLAG RECOVERED  ★                   ║
  ║   FlagY{best_vuln_P3rf3ct_f0rw@rd_S3cr3cy_1mpl3m3nt3d}   ║
  ╚══════════════════════════════════════════════════════════╝
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| Curve never validated: `4a³ + 27b² ≡ 0` | `CHECKPOINT` params in `clickclack.py` | the "elliptic curve" is a singular cubic; its group is `F_p*`, not an EC |
| `p-1` fully smooth (nine ~32-bit factors) | field choice | PH + BSGS solves the secret in seconds — the hardness of ECDLP evaporates |
| Node splits over `F_p` (`legendre(3x₁) = +1`) | curve shape | the isomorphism to `F_p*` is explicit and rational — no point-counting needed |
| ECDH key derived by hashing only the `x` coordinate | `ecdh_kex` | one-way function on a single coordinate; standard, but it means the attacker only needs the point, not `s` |
| A 255-bit prime | field choice | below the ~256-bit bar; only matters because the group is trivial, but it removes any "small enough to brute force" objection |
| Nothing in the transcript is authenticated | the "TLS-like" framing | a passive eavesdropper recovers the flag; no MAC, no transcript binding |

---

## Takeaways

- **Always check the discriminant before writing a single line of ECDLP
  code.** `4a³ + 27b² ≡ 0` is a *one-multiply* test, and it distinguishes a
  real EC from a curve whose group law is `F_p*` or `F_p`. Most tooling will
  happily compute points on a singular curve and hand you garbage instead of
  telling you the group you are actually in.
- **Singular ≠ safe.** The curve being "broken" is not a theoretical nicety:
  singular cubics have *fully explicit* isomorphisms to `(F_p*, ·)` or
  `(F_p, +)`, both of which are routinely solvable. Smart's attack on anomalous
  curves is the elliptic analogue; here it's simpler.
- **Smoothness of `p-1` is a first-class parameter.** In the multiplicative
  group, `p-1` smooth = DLP free. Choose `p` so that `p-1` has a large prime
  factor (SafePrimes / `p-1` with a big divisor), not just so `p` is large.
- **A translation changes the group law formula.** `a2` is 0 on the original
  curve and non-zero after shifting the node to the origin; the `-a2` term in
  `X3` appears out of nowhere and its absence produces off-curve points with no
  exception raised. Assert `on_curve()` after every operation.
- **The name was the hint.** "A single way you get me" = one specialisation
  for one curve family. The generic ECDLP solvers were never going to be the
  path; recognising the singularity was the entire challenge.

---

## The solver

`solve_clickclack.py` — parses `output.txt`, proves the curve singular, derives
and verifies the isomorphism, runs Pohlig-Hellman + BSGS over the nine smooth
subgroups, then derives the key and decrypts. Fully offline, `W = 58` framed
panel, same design as the other FlagYard solvers:

```
python solve_clickclack.py

  ╔══════════════════════════════════════════════════════════╗
  ║            C L I C K C L A C K   S O L V E R             ║
  ║     singular curve  |  Pohlig-Hellman on smooth p-1      ║
  ╚══════════════════════════════════════════════════════════╝

  [  3.0%] ▶  reading the eavesdropped transcript
  [  7.0%] ✓  output.txt  (628 bytes)
  [ 10.0%] ✓  ciphersuite ECDHE_CHECKPOINT_WITH_AES_128
  [ 12.0%] ✓  field 255 bits, client pub x = 2073035374...0499001387
  [ 14.0%] ✓  server pub x = 1666189330...0525597777
  [ 16.0%] ✓  ciphertext 80 bytes, iv = 44c475dbf81e17fa8bcc09d7ddfe830b
  [ 20.0%] ▶  checking the discriminant  4a^3 + 27b^2 (mod p)
  [ 24.0%] ✓  4a^3 + 27b^2 = 0  ->  discriminant vanishes
  [ 28.0%] ▶  this is not an elliptic curve - it is a singular cubic
  [ 32.0%] ▶  locating the singular point  x1 = sqrt(-a/3)
  [ 36.0%] ✓  double root x1 = 2868170788...7676416087
  [ 40.0%] ✓  simple root x2 = -2*x1 = 2930678980...9691514072
  [ 44.0%] ▶  translating the node to the origin  (a2' = 3*x1)
  [ 48.0%] ✓  Y^2 = X^3 + a2'*X^2,  a2' = 2575102890...7984902015
  [ 51.0%] ✓  legendre(a2') = +1  ->  split node,  E(F_p) ~= F_p*
  [ 53.0%] ✓  s = sqrt(a2') = 7846483633...9692758342
  [ 57.0%] ▶  verifying the translated group law
  [ 60.0%] ✓  G, client and server all lie on the translated cubic
  [ 64.0%] ▶  checking phi is a homomorphism  (k=1..5)
  [ 68.0%] ✓  phi(kG) = phi(G)^k for k = 1..5
  [ 71.0%] ▶  checking the group order is p-1
  [ 74.0%] ✓  (p-1)*G = O  ->  order p-1, so E(F_p) ~= F_p*
  [ 76.0%] ✓  phi(G) = 2
  [ 77.0%] ✓  phi(server) = 1209592224...2907447329
  [ 80.0%] ▶  factoring p-1  (9 distinct prime factors)
  [ 83.0%] ✓  largest prime-power subgroup 4231024097  (~32-bit DLP)
  [ 84.0%] ✓  p-1 = 2^1 * 2757875111^1 * 2881450211^1 * 3753286421^1 * 3997403287^1 * 4231024097^1 * 2936391401^1 * 3533373847^1 * 2879985937^1
  [ 87.0%] ▶  Pohlig-Hellman + baby-step giant-step over F_p*
  [ 87.0%] ▶  BSGS in the subgroup of order 2
  [ 88.0%] ▶  BSGS in the subgroup of order 2757875111
  [ 89.0%] ▶  BSGS in the subgroup of order 2881450211
  [ 90.0%] ▶  BSGS in the subgroup of order 3753286421
  [ 91.0%] ▶  BSGS in the subgroup of order 3997403287
  [ 92.0%] ▶  BSGS in the subgroup of order 4231024097
  [ 93.0%] ▶  BSGS in the subgroup of order 2936391401
  [ 94.0%] ▶  BSGS in the subgroup of order 3533373847
  [ 95.0%] ▶  BSGS in the subgroup of order 2879985937
  [ 97.0%] ✓  server secret s = 2446308224...1293436706
  [ 98.0%] ✓  verified:  phi(G)^s == phi(server)
  [ 98.5%] ▶  recomputing the ECDH shared point  s * Q
  [ 99.0%] ✓  shared x   = 1682240157...4641943272
  [ 99.3%] ✓  sha256(str(x))[:16] = 6ab3a76e2945acfc2c3d2c4ee829a1d4
  [ 99.6%] ▶  decrypting AES-128-CBC
  [ 99.9%] ✓  valid FlagY{} format

  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║                   ★  FLAG RECOVERED  ★                   ║
  ║                                                          ║
  ║   FlagY{best_vuln_P3rf3ct_f0rw@rd_S3cr3cy_1mpl3m3nt3d}   ║
  ║                      elapsed 13.0 s                      ║
  ║      singular curve -> F_p* | PH/BSGS on 9 factors       ║
  ║                                                          ║
  ╠══════════════════════════════════════════════════════════╣
  ║   made with ❤  by  Fares Badaj                           ║
  ║   Red Team Operator | Penetration Tester Specialist      ║
  ╠══════════════════════════════════════════════════════════╣
  ║   Telegram  ›  @ptok3        t.me/ptok3                    ║
  ║   GitHub    ›  github.com/FaresBadaj                     ║
  ║   LinkedIn  ›  linkedin.com/in/FaresBadaj                ║
  ║   Credly    ›  credly.com/users/faresbadaj               ║
  ╚══════════════════════════════════════════════════════════╝

  [+] saved to flag_from_clickclack.txt
```

It asserts `on_curve()` for every public point, `phi(kG) == phi(G)^k` for
`k = 1..5`, `(p-1)*G = O`, `legendre(a2') = +1`, and `phi(G)^s == phi(server)`
before decrypting — so picking the wrong singular-curve attack fails loudly
instead of printing a plausible flag. It saves the flag to
`flag_from_clickclack.txt`.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)