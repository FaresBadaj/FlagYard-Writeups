# FlagYard CTF — constrained

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) • **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) • **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) • **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Medium
- **Target:** `chall.pyc` — CPython 3.6 bytecode (magic `0x0d0d33`).

> *"And then I started thinking about ... constraint solver"* — the hint is
> the whole solution.

---

## The flag

```
FlagY{w0w_I_hop3_You_used_z3_or_smth_01830193972983}
```

---

## The short version

`chall.pyc` is Python 3.6 bytecode exposing a single real function,
`check(flag)`. Unpacked with `xdis`, it replays `random.seed(1337)` and then
runs **56 rounds** of:

```
a,b,c,d = randint(0,51) x4               # same indices as the checker
((flag[a]<<8) + flag[b]) * ((flag[c]<<8) + flag[d])  &  0xffff  ==  magic[i]
```

Only the **low 16 bits** of every product are asserted, so the check is a
big **non-injective modular constraint system** — exactly what z3 is for.
We model each flag byte as a printable `BitVec`, pin the `FlagY{…}` envelope,
and let z3 solve the 56 modular products. It returns a unique 52-byte flag.

---

## Step-by-step

### 1. Look at the bytecode

The pyc has no symbol noise, so `xdis.load_module` gives straight reads:

```python
import xdis
r = xdis.load_module("chall.pyc")
co = r[3]                       # code object for <module>
print(co.co_consts)             # numbers + the check() code object
```

Decompiled, `check` is:

```python
def check(flag):
    if len(flag) != 52:
        return False
    random.seed(1337)
    for i in range(56):                     # 56 rounds
        a = random.randint(0, 51)
        b = random.randint(0, 51)
        c = random.randint(0, 51)
        d = random.randint(0, 51)
        t = ((flag[a] << 8) + flag[b]) * ((flag[c] << 8) + flag[d]) & 0xffff
        if t != magic[i]:
            return False
    return True
```

`random.seed(1337)` + `randint(0, 51)` is the deterministic Mersenne Twister
stream — we reproduce it exactly, so every round gives the **same** indices
`(a,b,c,d)` the binary computed at authoring time.

### 2. magic[]

The `magic` list is built straight in the module with a `BUILD_LIST` of 56
integer constants (`co_consts[2:58]`), e.g.:

```
magic = [6596, 29872, 62287, 15227, 36671, 60341, ..., 56666]
```

Verify identity with the pyc constants (the solver does this automatically):

```python
built = [c for c in co.co_consts if isinstance(c, int)][1:57]
```

### 3. Model + solve

The low-16-bits of the product lose information, so there is no unique
"invert the equation" route — it's a constraint system. Model each byte:

```python
from z3 import BitVec, Or, Solver, sat
n  = 52
f  = [BitVec(f"f{i}", 32) for i in range(n)]
s  = Solver()
for i in range(n):
    s.add(Or([f[i] == c for c in range(0x20, 0x7f)]))   # printable ASCII
for i, ch in enumerate("FlagY{"):
    s.add(f[i] == ord(ch))
s.add(f[n-1] == ord("}"))

random.seed(1337)
for i in range(56):
    a = random.randint(0, 51); b = random.randint(0, 51)
    c = random.randint(0, 51); d = random.randint(0, 51)
    s.add(((f[a] << 8) + f[b]) * ((f[c] << 8) + f[d]) & 0xffff == magic[i])

assert s.check() == sat
return "".join(chr(s.model().evaluate(f[i]).as_long()) for i in range(n))
```

### 4. Cross-verify

Re-import `random`, `seed(1337)`, replay the 56 rounds against the solved
string: **0 mismatches** — the flag satisfies every product, `len == 52`,
and it fits `FlagY{…}`:

```
FlagY{w0w_I_hop3_You_used_z3_or_smth_01830193972983}
```

---

## Solver

`constrained_solve.py` — disassembles the pyc (xdis), cross-checks `magic[]`,
and drives z3:

```
python constrained_solve.py
★  FLAG RECOVERED  ★
FlagY{w0w_I_hop3_You_used_z3_or_smth_01830193972983}
```

---

## Tools

- `xdis` — Python 3.6 opcode disassembly of the pyc
- `z3` — BitVec constraint solver
- CPython `random` — Mersenne Twister stream replay (`seed(1337)`)

---

## Takeaways

- **`& 0xffff` on every product means the system is non-injective** — no
  clean arithmetic inversion; that's the tell for "use a SAT/SMT solver".
- **`random.seed` + `randint` is deterministic**: replay the exact stream
  with the same PRNG to regenerate the (a,b,c,d) index tape.
- **Pinning the `FlagY{…}` envelope + printable-ASCII domain** prunes the
  model space and, with it, the classic OR-amiguity that richer domains and
  wraparound products leave behind.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)