FlagYard | Roll Call (Crypto — Hard) — Writeup

**Fares Badaj**

---

## Info

| | |
|---|---|
| Challenge | Roll Call |
| Difficulty | Hard |
| Category | Crypto |
| Platform | FlagYard Training Labs (SAFCSP) |
| Description | *Name the absent member 16 times.* |
| Flag | `FlagY{3f2929933428f484af88047c89963351}` |

---

## 1. The box

TCP service (`tcp.flagyard.com:27905`) with full source. A classroom of 256
members `0..255` each round; one member `a` is absent. Three commands per
round:

* `handle c` — the server picks a fresh random `k` and returns the **ordered**
  encryption list of every present member
  `eids[j] = H(roster[j])^k mod p`, then `deid = c^k mod p`;
* `submit x` — round ends, `True` only if `x == a`.

Win 16 rounds in a row to get the flag.

```python
p = 113922386694983050382912391517437431439572639334235676622418446302583918640667
q = 56961193347491525191456195758718715719786319667117838311209223151291959320333
N = 256

def H(member_id):
    h = int.from_bytes(hashlib.sha256(f"id={member_id}".encode()).digest(), "big") % p
    return pow(h, 2, p)          # always a quadratic residue
```

## 2. Why the obvious attacks die

`p` is a **safe prime** (`p = 2q + 1`) and `q` is a 245-bit prime, so the QR
subgroup has prime order → the discrete log of `deid` (recovering `k`) is
infeasible. A membership test (`c = H(x)` → is `deid` in `eids`?) gives **one
bit** per handle, and the `eids` position of a known member only tells you one
side of `a`. With only 2 handles per round that can never narrow down 256
values — binary search needs 8.

## 3. The trick: the roster order is deterministic

`eids` keeps **ascending roster order**, just skipping the absent member:

```
eids[j] = H(member at position j)^k,   roster = [0..255] \ {a}
```

That means *given* an "absent-claim" `a'`, every member `m ≠ a'` must live at
a single predictable slot:

```
pos(m, a') = m      if a' > m     (a' after m, no shift)
             m - 1  if a' < m     (a' before m, m shifted left)
```

Now send one handle with **`c` = the product of `H(m)` over all 128 odd
members**. Then `deid = ∏_{odd m} H(m)^k`, while for a claimed `a'` we can
predict the same from `eids`:

```
pred(a') = ∏_{odd m} eids[pos(m, a')]   mod p
```

`pred(a')` equals `deid` **iff `a'` and the true `a` sit on the same side of
every odd member** — i.e. `a'` and `a` fall in the *same cell* of the odd
partition. Because the odd thresholds are spaced 2 apart, the cells are
singletons at even values:

```
a even  ->  pred(a') == deid ONLY for a' == a   → submit, done
a odd   ->  no hypothesis matches at all         → "a is odd" signal
```

If `a` is odd, one more handle with `c` = product of `H(m)` over all even
members: now `a' == a` is the unique match again. Every round is solved with
**≤ 2 handles** (1 often), no DLP, no guessing.

## 4. Result

Ran the solver 16/16 rounds:

```
round 1  absent=255   round  5  absent=194   round  9  absent=255   round 13  absent=104
round 2  absent=191   round  6  absent=151   round 10  absent=128   round 14  absent=61
round 3  absent=240   round  7  absent=15    round 11  absent=117   round 15  absent=78
round 4  absent=123   round  8  absent=215   round 12  absent=70    round 16  absent=21
```

```
FLAG = FlagY{3f2929933428f484af88047c89963351}
```

---

## Root cause

* The "encryption" is not used as a PRF here — the **roster ordering is
  leaked** by the returned list, and `eids` values are *fixed-width* encodings
  (`H(m)^k`) whose products can be cross-checked between hypotheses.
* A single product query over half the members lets the attacker verify *all*
  256 absent-claims at once.

## Remediation

* Then member list by the random key, or return `eids` in random order with no
  link to membership indices.
* Make `k` oracle-independent (e.g., use a real public-key scheme / hash of
  the roster) so `deid`/`eids` carry no order information.

## Files

* `solve_rollcall.py` — automated exploit (2 handles max per round).
* `flag_from_rollcall.txt` — `FlagY{3f2929933428f484af88047c89963351}`.