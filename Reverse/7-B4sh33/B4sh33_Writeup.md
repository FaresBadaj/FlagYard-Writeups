# FlagYard CTF — B4sh33

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Medium (متوسط)
- **Description:** "Reading bash is always fun."

---

## The flag

```
FlagY{b89f-f302-dd51-205f1}
```

---

## The short version

`Chall.sh` is a bash "keygen" — no binary at all. It builds
`version=(0 0 0 0)` → `"0.0.0.0"`, MD5s it, splits the 32-hex digest into 16
`hash_bytes`, then runs **20 gates**:

```
if [ $(( char_val ^ CONST )) -eq ${hash_bytes[J]} ]; then
    version[V]=$((version[V] + 1))
fi
```

where `char_val = ord(input[k])`. Each gate bumps one of the four
`version[0..3]` counters, and SUCCESS requires **every counter to equal 5**.
Each counter is wired to exactly five gates, so all 20 gates must pass — every
checked input character is pinned:

```
input[k] = hash_bytes[J] ^ CONST
```

Reading the 20 `(position, constant, hash-index)` triples and the schedule
digest gives the 20 characters `b89f-f302-dd51-205f1`; `FlagY{$1}` prints them.

---

## First look

A single 124-line script, no packer, no PE, nothing to execute:

```bash
if [ $# -lt 1 ]; then input=""; else input="$1"; fi
input="${input}XXXXXXXXXXXXXXXXXXXXXXX"
declare -a version=(0 0 0 0)
initial_version=$(IFS='.'; echo "${version[*]}")      # 0.0.0.0
hash=$(echo -n "$initial_version" | md5sum | cut -d' ' -f1)

declare -a hash_bytes
for ((i=0; i<32; i+=2)); do
    hex_byte="${hash:$i:2}"
    hash_bytes[$((i/2))]=$((16#$hex_byte))            # 16 bytes
done
```

- The 23 trailing `X`s guarantee `$1` of length ≤ 20 always has 23 backing
  characters — the gates index `0..19` safely.
- `initial_version` is just the four counters joined on `.`: a **fixed
  `0.0.0.0`**, so the digest is a compile-time constant key schedule.

Then 20 copy-paste blocks, each reading one input slot:

```bash
char_val=$(printf "%d" "'${input:0:1}")     # ord(input[0])
if [ $((char_val ^ 0x56)) -eq ${hash_bytes[3]} ]; then
    version[0]=$((version[0] + 1))
fi
```

### The backtick artifact

The original line must have used bash command substitution to turn the
character into its code:

```bash
char_val=$(printf "%d" "'`${input:0:1}`")   # ord(input[i])  (backticks)
```

In the shipped file the grab-backticks were **stripped** (`'"'${input:0:1}'"'`);
the file contains zero `` ` `` characters. "Reading bash is always fun": the
arithmetic is obvious from intent, and the key schedule / gates are fully
recoverable regardless.

---

## Reading the 20 gates

Extract every `(position, xor, hash_byte_index, version_index)`:

| # | pos | const | hash_bytes[J] | → version |
|---|---|---|---|---|
| 1 | 0 | `0x56` | `[3]` | 0 |
| 2 | 5 | `0x07` | `[7]` | 1 |
| 3 | 12 | `0x25` | `[11]` | 2 |
| 4 | 3 | `0xe2` | `[15]` | 3 |
| 5 | 8 | `0x4b` | `[2]` | 0 |
| 6 | 1 | `0xda` | `[6]` | 1 |
| 7 | 15 | `0x42` | `[10]` | 2 |
| 8 | 7 | `0xa6` | `[14]` | 3 |
| 9 | 4 | `0xdc` | `[1]` | 0 |
| 10 | 11 | `0x2e` | `[5]` | 1 |
| 11 | 18 | `0xff` | `[9]` | 2 |
| 12 | 2 | `0xd6` | `[13]` | 3 |
| 13 | 9 | `0xdc` | `[0]` | 0 |
| 14 | 14 | `0xae` | `[4]` | 1 |
| 15 | 6 | `0x05` | `[8]` | 2 |
| 16 | 13 | `0x65` | `[12]` | 3 |
| 17 | 16 | `0xc1` | `[1]` | 0 |
| 18 | 10 | `0x2e` | `[5]` | 1 |
| 19 | 19 | `0xa8` | `[9]` | 2 |
| 20 | 17 | `0xda` | `[13]` | 3 |

Positions `0..19` each appear **exactly once**; every `version[V]` gets five
gates.  Positions 10 and 11 share `(hash_bytes[5], 0x2e)` → both decode to `d`,
the only repeated character.

## Recovering the key schedule

```bash
hash=$(echo -n "0.0.0.0" | md5sum | cut -d' ' -f1)
# f1f17934834ae2613699701054ef9684
```

`hash_bytes = f1 f1 79 34 83 4a e2 61 36 99 70 10 54 ef 96 84` (indices 0..15).

---

## Solve

```python
import hashlib
hb = hashlib.md5(b"0.0.0.0").digest()

# (position, xor_const, hash_index) from the 20 gates
gates = [(0,0x56,3),(5,0x07,7),(12,0x25,11),(3,0xe2,15),(8,0x4b,2),
         (1,0xda,6),(15,0x42,10),(7,0xa6,14),(4,0xdc,1),(11,0x2e,5),
         (18,0xff,9),(2,0xd6,13),(9,0xdc,0),(14,0xae,4),(6,0x05,8),
         (13,0x65,12),(16,0xc1,1),(10,0x2e,5),(19,0xa8,9),(17,0xda,13)]

inp = ['?'] * 20
for pos, c, j in gates:
    inp[pos] = chr(hb[j] ^ c)          # input[k] = hash_bytes[j] ^ CONST

print("".join(inp))                    # b89f-f302-dd51-205f1
```

The solver inside the deliverable parses the 20 gates **from Chall.sh itself**
rather than hardcoding them, and re-verifies every `ord(input[k]) ^ CONST ==
hash_bytes[J]` line.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Fixed, public key schedule | `md5("0.0.0.0")` | no secret input, no anti-automation |
| Digest only 16 bytes | `hash_bytes[0..15]` | every gate target is recoverable |
| One gate per character | `input:0:1` … `input:19:1` | each char independently solvable |
| No cross-dependency | count only, no coupling | solving 1 char doesn't depend on others |
| Counter wiring 5×4 | `version[V]` lines | confirms every gate must pass (no slack) |
| XOR with a known byte | `char_val ^ 0x..` | trivially invertible |
| No execution, no system calls | pure text | `bash Chall.sh` not even required |

"Reading bash" is the whole challenge: the "protection" is 20 nearly identical
lines a human must skim.

---

## Takeaways

- **Read, don't run.** A script keygen is often simpler statically: extract the
  schedule and the per-character transforms, invert each one.
- **`version ++ counter pattern` reveals slack.** When success requires `N`
  and exactly `N` increments are possible, every check *must* pass — no search
  space, no optional paths.
- **Known-format injection works on keys too.** Because `FlagY{$1}` is printed on
  success, `$1` *is* the flag; the 23 `X` padding is just a safety buffer for
  the `input[i]` indexing.
- **Watch mangled quoting in shipped files.** Stray/stripped backticks (` `` `!)
  change semantics but not intent; reconstruct the math, then verify against the
  raw gates.

---

## The solver

Colored CLI solver in the same folder, **pure Python (stdlib only)**:

```
b4sh33_solve.py
```

```bash
python b4sh33_solve.py            # reads Chall.sh next to it
python b4sh33_solve.py <path-to-sh>
```

It parses Chall.sh, recovers the 20 gate triples, computes `md5("0.0.0.0")`,
derives the 20 characters, **simulates the bash counters** (must reach
5,5,5,5), cross-checks every constraint, then prints the flag box and saves
`flag_from_b4sh33.txt`:

```
FlagY{b89f-f302-dd51-205f1}        🏁
```