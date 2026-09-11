# FlagYard CTF — Shuffler

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Easy
- **Target:** `chall.py` (Python encryptor) + `flag.enc` (ciphertext)

---

## The flag

```
FlagY{bc22719f0816578efad8d19496531512}
```

---

## The short version

`chall.py` encrypts a 40-character plaintext with two steps:

1. **Per-index XOR** — byte `i` is XORed with the key `(i << 3)`:
   ```python
   encrypted += chr(ord(data[i]) ^ (i << 3))
   ```
2. **Block shuffle** — the XORed text is split into five 8-character blocks
   and `random.shuffle` permutes them before writing `flag.enc`.

There is also a **hidden-gem hint** inside the encryptor: when the first 39
characters MD5-hash to `ac9dc5b77c199d4737f5010da0fcdd24` it prints
`"You got a hidden gem"` — that hash is the integrity check we reuse to
pick the right permutation.

Decryption is therefore:
1. Read `flag.enc` as UTF-8 text (XOR with `(i<<3)` pushes ASCII above
   127, so it must be decoded as text, not read as bytes).
2. Split into the same 5 blocks of 8, and try the `5! = 120` possible
   block orders.
3. For each order, undo the XOR with the same key `(i << 3)`.
4. Keep the order that satisfies, simultaneously:
   - the plaintext ends with the appended `"A"` (length 40);
   - it looks like a flag: `FlagY{...}`;
   - `md5(plain[:39]) == ac9dc5b77c199d4737f5010da0fcdd24`.

Exactly **one** order survives: `(4, 3, 2, 0, 1)`, giving
`FlagY{bc22719f0816578efad8d19496531512}`.

---

## Step-by-step

### 1. The encryptor

```python
import random
import hashlib
encrypted=''
data=input('Hello enter the string you want to encrypt: \n')
data+="A"                                  # 40 chars if input was 39
if len(data)==40:
    if hashlib.md5(data[:39].encode()).hexdigest()=="ac9dc5b77c199d4737f5010da0fcdd24":
        print("You got a hidden gem")
    for i in range(40):
        encrypted+=chr(ord(data[i])^(i<<3))           # XOR, key = i<<3
    simp=[encrypted[i:i+8]for i in range(0,len(data),8)]  # 5 x 8 bytes
    random.shuffle(simp)                              # permutation of blocks
    with open('flag.enc','w', encoding="utf-8")as file:
        file.write(''.join(simp))
```

Two weaknesses:
- the **XOR key is trivially invertible** (`key = i << 3`, known for every
  index `i`), and
- the **shuffle only has 120 possibilities** (5 blocks of a 40-char string),
  so we can brute-force it.

### 2. Solve the XOR

`flag.enc` output for an ASCII plaintext produces code points above 127
(`ord('A') ^ (0<<3) = 65` stays ASCII for index 0, but later indexes reach
high values, e.g. `ord('}') ^ (39<<3)`). Reading the file as UTF-8 text
gives 40 code points:

```
[164, 240, 180, 233, 217, 220, 201, 206, 309, 315, 289, 301, 273, 282, 333,
 377, 177, 190, 165, 175, 152, 205, 214, 217, 114, 122, 103, 105, 89, 14,
 64, 64, 70, 100, 113, 127, 121, 83, 82, 91]
```

For a candidate block order we simply reverse the XOR:

```python
"".join(chr(ord(c) ^ (i << 3)) for i, c in enumerate(reassembled))
```

### 3. Find the right block order

Iterate `itertools.permutations(range(5))` (120 orders). For each, undo the
XOR and test the three constraints (trailing `"A"`, `FlagY{...}` shape,
MD5 hint). Only the permutation `(4, 3, 2, 0, 1)` matches all of them.

```
ciphertext block order recovered -> (4, 3, 2, 0, 1)
plaintext : FlagY{bc22719f0816578efad8d19496531512}A   (40 chars)
md5(...)  : ac9dc5b77c199d4737f5010da0fcdd24            (hint matches)
```

### 4. Runtime confirmation

```
C:\> type flag_from_shuffler.txt
FlagY{bc22719f0816578efad8d19496531512}
```

Verified: `md5("FlagY{bc22719f0816578efad8d19496531512}")` equals the hash
baked into `chall.py`.

---

## Tools

- Pure-Python analysis: `itertools.permutations` over the 120 block orders
- `hashlib.md5` against the embedded hint `ac9dc5b77c199d4737f5010da0fcdd24`
- UTF-8 text read of `flag.enc` (required, the XOR output is non-ASCII)

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)