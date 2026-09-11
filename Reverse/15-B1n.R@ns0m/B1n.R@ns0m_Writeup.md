# FlagYard CTF — B1n.R@ns0m

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Medium
- **Target:** `B1n.R@ans0m.exe` + `secretinfo.EX`

> *"Ransomwares are very dangerous, but is this one dangerous?"*

---

## The flag

```
FlagY{649ceac01c1beeaa36d1b6546b4e1a57}
```

---

## The short version

The "ransomware" reads `secretinfo.txt`, mangles every character into a
decimal number, and writes them joined by `??` into `secretinfo.EX`. Inside
the package there are 39 numbers and `secretinfo.EX` is exactly what a
ransom note would look like — encrypted data with no key in sight.

The "encryption" is nothing scary. Running the binary with controlled
plaintext reveals that character at position `i` is encoded as:

```
num_i = base(char) * (i + 1)
```

where `base(char)` is a **fixed per-character integer**. Since `i=0`
multiplies by `1`, the very first number of a run of identical characters is
the character's base directly. Feed the binary every printable character
(`0x20..0x7e`) and you build a perfect `base -> char` lookup table. Then each
ciphertext number decodes as:

```python
base = num // (i + 1)
char = table[base]
```

Re-encoding the recovered flag produces exactly the original `secretinfo.EX`
— a full round-trip proof.

---

## Step-by-step

### 1. Triage

`secretinfo.EX` is 254 bytes of decimal numbers separated by `??`. Parsed:

```python
[156, 2490, 381, 50268, 6735, 740802, 16492, 1880, 21123, ...]
```

`39` numbers — exactly the length of a FlagYard flag.

### 2. Black-box the encoder with controlled plaintext

Drop a file `secretinfo.txt` containing 39 copies of the character `A` in the
same directory as the exe and run it. `secretinfo.EX` turns into:

```
17??34??51??68??85??102??119??136??153??170??187??204??221??238??255??272??289??306??323??340??357??374??391??408??425??442??459??476??493??510??527??544??561??578??595??612??629??646??663??
```

These are exactly `17 * (i+1)` for `i = 0..38`. So:
- `base('A') = 17`
- `num_i = base(char) * (i + 1)`

### 3. Build the full table

Run the exe once per printable character `0x20..0x7e` (repeated ×39), read the
first number (position 0 → multiplier 1) and you get that char's base. All 95
printable chars map to **unique** bases, e.g.:

```
'F'  156      '0'  23
'l'  1245     '4'  235
'a'  127      '6'  2356
'g'  12567    '9'  2347
'Y'  1347     'c'  1267
'{'  123467   'e'  1257
'}'  123457   'b'  126
```

### 4. Decode

```python
inv = {b: ch for ch, b in table.items()}
flag = ""
for i, n in enumerate(nums):
    flag += inv[n // (i + 1)]
```

Result:

```
FlagY{649ceac01c1beeaa36d1b6546b4e1a57}
```

### 5. Round-trip proof

Encoding the flag with the same table:

```
num_i = table[flag[i]] * (i + 1)
```

reproduces `secretinfo.EX` **byte-for-byte** — the key is the whole scheme,
and the base table is the only secret, which the binary hand delivers.

---

## Why the "ransomware" is harmless

| Factor | Effect |
|---|---|
| No key, no IV, no block cipher | "Encryption" is arithmetic on each char independently |
| `num_i = base(char)·(i+1)` | Position only scales, never mixes |
| `i=0` leaks base directly | One oracle run per char = full alphabet table |
| Unique bases per char | Invertible lookup, zero ambiguity |
| Measured via controlled plaintext | No RE needed at all — pure black-box |

---

## Takeaways

- **Before you crack a cipher, ask if it's even a cipher.** Position-scaled
  arithmetic with a per-character table is a substitution cipher in disguise.
- **Controlled plaintext is your best friend.** When a binary packs a file,
  give it 39 `A`s and read what comes back — the layout of the scheme falls
  out immediately.
- A `base(char) * (i+1)` product looks "encrypted" until you notice position
  0 strips the scare factor to a plain lookup.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)