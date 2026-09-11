# FlagYard CTF — SlowScript

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Easy
- **Target:** `challenge.py` — a 50-layer self-unpacking Python packer whose
  innermost code is deliberately slow.

---

## The flag

```
FlagY{6233fb2f5573ade1d34aba3e6076017d}
```

---

## The short version

`challenge.py` is one line of **nested packing**. Each layer is identical:

```python
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))
exec((_)(b'...'))
```

So every layer: takes the base64 blob, **reverses** it, `base64`-decodes,
`zlib`-decompresses, and `exec`s the result — which is the next layer. One
line of source hides a whole cake of 50 layers.

After unwrapping all of them, the real program is tiny:

```python
enc_flag=[71,209,120,114,232,150,255,119,82,46,31,23,35,43,28,144,246,78,
          184,177,20,156,237,54,21,188,91,84,226,104,223,85,182,11,169,164,6,9,52]
tmp=31337
for i in range(len(enc_flag)):
    fn=tmp**i                 # 31337**i  -> astronomically large
    sm=0
    for j in range(fn+1):     # <-- the "too slow" part: O(fn) iterations
        sm+=j
    print(chr((sm%256) ^ enc_flag[i]), end='')
```

For index `i` the inner loop runs `31337**i + 1` times — index 2 alone is
~981 *million* iterations, index 3 is ~3×10¹³. That's why it's "too slow".
But the loop just computes the triangular number `0+1+2+...+fn`, which has a
closed form:

```
sm = fn*(fn+1)//2
```

With that O(1) replacement the whole flag decrypts instantly:

```
FlagY{6233fb2f5573ade1d34aba3e6076017d}
```

---

## Step-by-step

### 1. Unpack the 50 layers

Extract `exec((_)(b'<b64>'))`, reverse the blob, base64-decode, zlib-decompress
and repeat. The definition of `_` does all of that in one lambda, so we just
recursively apply the same transformation:

```python
m = re.search(r"exec\(\(_\)\(b'([^']*)'\)\)", src)
raw = m.group(1)[::-1]
src = zlib.decompress(base64.b64decode(raw)).decode()
```

Each pass shrinks the code by ~5% (4230 → 418 → 351 chars) until no more
`exec((_)(b'...'))` remains — 50 full layers, then the final payload.

### 2. The inner "slow" decryption

```python
fn = tmp**i                  # 31337^i
for j in range(fn+1):
    sm += j                  # sum of 0..fn
```

`sum_{j=0}^{fn} j = fn*(fn+1)//2`. That single expression is the whole
optimization. `fn = 31337**i` is only ~170 digits at `i=38`, so Python
big-int arithmetic finishes instantly — no modular shortcut (like reducing
mod 512) is even needed.

### 3. Decrypt

```python
for i in range(len(enc_flag)):
    fn = 31337 ** i
    sm = fn * (fn + 1) // 2
    print(chr((sm % 256) ^ enc_flag[i]), end='')
```

Result:

```
FlagY{6233fb2f5573ade1d34aba3e6076017d}
```

### 4. Runtime confirmation

```
C:\> type flag_from_slowscript.txt
FlagY{6233fb2f5573ade1d34aba3e6076017d}
```

The payload `6233fb2f5573ade1d34aba3e6076017d` is 32 clean hex chars.

---

## Tools

- Pure-Python recursive unpacker for the 50-layer `reverse(b64)+zlib+exec`
  packer
- `re` extraction of the nested `exec((_)(b'...'))` payloads
- Triangular-number closed form `fn*(fn+1)//2` to neutralize the O(fn) loop

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)