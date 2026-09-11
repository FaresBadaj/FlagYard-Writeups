# FlagYard CTF — Cryp70

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Medium (متوسط)

> *"Maybe some reverse engineering skills and a little bit crypto would be good for you."*

---

## The short version

A Windows PE encrypts a 48-byte flag with **Serpent-256 in ECB mode**, using a key produced by **MSVCRT `rand()`**. The tiny catch? The RNG seed is **derived from the plaintext itself**. Since a printable ASCII flag can only produce a small range of seeds (`0..12240`), we just:

1. Reverse the binary to recover the *key schedule* and the *seed formula*.
2. **Brute-force every possible seed**, decrypt the ciphertext, and keep the plaintext that *re-derives its own seed*.
3. One of them is the flag.

**Flag:** `FlagY{c7fffe64a77d65408803598472c1c654e17ff5db8}`

---

## First look

Two files are given:

```
Cryp70.exe     57 KB  Windows PE (AMD64)
enc_flag.txt   48 bytes of ciphertext
```

Running the exe just produces `enc_flag.txt`. So the work is **reversing**: figure out exactly *how* it encrypted, then undo it with Python.

### Strings — the whole blueprint

`strings` already leaks half the story:

- Imports: **`srand`**, **`rand`**, `fwrite` … that's the MSVCRT C RNG.
- Embedded strings: **`Key Length Error`** and **`Given output char pointer not initialized/allocated.`**

Those two strings belong to **libgcrypt**, and they're *inside* the exe → **libgcrypt is statically linked**. So the cipher comes from the gcrypt API, and the RNG seed comes from the CRT.

---

## Reversing the key schedule (Ghidra/IDA)

Clean up the `main` in any decent disassembler and the flow is small and readable:

```
1. read "flag.txt"-sized plaintext (48 bytes)              
2. seed = sum( (signed_char)byte ^ 0xBB )   -> int32       
3. srand(seed)                                              
4. for i in 0..32:                                          
      r  = rand() & 0x7FFF                                   
      key[i] = (r % 256) ^ 0x9D                              
5. gcry_cipher_open(SERPENT256 = 306, mode ECB, 0)         
6. gcry_cipher_setkey(h, key, 32)                          
7. gcry_cipher_decrypt(h, enc, 48, plain, 48)              
8. fwrite(enc, 1, 48, "enc_flag.txt")                      
```

Every part of it is reproducible in Python:

```python
def generate_key(seed):                       # MSVCRT LCG
    state = seed & 0xFFFFFFFF
    for _ in range(32):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        r = (state >> 16) & 0x7FFF
        key.append((r % 256) ^ 0x9D)

def derive_seed(plaintext):                   # the binary's "seed" step
    total = sum((b - (256 if b >= 128 else 0)) ^ 0xBB for b in plaintext)
    return signed32(total)
```

---

## The crypto insight — why the key space is tiny

The key is `rand()`-derived, and `rand()` is seeded with `seed = f(plaintext)`.

Here's the beautiful part:

- The flag is **printable ASCII** → every byte is in `0x20..0x7E`.
- After the `^ 0xBB` step, each byte contributes a *small non-negative* value.
- So `seed` can only be in **`0 .. 48*255 = 12240`** — eleven thousand candidates. That's *nothing* to brute-force.

For each candidate seed:

1. Build the 32-byte key.
2. Try Serpent-256 **decryption** of the 48-byte ciphertext (single ECB block).
3. Accept it only if:
   - the result is **printable** and ends with `}`, **and**
   - `derive_seed(plaintext) == seed` — i.e. *the plaintext re-produces the very seed that made the key that decrypted it*.

That self-consistency check is what makes a false positive impossible: only the true seed yields a readable result that matches its own seed formula.

```python
for seed in range(48 * 255 + 1):
    key = generate_key(seed)
    gcry_cipher_setkey(h, key, 32)
    gcry_cipher_decrypt(h, out, 48, enc, 48)
    if derive_seed(out) == seed and is_printable_flag(out):
        print(seed, key.hex(), out.decode())
```

After a fraction of a second:

```
seed = 8344
key  = 0b9bd0bbdd72bdddea6291f7ec77990a7a4d2a0d93f881a454d2d08b80520592
flag = FlagY{c7fffe64a77d65408803598472c1c654e17ff5db8}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| `rand()` used for key material | key schedule | fully deterministic, predictable key |
| Seed derived **from the plaintext** | seed selection | seed space = tiny ASCII algebra |
| No entropy, no KDF, no randomness | key generation | key is a pure function of the flag itself |
| ECB mode | cipher mode | makes a pure single-block decryption trivial |

---

## Takeaways

- **The "little bit crypto" is the whole game here.** The cipher (Serpent-256) is *fine* — the bug is *how the key is made*, not the block cipher.
- **Whenever a key is seeded, ask: what feeds the seed?** If it's derived from the plaintext, the key space collapses to whatever range the plaintext can produce.
- **Self-consistency beats guessing.** A check like `f(decrypted) == seed` turns a 12k-way brute-force into a one-hit lock.
- **Static-linked libgcrypt strings are a gift** — "Key Length Error" tells you the exact API family before you even open a disassembler.
- MSVCRT `rand()` is just an LCG (`state*214013+2531011`) returning `(state>>16)&0x7FFF`. Reimplement in three lines, done.

---

## The solver

Styled, colored edition in the same folder:

```
cryp70_solver.py
serpent_py.py       # embedded pure-Python Serpent backend (verified vs libgcrypt)
```

Cross-platform, zero external dependencies — it picks the best backend available:

1. **libgcrypt** (Linux/WSL, fastest) — `sudo apt install libgcrypt20`
2. **PyCryptodome** (if Serpent is compiled in) — `pip install pycryptodome`
3. **bundled pure-Python Serpent** (`serpent_py.py`) — runs anywhere, including plain Windows Python

Run it (Windows included):

```bash
python cryp70_solver.py            # reads enc_flag.txt next to it
```

It shows a live progress bar over the 12,241 seeds, the recovered key, and the flag — plus it saves `flag_from_cryp70.txt` (~19 s on the pure-Python fallback).

*Maybe some reverse engineering skills and a little bit crypto would be good for you.* — they were. 🏁