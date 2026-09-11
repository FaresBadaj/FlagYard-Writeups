# FlagYard CTF — GuessyMan

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Easy (سهل)

---

## The flag

```
FlagY{a01b1ac2858ec221d87a015d9f85837f}
```

---

## The short version

`GuessyMan.exe` is a **Zig** number-guessing game ("Are you a real guesser?",
secret between 1 and 100). On a correct guess the program XORs a **39-byte
ciphertext** in `.rdata` with the secret number and prints `FLAG DECRYPTED:`.

The ciphertext is fixed and constant — only the secret differs per run. Since
the flag starts with the known prefix `FlagY{`, the XOR key falls out of the
first bytes:

```
ct[0]^'F' == ct[1]^'l' == ct[2]^'a' == 0x15
```

`0x15 = 21`. So `flag = ct[i] ^ 0x15`:

```python
ct = data[0x3c45 : 0x3c45 + 39]   # .rdata, rva 0x5045
flag = bytes(b ^ 0x15 for b in ct)  # == b"FlagY{a01b1ac2858ec221d87a015d9f85837f}"
```

---

## First look

- `GuessyMan.exe` — 36352 bytes, x64 PE32+, minimal Zig build, symbols
  **stripped** (`Unable to dump stack trace: debug info stripped`).
- Zig fingerprints are everywhere: `thread  panic: 1`, Zig error sets
  (`InputOutput`, `OutputStream`, `BrokenPipe`, `NotOpenForReading`, …) and the
  std `getrandom()` RNG path. There is a `expand 32-byte k` ChaCha stream
  constant in `.rdata` — that is only Zig's `std.crypto` hasher importing the
  ChaCha20 sigma string, a **red herring**, not the flag cipher.
- The game text is fully readable:

  ```
   Welcome to the Number Guessing CTF Challenge!
   I'm thinking of a number between 1 and 100.
   Guess correctly to decrypt the flag!
    FLAG DECRYPTED:
    Too low! Try higher.
    Too high! Try lower.
   ```

The interesting blob: a 39-byte buffer of dense bytes starting at
**file offset `0x3c45`** (== **rva `0x5045`** in `.rdata`):

```
5b 5f 5e 41 5c 41 5d 41 5e 41 5f 5d c3 55 41 56 56 57 53 48 83 ec 30 48 8d ...
```

It looks like random machine code — because it is not code: it is the
XOR-encrypted flag.

---

## Understanding the "decrypt"

The game loop reads guesses with `scanf`, reports `Too low/high`, and on a hit:

```zig
if (guess == secret) {
    print(" FLAG DECRYPTED:  ");
    for (ct) |b| print("{c}", .{b ^ secret});   // ct bytes XOR the secret
}
```

The secret is picked **randomly per run** via `getrandom()` →
`RtlGenRandom`/`SystemFunction036`. That randomness is cosmetic: the FLAG data
is static, so the cipher is simply

```
flag[i] = ct[i] ^ secret
```

which collapses to a one-byte XOR key over a fixed 39-byte plaintext.

---

## Recovering the key — known plaintext

We know the flag format `FlagY{` for every FlagYard challenge. XORing any pair
`ct[0]^'F'`, `ct[1]^'l'`, `ct[2]^'a'`:

```
5b ^ 0x46 = 0x15
5f ^ 0x6c = 0x15
5e ^ 0x61 = 0x15
```

Same constant → the key is `0x15` (decimal **21**). Done.

A full single-byte brute over 1..255 also finds it uniquely — no other
`(offset, key)` in all of `.rdata` turns a 39-byte window into
`FlagY{[0-9a-f]{32}}`.

---

## Solve

```python
data = open("GuessyMan.exe", "rb").read()
ct = data[0x3c45 : 0x3c45 + 39]          # rva 0x5045, .rdata
flag = bytes(b ^ 0x15 for b in ct).decode()
print(flag)
# FlagY{a01b1ac2858ec221d87a015d9f85837f}
```

No bruteforce, no emulation, no guessing.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Known flag prefix `FlagY{` | challenge-wide format | key recovered from 3 bytes of plaintext |
| Single 39-byte static buffer | `.rdata` rva 0x5045 | the whole secret is one tiny blob |
| Trivial cipher (single-byte XOR) | decrypt loop | any 1..255 probe decrypts it |
| Secrets only "look" random | `getrandom()` per run | has no effect on the static ciphertext |
| No integrity / anti-tamper | plain Zig single-thread game | nothing to bypass |
| Flag text decipherable directly | static analysis | the game's own loop proves the algorithm |

The "hard" part is just noticing that the byte blob is encrypted text, not
obfuscated code.

---

## Takeaways

- **Always start from a known plaintext.** CTF flag formats (`FlagY{`, `flag{`,
  `picoCTF{`, …) are a free ciphertext oracle for XOR/stream ciphers.
- **A random key that re-encrypts a fixed buffer is still a fixed cipher.**
  Here "random" only meant *which* guess decrypts it; the underlying XOR key is
  constant and recoverable statically.
- **Check the runtime's std library signatures.** `expand 32-byte k` is the
  ChaCha20 sigma constant and appears in Zig/secret libraries routinely — do not
  chase it as the challenge cipher.
- **Differentiate *code-looking* random bytes from data.** A dense opaque buffer
  in `.rdata` decoded by a byte-at-a-time loop is usually an XORed flag.
- **Prove uniqueness.** A solver that brute-checks *all* keys and *all* offsets
  converts "the answer looks right" into "the answer is the only one".

---

## The solver

Colored CLI solver in the same folder, **pure Python (stdlib only)**:

```
guessyman_solve.py
```

```bash
python guessyman_solve.py            # reads GuessyMan.exe next to it
python guessyman_solve.py <path-to-exe>
```

It parses the PE, relocates the ciphertext into `.rdata`, recovers the key from
the `FlagY{` prefix, decrypts, re-encrypts (round-trip) and proves `0x15` is
the **unique** `(offset, key)` that yields a 32-hex `FlagY{}` across all of
`.rdata`, then prints the flag box and saves `flag_from_guessyman.txt`:

```
FlagY{a01b1ac2858ec221d87a015d9f85837f}   🏁
```