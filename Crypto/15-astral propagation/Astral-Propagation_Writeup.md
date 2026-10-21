# FlagYard CTF — astral propagation

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** defund
- **Category:** Crypto
- **Difficulty:** Medium

> *"CBC mode is vulnerable to padding oracle attacks, but what about PCBC?"*

---

## The flag

```
FlagY{2f6170573b1a7f8c66a650e0f6314587}
```

---

## The short version

A remote AES **PCBC** oracle (`tcp.flagyard.com:31145`) decrypts any
ciphertext we send and tells us one of three things: *failed to decrypt*
(bad padding), *incorrect message* (valid padding, not the target), or the
**flag** (valid padding **and** equal to `MESSAGE`). We never learn the key,
yet we forge a ciphertext that decrypts to `MESSAGE` — and the server hands
us the flag:

1. **Turn the padding oracle into an AES-decryption oracle.** A
   *single-block* PCBC message behaves exactly like CBC: `P = D(C) XOR IV`.
   The classic byte-by-byte CBC padding oracle recovers `D(C)` for any block
   `C` we choose — so we can compute `D(C)` on demand.
2. **Walk PCBC backwards.** For target blocks `t1, t2, t3 =
   pad("propagating cipher block chaining")`, the equations
   `P_i = D(C_i) XOR C_{i-1} XOR P_{i-1}` are inverted block by block; each
   step uses one recovered `D` to set the previous ciphertext block.

   ```
   C3  = 0x00..00            (free choice)
   C2  = D(C3) XOR t2 XOR t3
   C1  = D(C2) XOR t1 XOR t2
   IV  = D(C1) XOR t1
   ```

   Sending `IV || C1 || C2 || C3` decrypts to exactly `MESSAGE`.

---

## The challenge box

```python
MESSAGE = b'propagating cipher block chaining'

class Pcbc:
    def encrypt(self, buf):
        buf = pad(buf, 16)
        iv = get_random_bytes(16)
        out = iv
        for i in range(0, len(buf), 16):
            p  = buf[i:i+16]
            c  = self.cipher.encrypt(strxor(iv, p))
            iv = strxor(p, c)          # PCBC: iv is chained with plaintext, not just ciphertext
            out += c
        return out

    def decrypt(self, buf):
        iv = buf[:16]
        out = bytes()
        for i in range(16, len(buf), 16):
            c = buf[i:i+16]
            p = strxor(iv, self.cipher.decrypt(c))
            iv = strxor(p, c)
            out += p
        out = unpad(out, 16)           # PKCS#7 -> crash = oracle bit
        return out
```

Server loop: hex ciphertext in → either `failed to decrypt`, `incorrect
message`, or the flag if the recovered message equals `MESSAGE`. That plain
`try/except` around `unpad` **is** a padding oracle.

---

## Step 1 — recover D(C) for chosen blocks

The decrypt loop for a message consisting of just `IV || C` computes

```
P = D(C) XOR IV
```

exactly like CBC, and then pads-checks `P`. Standard single-block padding
oracle: to learn byte `i` of `D(C)` guess `IV[i] = g` while the bytes after
`i` are fixed so their plaintext (already known) equals `16 - i`; the `g`
that yields a valid `unpad` satisfies `D(C)[i] = g XOR (16 - i)`.

```
block 3: D(C3) = 9a032f6a2466d63fe8f32c94b8235906
block 2: D(C2) = 62ff6fbf9e5b5fef02c1179a3f2f2328
block 1: D(C1) = 5b0dfebb22a0ecb03782819162503949
```

Per-byte the search is over `0..255`, so a naive `send → recv` per guess
means thousands of network round-trips. **Pipeline it**: send all 256 `IV`
variants for a byte in one payload, read the 256 answers back in bulk — 16
pipelined trips per block, ~36 s on the remote.

## Step 2 — forge a ciphertext that decrypts to MESSAGE

PCBC decryption (`C_0 = IV`, `P_0 = IV`):

```
P_1 = D(C_1) XOR C_0 XOR P_0 = D(C_1) XOR IV
P_2 = D(C_2) XOR c_1 XOR P_1
P_3 = D(C_3) XOR C_2 XOR P_2
```

We know the plaintext we *want* (`T = pad(MESSAGE)`), so solve backwards:

```
P_3 = t3  =>  D(C3) XOR C2 XOR P2 = t3  =>  C2 = D(C3) XOR t2 XOR t3
P_2 = t2  =>  C1 = D(C2) XOR t1 XOR t2
P_1 = t1  =>  IV = D(C1) XOR t1
```

`C3` is free (chosen `0x00 * 16`). Every right-hand side is known:

```
IV  = 2b7f91cb43c78dc45eece6b101394921
C1  = 77ff20ad93535df04bcc18db35283a2e
C2  = 987e00074706ba5bc79f4bfade423f67
C3  = 00000000000000000000000000000000
```

Submitting that yields exactly `P_1||P_2||P_3 = T` → `unpad` → `MESSAGE` →
flag.

---

## Result

```
★  FLAG RECOVERED  ★
FlagY{2f6170573b1a7f8c66a650e0f6314587}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| `unpad` errors caught and echoed ("failed to decrypt") | server loop | a classic PKCS#7 padding oracle |
| PCBC used as a plain decrypt oracle with no authentication | server loop | malleability → forge any plaintext once `D` is recoverable |
| Fixing `MESSAGE` as an equality target | server loop | lets the attacker aim the forgery precisely and get the flag |
| Single-block PCBC reduces to CBC | `decrypt` | standard CBC byte-recovery oracle applies unchanged |

---

## Takeaways

- **Security ≠ mode of operation.** PCBC still leaks a padding bit per
  query; authenticated encryption (GCM/ChaCha20-Poly1305) with MAC-verify-
  before-decrypt is the fix.
- **Malleable encryption can be inverted without the key.** Given a
  decryption oracle for one block, backward chaining forges ciphertexts for
  any chosen plaintext — CCA security requires non-malleability, not just an
  oracle inside.
- **Pipeline your oracle.** Sequential 256-guess loops over a socket cost
  thousands of RTTs; batching all guesses per byte cut the attack from
  `>5 min` to `36 s`.

---

## The solver

`solve_astral.py` — connects to `tcp.flagyard.com:31145`, recovers
`D(C_3)`, `D(C_2)`, `D(C_1)` with a pipelined single-block padding oracle,
builds `IV || C1 || C2 || C3` and prints the flag:

```
python solve_astral.py tcp.flagyard.com:31145
★  FLAG RECOVERED  ★
FlagY{2f6170573b1a7f8c66a650e0f6314587}
```

It saves the flag to `flag_from_astral_propagation.txt`.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3) + challenge author **defund**.