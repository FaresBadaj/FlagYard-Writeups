# FlagYard CTF — Power of Statistics

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard CTF
- **Author:** blackfish
- **Category:** Hardware / Reversing
- **Difficulty:** Hard (صعب)
- **Target:** `crypto_firmware.elf` — a ChipWhisperer CW308_STM32F3 custom crypto firmware, shipped with
  1000 `(plaintext, power-trace)` pairs and a 16-byte `encrypted_flag`.

---

## The flag

```
FlagY{P0w3rL3aK}
```

---

## The short version

The "device" is a fake AES-box firmware that encrypts plaintexts with a
**hand-made 8-round block cipher**. The core of every round is a lookup

```
t[i] = sbox[ key[i] ^ pt[i] ]        for i = 0..15
```

(same custom 256-byte S-box every round, no key schedule), followed by a
byte rotation on the first half and a XOR diffusion across the two halves:

```
new[0..7]  = t[7], t[0], t[1], ... t[6]     (rotate t by one byte)
new[8+i]   = t[i] ^ t[8+i]                   (mix the halves)
```

Because the S-box lookup is the **only** sensitive computation and it is
surrounded by the power trigger, every trace leaks the Hamming weight of
`sbox[key[i] ^ pt[i]]`. A byte-by-byte **Correlation Power Analysis (CPA)**
with that model recovers all 16 key bytes:

```
key = 56a7590123c89e457066442a88ddff01
```

With the key in hand the 8-round transform is inverted the same way (inverse
S-box, un-rotate, undo the XOR mix — 8 iterations) and `encrypted_flag`
decrypts to the flag. A re-encryption round-trip proves the whole pipeline.

> The firmware legitimately contains a dummy key (`FlagY{DummyFlag}` in
> `.data@0x20000100`) — the real key is only in the power traces.

---

## First look

- `crypto_firmware.elf` — ARMv7-M (EM_ARM), Thumb, ChipWhisperer CW308 target.
- `plaintext.npy` — `(1000, 16)` uint8 known plaintexts.
- `traces.npy` / `traces_aligned.npy` — `(1000, 1500)` float64 power traces.
- `encrypted_flag` — single 16-byte ciphertext block (`e3c8f9f72f224fc7bc8cf76c90fceb7e`).
- Conclusion: this is a classic **side-channel power-analysis** challenge, not
  a crypto-textbook one.

---

## Firmware analysis (Thumb disassembly)

`get_pt()` lives at `0x0800025c` (Thumb mode). The relevant body is an
8-round loop that reads one key byte per S-box input from a table base `r3`
= `0x20000000`:

```asm
0x08000268  movs    r5, #8                  ; 8 rounds
0x0800026a  ldrb.w  r2, [r3, #0x100]        ; key[0]
0x0800026e  ldrb    r1, [r4]                ; pt[0]
0x08000274  eors    r2, r1                  ; idx = key[0]^pt[0]
0x08000278  ldrb.w  r8, [r3, r2]            ; t0 = sbox[key[0]^pt[0]]
...                                           ; ... t1..t15 same pattern ...
0x080002c6  strb    r2, [r4]                ; new[0] = t7
0x080002c8  strb.w  r8, [r4, #1]            ; new[1] = t0
...                                           ; rotate first 8 bytes ...
0x080002c8  ... 0x080002da                  ;  + XOR mix into bytes 8..15
0x08000384  bne.w   0x800026a               ; loop 8 times
```

Two things worth noting:

- The S-box is **not** the AES one — it is a custom 256-byte table in `.data`
  at `0x20000000` (the 16-byte key the firmware uses at `0x20000100` is a
  **dummy**: `466c..` = `"FlagY{DummyFlag}"`).
- The trigger wraps the whole 8-round block, so the traces are clean and the
  S-box leak per byte is consistently aligned (`traces_aligned.npy`).

---

## The power model

The switch of `sbox[key[i] ^ pt[i]]` dominates the dynamic power. For a
CMOS device the leakage is proportional to the **Hamming weight** of the
byte that changes — here the S-box output value. For each key byte `i` and
each guess `k ∈ 0..255` we build the hypothetical intermediate

```
V[tr, k] = HW( sbox[ plaintext[tr, i] ^ k ] )
```

and correlate it with every sample of the power trace. The correct `k`
maximizes the Pearson correlation (up to a sign flip), recovering one key
byte at a time:

```
                sum (T - T̄)·(V - V̄)
corr(k)  =  --------------------------------
                σ(T) · σ(V) · sqrt(N)
```

All 16 bytes come out with clean correlation peaks (`0.34 – 0.73`):

```
byte  0: key=0x56  corr=0.355
byte  1: key=0xa7  corr=0.384
byte  2: key=0x59  corr=0.609
...
byte 15: key=0x01  corr=0.547
```

---

## Solve

```python
import numpy as np

def hw(vals):                     # population count
    out = np.zeros(vals.shape, np.float64); v = vals.astype(np.uint32)
    while v.any(): out += (v & 1).astype(np.float64); v >>= 1
    return out

def recover_key(traces, plain, sbox):
    # traces (1000,1500), plain (1000,16), sbox (256,)
    Tm   = traces - traces.mean(0, keepdims=True)
    Ts   = traces.std(0); Ts[Ts < 1e-9] = 1e-9
    key  = bytearray(16)
    for i in range(16):
        idx = plain[:, i, None] ^ np.arange(256, dtype=np.uint8)[None, :]   # (N,256)
        H   = hw(np.take(sbox, idx))                                       # HW model
        Hm  = H - H.mean(0, keepdims=True); Hs = H.std(0); Hs[Hs < 1e-9] = 1e-9
        corr = (Tm.T @ Hm) / (Ts[:, None] * Hs[None, :] * len(traces))     # (S,256)
        key[i] = np.abs(corr).max(0).argmax()                              # best guess
    return bytes(key)

# invert the 8-round cipher: inverse sbox, un-rotate, un-mix
def build_inv(sbox):
    inv = np.zeros(256, np.uint8); inv[sbox.astype(int)] = np.arange(256, np.uint8)
    return inv

def decrypt(ct, key, sbox, sinv):
    st = bytes(ct)
    for _ in range(8):
        t = [0]*16
        for i in range(8): t[i]    = st[(i+1) % 8]      # undo new[0..7]=rotate(t)
        for i in range(8): t[8+i]  = st[8+i] ^ t[i]     # undo new[8+i]=t[i]^t[8+i]
        st = bytes(int(sinv[t[i]]) ^ key[i] for i in range(16))  # undo sbox+key
    return st

key  = bytes.fromhex("56a7590123c89e457066442a88ddff01")
flag = decrypt(open("encrypted_flag","rb").read(), key, sbox)
print(flag)   # b'FlagY{P0w3rL3aK}'
```

The solver in this folder runs the full pipeline and verifies the key with a
round-trip: `enc(dec(ct), key) == ct`.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| S-box lookup leaks HW | `get_pt()` per round | one correlation equation per trace per key byte |
| Key fully in RAM, used every round | firmware `.data` | no masking, no blinding, no key schedule to crack |
| 1000 clean aligned traces | challenge files | enough to average out noise, `corr ≥ 0.34` peak |
| Single fixed key for flag block | `encrypted_flag` | recovered key decrypts directly |
| Dummy key in firmware | `.data@0x20000100` | red-herring; the *traces* hold the secret |

Custom cipher + custom S-box still lose to physics: any key-dependent lookup
in a loop with a power trigger is a CPA target no matter how "custom" the
math is.

---

## Takeaways

- **Side-channel > brute force.** With a millionth the effort of attacking
  the cipher mathematically, the HW model walks the key out byte by byte.
- **Locate the sensitive operation.** Reversing `get_pt()` first (Thumb
  disassembly) told us exactly *what* to model: the S-box output.
- **Rotate-and-XOR ciphers still leak the byte before the mix.** The first
  half is just the S-box outputs rotated — recover `t[0..7]`, recover 8 key
  bytes; the `t[i]^t[8+i]` mix recovers the other 8.
- **A dummy key in firmware is a red herring.** The real key lives only in
  the power traces; don't trust embedded strings on a side-channel target.
- **Proof with a round-trip.** Re-encrypting the decrypted block and matching
  `encrypted_flag` confirms the key is actually right.

```bash
python power_of_statistics_solve.py
# ... 16 key bytes recovered, round-trip proven ...
# FlagY{P0w3rL3aK}   🏁
```

---

## The solver

Colored CLI solver in the same folder, **Python 3 + numpy only** (stdlib ELF
section parsing, no pyelftools/capstone needed):

```
power_of_statistics_solve.py
```

```bash
python power_of_statistics_solve.py
```

It links the challenge files next to it (`crypto_firmware.elf`,
`plaintext.npy`, `encrypted_flag` + traces), parses the custom S-box out of
`.data@0x20000000` with a tiny stdlib section-table reader, recovers the
16-byte key with byte-wise CPA, inverts the 8-round cipher, proves the key by
re-encrypting `encrypted_flag`, and saves

```
flag_from_power_of_statistics.txt
```

```
FlagY{P0w3rL3aK}   🏁
```