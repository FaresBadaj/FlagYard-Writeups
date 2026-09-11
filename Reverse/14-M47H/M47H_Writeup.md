# FlagYard CTF — M47H

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Easy
- **Target:** `M47H.exe` — a Rust (cargo) x64 Windows console binary.

> *"They say that c/c++ plus is old so it was the time to move to something
> new, But is it easier to reverse?"*

---

## The flag

```
FlagY{685fdf10231cc1013ca0d19f66a56865}
```

---

## The short version

`M47H.exe` reads one line from stdin, requires exactly **39 characters**, and
checks each byte with a simple modular equation:

```python
for i in range(39):
    (input[i] * 52) % 123 == target[i]
```

`gcd(52, 123) == 1`, so the transformation is invertible: multiply each target
byte by the modular inverse of 52 mod 123, then pick the printable character
in that residue class. All 39 positions land uniquely in `0x20..0x7e` and
spell out the flag. Piping the recovered value into the exe prints
`Correct flag`.

---

## Step-by-step

### 1. Triage

`file`-style check: it's a Windows PE (`MZ`), with `.pdata` + `.reloc`
sections and the standard Rust runtime error table (`RtlExitUserProcess`,
`DiskQuota`, `Utf8*` entries) — a Rust `std` console app.

`strings` shows the interesting bits right away:

```
2fSf2hEnter the flag:
Error: Failed to read input.
Error: Input length must be exactly 39 characters, but got {} characters.
Wrong flag
Correct flag
00010203...979899
```

So: 39-char input, then some check.

### 2. Find the verification loop

The binary is small (13 KB, ~1009 instructions). The interesting code is at
`0x40130f`:

```asm
0x40130f  cmp   rsi, 0x28          ; length fixed-point check
0x401315  mov   r8w, 0x7b          ; divisor = 123
0x40131a  lea   r9, [rip+0xcff]     ; -> target table @ 0x402020
0x401321  xor   r10d, r10d
0x401324  cmp   r10, 0x27          ; loop for 39 (0x27) bytes
0x40132e  movzx eax, byte ptr [rcx + r10]   ; input[i]
0x401333  imul  eax, eax, 0x34              ; input[i] * 52
0x401336  xor   edx, edx
0x401338  div   r8w                         ; / 123 -> remainder in dx
0x40133c  movzx eax, byte ptr [r10 + r9]    ; target[i]
0x401344  cmp   dx, ax
0x401347  je    0x401324                    ; continue on match
```

The math: `(input[i] * 52) % 123 == target[i]`.

### 3. Extract the target table

`lea r9, [rip+0xcff]` at `0x40131a` resolves to `0x402020` in `.rdata`
(next-rip = `0x401321` → `0x401321 + 0xcff = 0x402020`). The 39-byte table:

```
49 51 01 43 4d 00 66 53 32 0f 22 0f 58 24 11 45 58 69 69 58
24 58 45 69 01 24 22 58 0c 0f 66 66 01 32 66 53 66 32 68
```

Note the bytes `01 43 4d 00 66 53 ...` map under the inverse to `FlagY{...}`.

### 4. Invert the modular function

`52` has an inverse mod `123` because `gcd(52, 123) = 1`:

```
inverse ≡ 52^(-1) mod 123 = 97
```

Candidate for position `i` = `target[i] * 97 mod 123`. That gives a residue
class, and since `52 * c mod 123` cycles with period 123, each target byte
has exactly one **printable** solution in `0x20..0x7e`:

```python
inv = pow(52, -1, 123)          # 97
flag = ""
for t in target:
    cands = [c for c in range(0x20, 0x7f) if (c * 52) % 123 == t]
    flag += chr(cands[0])
```

Result:

```
FlagY{685fdf10231cc1013ca0d19f66a56865}
```

### 5. Verify

```
> echo FlagY{685fdf10231cc1013ca0d19f66a56865}| M47H.exe
Enter the flag:
Correct flag
```

> Note: like many Windows console Rust binaries, stdin is read as a
> CR-terminated line — feed the flag ending with `\r\n` (CRLF), and the
> exe reports `Correct flag`.

---

## Why it's solvable

| Factor | Why it made the challenge easy |
|---|---|
| Tiny binary (13 KB) | No packing, no obfuscation, ~1000 instructions |
| One tight check loop | `(c*52) % 123 == t` is a single point in the disassembly |
| `gcd(52, 123) == 1` | The transform has an exact modular inverse |
| 39 printable targets | Every residue class contains exactly one printable char |
| Plain `% 123` | No masking/seed/key needed — a straight residue class |

---

## Takeaways

- **Rust binaries still load the same way**: `.pdata`/`.reloc` + error tables
  are a reliable fingerprint before you even disassemble.
- **Spot the one arithmetic op.** A single `imul` + `div` inside a length-39
  loop is a cryptosystem you can invert with high-school number theory:
  `gcd` + modular inverse.
- When `*k % m` gives a residue, walk the **printable band** `0x20..0x7e` and
  pick the unique char — no brute-forcing needed.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)