# FlagYard CTF — Hasher

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Medium (متوسط)

---

## The flag

```
FlagY{8a5f4a15f97242c3b8d8a5fa45798aab}
```

---

## The short version

`Hasher.exe` reads a flag with `scanf("%255s", ...)` and first requires **exactly 39 characters** (`cmp rax, 0x27` → otherwise *"Wrong length!"*). Then it loops over each character, hashes **each byte on its own** as a 1-byte NUL-terminated string with the **Bob Jenkins "one-at-a-time" hash** (seed 0), and compares the 32-bit result to one entry of a **39-dword table baked as immediate constants** inside `main()`.

Because every byte is hashed in *isolation*, `hash(byte)` is a pure function of that byte — a 256-entry lookup table turns the whole check into a byte-by-byte decode:

```python
for c in range(256):
    lut[jenkins(c)] = c
flag = "".join(lut[t] for t in table_39_dwords)
```

One of the two commands (`"Wrong flag!"` / `"Correct flag!"`) is never reached — we simply read the expected hashes straight out of the instruction stream.

---

## First look

A single 12,800-byte x64 PE, no challenge files besides the exe:

```
Hasher.exe   12800 bytes  Windows PE (AMD64, MSVC Release)
```

`strings` gives the whole layout of `main`:

```
Enter the flag:
%255s                    <- scanf max width 255
Wrong length!            <- strnlen result != 39
Wrong flag!              <- any slot mismatch
Correct flag!
```

The PDB path leak confirms the origin: `...\Reverse\Medium\Hasher\x64\Release\Hasher.pdb`.

---

## Reversing the checker

Clean the entry stub in any disassembler and `main` is tiny:

```
1. memset(buf, 0, 0x100)
2. printf("Enter the flag: ")
3. scanf("%255s", buf)
4. len = strlen(buf)              ; inline scan-to-NUL loop
5. if len != 0x27 → "Wrong length!", exit
6. for (rbx = 0; rbx < 0x27; rbx++):
       tmp[0] = buf[rbx]          ; 1-byte string
       tmp[1] = 0
       n = strnlen(tmp, 0x100)    ; always 1
       h = hash_one_byte(tmp, n)  ; Bob Jenkins one-at-a-time, seed 0
       if h != table[rbx] → "Wrong flag!"
7. → "Correct flag!"
```

The loop decrements/compares with `rbx` against `0x27`, and the per-slot compare is exactly:

```asm
cmp  ecx, dword ptr [rsp + rbx*4 + 0x20]   ; hash vs table[rbx]
jne  wrong
inc  rbx
cmp  rbx, 0x27
jb   loop
```

### The hash — Bob Jenkins "one-at-a-time"

The hash body is the classic Jenkins mix, visible in the disassembly:

```asm
add  eax, byte            ; a += c                       (seed a = 0)
xor  eax, eax<<10         ; a ^= a << 10
add  eax, eax>>1          ; a += a >> 1
xor  eax, eax<<3          ; a ^= a << 3
add  eax, eax>>5          ; a += a >> 5
xor  eax, eax<<4          ; a ^= a << 4
add  eax, eax>>17         ; a += a >> 17
xor  eax, eax<<25         ; a ^= a << 25
add  eax, eax>>6          ; a += a >> 6                  (32-bit wraps)
```

The disassembler emits a 4-bytes-at-a-time word loop of the same hash; for a 1-byte input `len >> 2 == 0`, so only the `len & 3 == 1` tail runs — which is exactly the mix above.

```python
def jenkins(byte):
    a = byte
    a = (a ^ ((a << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 1)) & 0xFFFFFFFF
    a = (a ^ ((a << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 5)) & 0xFFFFFFFF
    a = (a ^ ((a << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 17)) & 0xFFFFFFFF
    a = (a ^ ((a << 25) & 0xFFFFFFFF)) & 0xFFFFFFFF
    a = (a + (a >> 6)) & 0xFFFFFFFF
    return a
```

Sanity check before doing anything else — `jenkins(ord('F'))` must equal the first table entry:

```
jenkins(0x46) = 0xb99d68d8  == table[0]   ✓
```

### The table — 39 dwords in the instruction stream

The expected hashes are **not** stored in `.rdata`; they are written into the stack frame by a burst of `mov dword ptr [..], imm32` instructions:

```asm
mov dword ptr [rsp + 0x20], 0xb99d68d8   ; slot 0  -  'F'
mov dword ptr [rsp + 0x24], 0x4ea585c0   ; slot 1  -  'l'
...
mov dword ptr [rbp - 0x48], 0x303097c9   ; slot 38 -  '}'
```

24 entries at `[rsp+0x20 .. rsp+0x7c]` followed by 15 entries at `[rbp-0x80 .. rbp-0x48]`, back-to-back on the stack → a contiguous 39-dword table. They can be scraped directly from the `.text` bytes (no disassembler needed):

- `C7 44 24 <disp8> <imm32>` → `mov dword ptr [rsp+disp8], imm`
- `C7 45 <disp8> <imm32>` → `mov dword ptr [rbp+disp8], imm`

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Hash fed **one byte at a time** | the per-char loop | result depends only on that byte → 256-entry LUT kills it |
| No chaining, no salt | hashing design | no avalanche across characters, slots are independent |
| Mix keys/expected values baked as **immediate constants** | `main()` | table is recovered by static reading only |

The Jenkins one-at-a-time hash is *strong only when it chains many bytes together*. The moment you hash a single byte with a fixed seed, every possible input maps into one of 256 values — it's a substitution box, not a hash.

---

## Takeaways

- **Recognize the pattern by its opcodes.** `^<<10, +>>1, ^<<3, +>>5, ^<<4, +>>17, ^<<25, +>>6` (32-bit) is the Jenkins "one-at-a-time" signature. Naming it makes the whole approach obvious.
- **"Hash one byte" is a code smell.** A per-character hash with a shared constant seed is invertible via a 256-byte lookup. Length-check + slot-compare loops practically advertise it.
- **Baked constants are the easiest target.** The "expected hashes" live in the instruction stream as `mov dword ptr [..], imm32`; parse those bytes and you have the oracle without running anything.
- **Self-consistency verification:** in the table above, repeated hashes like `0x93642e87` and `0x45e26648` recur (e.g. slots for `a`), which doubles as a confirmation that the extraction order is correct.

---

## The solver

Colored, dependency-free edition in the same folder:

```
hasher_solve.py
```

It needs **no disassembler and no DLLs** — it parses the PE headers itself, scrapes the 39 dwords from `.text`, verifies the exact count, builds the LUT, and decodes all 39 slots unambiguously:

```bash
python hasher_solve.py        # reads Hasher.exe next to it
```

It renders a live progress bar over the 39 slots, prints the flag, and saves `flag_from_hasher.txt`. Run completes in a fraction of a second.

```
FlagY{8a5f4a15f97242c3b8d8a5fa45798aab}   🏁
```