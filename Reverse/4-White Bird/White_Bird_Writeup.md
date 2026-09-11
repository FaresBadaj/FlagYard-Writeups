# FlagYard CTF — White Bird

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
FlagY{9dd0a8062df77529e323905c5bbe7809}
```

---

## The short version

`White Bird.exe` is a **tiny** 11,776-byte stripped x64 console PE. There are no
strings in it — everything is encrypted with `XOR 0x44` in `.data`:

| offset (VA 0x14004…) | message |
|---|---|
| `0x39` (len `0x38`) | `Enter the flag:` |
| `0x51` (len `0x50`) | `Wrong Flag :(` |
| `0x61` (len `0x60`) | `Correct Flag :D` |

The check is a single tight loop at `0x1400012b1` against a **40-dword expected
table** baked directly into `.text` as forty inline
`mov dword ptr [rbp + 4*i - 0x79], imm32` writes (spiced with cosmetic junk
instructions that are pure dead code). The gate per flag byte:

```asm
loop:
movzx ecx, byte ptr [rbp + rax + 0x27]   ; flag[i]
xor   ecx, 0x811C9DC5                    ; FNV-1a offset basis
imul  edx, ecx, 0x1000193                ; FNV-1a prime
xor   edx, 0x13333337                    ; glue constant
cmp   edx, dword ptr [rbp + rax*4 - 0x79]; expected[i]
jne   wrong
inc   rax
cmp   rax, 0x28                          ; 40 iterations
jl    loop
```

So `flag[i]` must satisfy `((flag[i] ^ 0x811C9DC5) * 0x1000193) ^ 0x13333337
== expected[i]` for every `i`. Because `0x1000193` is odd, that x86 multiply
is **invertible modulo 2³²**, and the whole map is a bijection — invert it
exactly as the machine does, fetch the low byte, done. The 40th entry decodes
to `0x00` (the NUL terminator), so the flag is exactly **39 characters**:
`FlagY{` + 32 hex + `}`.

---

## First look

```
White Bird.exe   11776 bytes   Windows PE32+ (AMD64, MSVC Release, stripped)
```

- No packing, no custom sections — plain `.text` / `.rdata` / `.data`.
- `.rdata` holds a single format string: `%40s` (the input length limit).
- PDB path leak: `White Bird_FlagYard_Med`.
- Entry point `0x1400015f4`; the real code is small and straight-line.

Reversing is easy because there is nothing to deobfuscate: the "obfuscation"
is *data* — the expected answer lives in the code bytes as a plain table, and
the interleaved junk (`xorps xmm0,xmm0`, `mov r8d,1`, `cmp byte [rip+..],r8b`,
`setz al`) only touches dead registers.

---

## Reversing the checker

### `main` flow — `0x140001260`

```asm
xor   byte ptr [rcx], 0x44     ; decrypt "Enter the flag:" (XOR 0x44, len-prefixed)
lea   rdx, [rip+fmt]           ; "%40s"
lea   rcx, [rip+prompt]        ; "Enter the flag:"
call  printf
lea   rdx, [rbp+0x27]          ; flag buffer (40 bytes, zeroed)
lea   rcx, [rip+fmt]           ; "%40s"
call  scanf
...                            ; xorps xmm0,0 => zero the 0x60-byte reg region
```

### The inline table — `0x14000112e` … `0x14000124f`

Forty writes fill the stack region `rbp-0x79 .. rbp+0x23`:

```asm
mov  dword ptr [rbp - 0x79],  0xD038C60E
mov  dword ptr [rbp - 0x75],  0xFA3F023C
mov  dword ptr [rbp - 0x71],  0xF73F1A1B
...
mov  dword ptr [rbp + 0x23],  0x163F6E28
```

A nice tell: most imm32 values share the pattern `…3F…` in the high bytes —
constants produced from an ASCII input by the `* 0x1000193` mixing. Extracting
them is just byte-pattern matching (`c7 45 <disp8> <imm32>` with the valid
`-0x79 + 4*i` displacements).

### The gate loop — `0x1400012b1`

Exactly the loop shown in the short version: transform → compare → branch on
mismatch → iterate `[rbp+rax*4-0x79]`. If control reaches `cmp rax, 0x28; jl`
for all 40 entries the program prints `Correct Flag :D`.

---

## Inverting the per-char gate

The constants are literally FNV-1a's: offset basis `2166136261 = 0x811C9DC5`
and prime `16777619 = 0x1000193`, with a final `XOR 0x13333337` glued on. The
left side is a bijection of `Z/2³²`:

```python
INV = pow(0x1000193, -1, 1 << 32)   # FNV prime is odd -> invertible mod 2^32

chars = []
for i in sorted(TABLE):              # 40 dwords lifted from .text
    e = (TABLE[i] ^ 0x13333337) & 0xFFFFFFFF
    c = ((e * INV) & 0xFFFFFFFF) ^ 0x811C9DC5
    chars.append(c & 0xFF)

flag = bytes(chars[:-1]).decode()    # chars[-1] is the NUL terminator
```

Result:

```
FlagY{9dd0a8062df77529e323905c5bbe7809}
```

Exactly **39 bytes + NUL**, format `FlagY{` + 32 hex + `}` — matches the
40-iteration loop.

### Live verification

```
$ White Bird.exe   (feed the flag)
Enter the flag:
Correct Flag :D

$ White Bird.exe   (feed a wrong flag)
Enter the flag:
Wrong Flag :(
```

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Expected data is baked into the code has inline immediates, not computed | `0x14000112e`..`0x14000124f` | just extract the imm32s with a byte regex |
| Interleaved junk only touches dead state | `xorps`/`setz`/`mov r8d,1` filler | ignore it; the live instructions are contiguous |
| The gate is a **bijection**, not a lossy hash | `xor; imul; xor` at `0x1400012b1` | `inv(0x1000193) mod 2^32` inverts it exactly; no brute force, no search |
| One loop, clean indexing | `[rbp+rax+0x27]` vs `[rbp+rax*4-0x79]` | table ↔ position mapping is straightforward |
| Messages XOR 0x44 in `.data` | `0x140004038`.. | confirmation output readable after a one-byte XOR |

The challenge masquerades as "broken FNV-1a", but the mask never collapses to
a lossy reduction — the compiler just wrote flat immediates and a symmetric
affine transform, which is trivially inverted with modular arithmetic.

---

## Takeaways

- **Recognize baked-in constants**: dozens of `mov dword [rbp+disp8], imm32`
  writes to one region are almost always an expected-value table — collect them
  all before reading the comparison.
- **Check invertibility before brute-forcing.** Any mix of `xor` and an *odd*
  multiply on 32-bit x86 is a bijection; FNV-1a's own prime `0x1000193` is odd,
  so `pow(prime, -1, 2**32)` exists. A "hash" that is reversible is a lookup,
  not a hash.
- **Junk instructions ≠ obfuscation.** Here the filling instructions don't feed
  into anything live; strip by data-flow, disassemble what remains.
- **Leniency of `scanf("%40s")` + a NUL entry**: the 40th table value decoding
  to `0x00` quietly announces the flag length. Use it as a free constraint.
- **Sanity-check flag format**: `FlagY{` + 32 hex chars is the flag all
  FlagYard reversings of this style use; a mismatch would mean wrong index
  mapping.

---

## The solver

Colored CLI solver in the same folder, **pure Python (stdlib only)** — no
disassembler, no third-party packages:

```
white_bird_solve.py
```

```bash
python white_bird_solve.py          # reads White Bird.exe next to it
```

It parses the PE header, locates the gate loop by its exact byte signature,
regex-lifts the 40 table dwords, inverts the affine map, re-verifies the flag
by re-running the forward transform over all 40 entries, prints the flag box
and saves `flag_from_white_bird.txt`:

```
FlagY{9dd0a8062df77529e323905c5bbe7809}   🏁
```