# FlagYard CTF — Fr33

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Hard (صعب) · **Points:** 270

---

## The flag

```
FlagY{56de424f-b02d562e-d77cd19b-3fd357e6}
```

The 35-char serial inside is the flag's payload; `FlagY{...}` is the
challenge's container.

---

## The short version

`Fr33.exe` is a *keygen*, not a crack. It asks for an **8-character username**
(must be exactly `DYSTOPIA`) and a license key of the form

```
XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX        (35 chars, dashes at 8, 17, 26)
```

Each hex group is parsed with `sscanf("%x")` and compared against
**MurmurHash3_x86_32(seed=0)** of a substring of the username — the hash bodies
are inlined four times into `.text`:

| key group | input | username slots |
|---|---|---|
| group0 | `DSO` | `[0]`, `[2]`, `[4]` |
| group1 | `YTP` | `[1]`, `[3]`, `[5]` |
| group2 | `IA` | `[6]`, `[7]` |
| group3 | `DYSTOPIA` | the whole name |

So the serial is just the four digests joined by `-`. For `DYSTOPIA`:

```
murmur3("DSO")      = 0x56de424f
murmur3("YTP")      = 0xb02d562e
murmur3("IA")       = 0xd77cd19b
murmur3("DYSTOPIA") = 0x3fd357e6

56de424f-b02d562e-d77cd19b-3fd357e6
```

---

## First look

```
Fr33.exe   13312 bytes   Windows PE32+ (AMD64, MSVC Release, stripped)
PDB: ...\joezid\Source\Repos\Fr33_FlagYard_Hard\64\Release\Fr33_FlagYard_med.pdb
```

- No packing, no VM, no custom section — plain 6-section MSVC PE.
- `strings` reveals the whole UX immediately:
  ```
  Enter an 8-character username:
  Error: Username must be exactly 8 characters long.
  Enter the key:
  Wrong Key
  Cracked ,Correct Key:D
  ```
- Format strings in `.rdata`: a `%s` for the username and `%x` for the key
  groups (there is also a `%d` used by the CRT startup).

The user-facing flow at `0x140001140`:

```asm
lea  rcx, text@"Enter an 8-character username:"  ; printf
lea  rdx, [rbp-0x29]                            ; username buffer (8 bytes)
lea  rcx, fmt@"%s"; call scanf
... strlen == 8 enforced ...
lea  rcx, text@"Enter the key:"                 ; printf
lea  rdx, [rbp+0x27]                            ; key buffer
call scanf
... strlen == 0x23 (35) and key[8]==key[17]==key[26]=='-' ...
```

Then the key is split into four 8-char groups with `strncpy(...)` (four buffers
at `rbp-0x19`, `rbp-9`, `rbp+7`, `rbp+0x17`), each immediately NUL-terminated,
and converted with four calls to the `__stdio_common_vsscanf` wrapper against
`"%x"` into `int` locals at `rbp-0x3d / -0x39 / -0x35 / -0x31`.

---

## Reversing the checker — the username becomes the serial

The actual gate is four **inlined hash bodies** that each rebuild a substring
out of the username, hash it, and compare:

```asm
; --- string rebuild, e.g. group0 = username[0],[2],[4] -> "DSO" ---
movzx eax, byte   ptr [rbp-0x27]        ; username[2]
movzx edi, byte   ptr [rbp-0x28]        ; username[1]
movzx esi, byte   ptr [rbp-0x23]        ; username[6]
...
lea   r10, [rbp-0x49]                   ; compact 3-char buffer "DSO", NUL
...
; --- hash core (inlined 4x) ---
mov   ecx, dword ptr [r10]              ; k1 = 4 bytes (or built tail)
imul  edx, ecx, 0xCC9E2D51              ; k1 *= c1
rol   edx, 0xf                          ; k1 = ROTL(k1,15)
imul  ecx, edx, 0x1B873593              ; k1 *= c2
xor   r9d, ecx                          ; h1 ^= k1
rol   r9d, 0xd                          ; h1 = ROTL(h1,13)
add   r9d, 0xFADDAF14                   ; (mangled) h1 = (h1 + K) * 5
lea   r9d, [r9 + r9*4]
...
xor   r9d, r8d                          ; h1 ^= len
; fmix32
shr   ecx, 0x10 / xor / imul 0x85EBCA6B / shr 0xd / xor / imul 0xC2B2AE35 / shr 0x10 / xor
cmp   ecx, dword ptr [rbp-0x3d]         ; == group0
jne   try_wrong
```

**Pattern recognition:** `0xCC9E2D51`, `rol 15`, `0x1B873593`, `rol 13`,
`0x85EBCA6B`, `0xC2B2AE35` are the *exact* filter/seed constants of
**MurmurHash3_x86_32**. The four `fmix` tails in `.text` = four hashes.

The four substring builders borrow *non-contiguous* username slots and squash
them into small NUL-terminated buffers, then hash from `seed = 0`
(`xor r9d, r9d` before each block). That "scrambled" layout is the custom
*mangle* of the challenge — but it is cosmetic: it just defines which three
characters go into which group.

---

## The mangled block step

Canonical MurmurHash3 does `h1 = ROTL(h1,13); h1 = h1*5 + 0xE6546B64;`. This
binary does `add r9d, 0xFADDAF14` *before* the `*5`:

```asm
rol   r9d, 0xd
add   r9d, 0xFADDAF14        ; (h1 + 0xFADDAF14) * 5
lea   r9d, [r9 + r9*4]
```

i.e. `h1 = (h1 + 0xFADDAF14) * 5`. The solver reproduces the binary's exact
arithmetic. For these specific inputs the resulting group values coincide with
a canonical implementation, so both reproduce the accepted serial.

---

## Keygen (solve)

A keygen needs no cracking — implement the hash and print:

```python
def murmur3_32(data, seed=0):
    h = seed
    n = len(data); i = 0
    for _ in range(n // 4):
        k = int.from_bytes(data[i:i+4], "little")
        k = (rol32((k * 0xCC9E2D51) & 0xFFFFFFFF, 15) * 0x1B873593) & 0xFFFFFFFF
        h ^= k
        h = rol32(h, 13)
        h = ((h + 0xFADDAF14) * 5) & 0xFFFFFFFF          # binary's variant
        i += 4
    k = 0
    for j in range(n % 4):
        k ^= data[i+j] << (8*j)
    if n % 4:
        k = (rol32((k * 0xCC9E2D51) & 0xFFFFFFFF, 15) * 0x1B873593) & 0xFFFFFFFF
        h ^= k
    h ^= n                                              # h1 ^= len
    h ^= h >> 16; h = (h * 0x85EBCA6B) & 0xFFFFFFFF     # fmix32
    h ^= h >> 13; h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h

user = b"DYSTOPIA"
groups = [murmur3_32(bytes((user[i] for i in idx)), )
          for idx in ((0,2,4), (1,3,5), (6,7))] + [murmur3_32(user)]
serial = "-".join("%x" % g for g in groups)
```

Result:

```
56de424f-b02d562e-d77cd19b-3fd357e6
```

which wraps into the checkable flag `FlagY{56de424f-b02d562e-d77cd19b-3fd357e6}`.

### Live verification

```
$ Fr33.exe
Enter an 8-character username: DYSTOPIA
Enter the key: 56de424f-b02d562e-d77cd19b-3fd357e6
Cracked ,Correct Key:D
```

A wrong key (or a wrong user name length/dashes) prints `Wrong Key`.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| No comparison table, no hardcoded key | whole `main` | the "answer" is derived, not stored — it's a keygen problem |
| Hash constants are recognizable | each inlined body's `imul rol` chain | pattern-match MurmurHash3 immediately |
| The hash is **non-secret / seed 0** | `xor r9d,r9d` before every body | recompute it directly, no brute force |
| Scramble is just `strncpy`-style byte picking | the substring builders | read the three slot offsets and emit the string |
| Plaintext "logic-free" flow | `sscanf("%x")` + 4 `cmp` | four independent comparisons, fully decoupled |
| Success/failure probes in cleartext | `.rdata` | dynamic confirmation is one run away |

The "hard" difficulty is entirely in *recognizing* the function and reading
which username bytes feed each group. There is no protection to defeat.

---

## Takeaways

- **A license/registration checker that hashes the username is a keygen.** When
  `transform(user_input) == stored` but the stored value is itself derived from
  an input you control, just run `transform` forward.
- **Memorize the murmur3_x86_32 fingerprint**: `imul 0xCC9E2D51; rol 15;
  imul 0x1B873593` (+ `0x85EBCA6B`, `0xC2B2AE35` fmix) appears verbatim across
  tons of CTFs as a keygen/checksum core.
- **Watch mangled constants.** A swapped order (`add` before `*5`) and a
  shuffled constant (`0xFADDAF14` vs `0xE6546B64`) are common disguises;
  reimplement what the disassembly says, not what the reference says.
- **`%x` group parsing + dash validation is the strongest format hint**:
  8-8-8-8 hex groups at 8/17/26 reveal both the serial shape and the 
  `%08x`-style formatting to match leading zeros.
- **Verify dynamically.** One `Fr33.exe` run with the computed serial proves
  the model; never ship a solver that only "looks right".

---

## The solver

Colored CLI keygen in the same folder, **pure Python (stdlib only)**:

```
fr33_solve.py
```

```bash
python fr33_solve.py            # reads Fr33.exe next to it (default user DYSTOPIA)
python fr33_solve.py --user IDENTITY   # keygen for any 8-char username
```

It parses the PE, proves the 4 inlined MurmurHash3_x86_32 bodies (constants
`0xCC9E2D51/0x1B873593`, fmix, and the custom `0xFADDAF14` block step), builds
the substrings, hashes them, re-parses the serial with `%x` semantics
(round-trip), runs `Fr33.exe` and expects `Cracked ,Correct Key:D`, then prints
the flag box and saves `flag_from_fr33.txt`:

```
FlagY{56de424f-b02d562e-d77cd19b-3fd357e6}   🏁
```