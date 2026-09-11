# FlagYard CTF — Bl4d3

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Medium/Hard
- **Target:** `Bl4d3.exe` — 64-bit PE, real entry `0x140001000`, flattened-VM control flow.

---

## The flag

```
FlagY{d89b2c0a6d7bfcaabfd66b2b8b1d252d}
```

---

## The short version

`Bl4d3.exe` is protected by **control-flow flattening**: the entire validation
is one big state machine (a "dispatcher") with a **single pollution sink** at
`0x140004cfa` that aborts wrong flags. There is no `cmp`/`call` to the real yet
entry — the real `main` at `0x140001000`:

```asm
cmp  ecx, 2                  ; argc must be 2
mov  r8, [rdx+8]             ; r8 = argv[1] (our flag)
; strlen(argv[1]) must equal 39  (cmp rax, 0x27)
; success arms a stack slot, then FALLS THROUGH into the VM at 0x140001288
```

By tracing the executed instruction stream with a correctly-shaped `argv`
(3-qword pointer block), we observed exactly **32 checkpoint sites** of the
pattern:

```asm
movsx rax, byte ptr [r8 + disp]   ; load one flag byte
add/sub/xor/imul rcx, rax         ; accumulate into rcx
... imul rcx, imm / add / shl ... ; fold in constants
cmp  rcx, TARGET
jne  FAILURE_ROUTINE              ; 0x140004cfa
```

Every checkpoint computes its own **multi-variable formula** over a subset of
positions `6..37` of the flag. The 32 recovered formulas were replayed against
20 random inputs with **0 mismatches**, then solved as **32 bit-vector
equations over 32 unknown printable bytes** with Z3. The model is unique and
the binary accepts it line-by-line.

---

## Step-by-step

### 1. First look

- Imagebase `0x140000000`, OEP RVA `0x4fb4`, `.text` at RVA `0x1000`.
- Static analysis is a maze: thousands of `xor ecx,ecx` resets followed by
  `cmp rcx,.. .. jne` — classic CFF. Static `main` hunting gives nothing
  because the real entry point **falls through** instead of being called.

### 2. Finding the real `main`

The real logic starts at **`0x140001000`**:

```
cmp  ecx, 2          ; argc check
mov  r8, [rdx+8]     ; r8 = argv[1]
strlen(argv[1])      ; length must be 39 -> "FlagY{..." (6) + 32 + "}"
cmp  rax, 0x27
je   <arm stack slot>
```

On the "correct length" path a stack slot is armed, and control
**falls through** into the flattened engine at `0x140001288` with
`rax = 0x8c41344eed39f35f`. This is why no `call`/`jmp` to it exists — the
fall-through *is* the branch.

### 3. The flattened engine

The dispatcher state machine (`0x140002450` etc.) walks a table of
`(address, key)` pairs. At each executed site the accumulator is reset with
`xor ecx,ecx` and rebuilt from scratch:

```asm
movsx rax, byte ptr [r8+disp]   ; disp depends on the gate
... additive / xor / multiplicative chain ...
cmp  rcx, BIG_CONST
jne  FAILURE_ROUTINE
```

We instrumented the trace to record, **per visited gate**, the full op chain
(`CHAR d`, `ADD_CHAR/SUB_CHAR/XOR_CHAR`, `IMUL k`, `SHL k`, …) plus the
compared target. Result: **32 unique gates**, each a polynomial (mod 2^64)
over 3–8 flag bytes.

Example gate (address `0x140002d93`, target `103138`):

```
rcx = 0
rcx += f[14]
rcx -= f[34]
rcx += f[6]
rcx += f[30]
rcx ^= f[30]           ; first xor uses the CURRENT rax
rcx *= 1172
rcx ^= f[18]
rcx ^= f[26]
rcx ^= f[10]
rcx += f[10]
cmp rcx, 103138
```

### 4. Validating the recovery

We wrote a pure-Python replay of each gate's op chain and replayed all 32 on
**20 random 39-byte payloads** — every gate reproduced the traced `cmp` value
exactly (**0 mismatches** over 640 chain evaluations). That removed all doubt
about `char` vs `acc` semantics: `-CHAR`/`^CHAR` fold the *loaded byte*, and
the chain's initial `imul` constants apply to the zero-initialized
accumulator.

### 5. Solving the system

The validation constraints form a **dense, non-linear, unique** system — 32
equations (mix of `+`, `-`, `^`, `*`, `<<`) over 32 unknown printable bytes.
We encoded each gate as a 64-bit bit-vector term and solved with **Z3**:

- domain: `0x20 <= c[i] <= 0x7e` for every `i in 6..37`
- 32 equalities (one per gate)
- result: **sat**, one model: `d89b2c0a6d7bfcaabfd66b2b8b1d252d`

We also confirmed uniqueness with an exhaustive printable-domain check (all
other assignments rejected by at least one gate).

### 6. Runtime confirmation

```
C:\> Bl4d3.exe FlagY{d89b2c0a6d7bfcaabfd66b2b8b1d252d}
Correct Flag :D
```

Exit code 0. **The flag is accepted.**

---

## Tools

- `x64dbg` / `pydbg`-style instruction tracing
- Custom trace recorder for the flat-VM gates
- Pure-Python replay/validator for the 32 gate chains
- Z3 (`z3-solver`) for the bit-vector SAT model

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)
- **Reference (cross-check):** public write-up for the same challenge reports the
  identical flag `d89b2c0a6d7bfcaabfd66b2b8b1d252d`, reached independently of
  this analysis.