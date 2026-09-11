# FlagYard CTF — Akaza

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Hard
- **Target:** `Akaza.exe` — 64-bit PE, flattened (switch-based) VM; the real logic lives in a sparse executable section named `.0Dev`.

---

## The flag

```
FlagY{fb0e698571d655911ebfefbfd08e1d43}
```

---

## The short version

`Akaza.exe` hides its checker in a **flattened switch machine**. The `.pdata`
directory reveals a function `0x10e0..0x1460` that starts with a single
`jmp 0x140026000` — straight into `.0Dev`, a compiler-like custom section
(VA `0x25000`, flags `0x60000020` = CODE|EXECUTE|READ) whose first 0x1000
bytes are zero padding and whose real code sits at `0x140026000+`. There, a
classic control-flow-flattening dispatcher walks **41 states**:

```asm
push rax ; pushfq ; mov eax, <state> ; jmp 0x140026008   ; call the switch
0x140026008: cmp eax, <case> ; jne +8 ; popfq ; pop rax ; jmp <handler>
...every handler ends with... mov eax, <next> ; jmp 0x140026008
```

After an anti-debug / XOR-decrypted prompt, it `scanf`s a **32-byte payload**
(the future hex inside `FlagY{...}`) and validates it through **16 rounds**.
Round `r` takes the 16-bit window `(payload[2r] << 8) | payload[2r+1]` and runs
it through a **3476-entry divisor chain** (word table at RVA `0x3280`,
ascending, unique, `2..0x7e6d`):

```python
for r in range(16):
    v = (payload[2*r] << 8) | payload[2*r+1]
    for each divisor d in table:          # word idx advances only on "not divisible"
        if v % d == 0:
            counter[word_idx] += 1        # WORD counter, re-tested until it stops dividing
            v = v // d                    # quotient carries into the next divisor
    memcmp(counter, expected_row[r], 0xd94)   # row r at RVA 0x6080, stride 0x1b28
```

All 16 `memcmp` must succeed (`ebx == 0x10`), then the binary prints
`Correct Flag :D` and `Flag: FlagY{%s}`.

Because every window is only **16 bits**, each expected row fixes a unique
16-bit value: we enumerate all 65536 windows per round, replay the exact chain
in Python, and keep the (single) value whose counter bytes equal the row. The
16 windows tile the 32 payload bytes in order, giving
`fb0e698571d655911ebfefbfd08e1d43`.

---

## Step-by-step

### 1. First look

- `Akaza.exe`, 159744 bytes, MSVC x64 Release build; PDB string embedded:
  `C:\Users\joezid\Source\Repos\FlagYard_hard1\x64\Release\FlagYard_hard1.pdb`.
- Imports: `IsDebuggerPresent` (anti-debug), `memcmp`, `memset`, and the
  usual `vfscanf`/`vfprintf` CRT pair.
- Running it prints `Enter the flag:`, reads from stdin, and any wrong input
  gives `Wrong Flag :(` (exit 0). Success format string `"Flag: FlagY{%s}"`
  sits at RVA `0x3260` — so the *payload*, not the braces, is what we supply.

### 2. The odd `.0Dev` section

The section table is unusual:

```
.text   VA=0x1000  VS=0x123c   raw=0x1000
.rdata  VA=0x3000  VS=0x2a6a
.data   VA=0x6000  VS=0x1b908
...
.0Dev   VA=0x25000 VS=0x2000   chars=0x60000020   (executable + readable)
```

`.0Dev` is almost all zeros except `0x140026000..0x140027000`, which is real
x64. `.pdata` maps a `main`-shaped function `0x10e0..0x1460` whose first
instruction is `jmp 0x140026000`, so the OEP `0x16f4` (CRT) eventually lands
in `.0Dev` logic.

### 3. The flattened dispatcher (41 cases)

The entry at `0x140026000` is:

```asm
0000: 50        push rax
0001: 66 9c     pushfq
0003: b8 00 00 00 00    mov eax, 0
0008: 3d 29 00 00 00    cmp eax, 0x29     ; <- every handler jumps here with next state
000d: 75 08     jne +8
000f: 9d        popfq
0010: 58        pop rax
0011: e9 ...    jmp case_41
...
```

We decoded every dispatch stub and produced a **case → address** map of all
41 states (e.g. `0->0x140026280`, `3->0x140026327`, `9->0x140026433`,
`18->0x140026587`, `19->0x1400265bf`, …). The flattening is textbook: each
handler ends `push rax; pushfq; mov eax,<next>; jmp 0x140026008`.

### 4. Recovering the rounds

- State `0` allocates `0x1b90` (via `_chkstk`), sets up the security cookie,
  and XOR-decrypts the prompt buffer with key `0x44`.
- State `3`: prints the prompt (`0x140001020` = vfprintf wrapper), reads the
  payload with `scanf` (`0x140001080` = vfscanf wrapper) into `[rsp+0x20]`;
  `rsi = payload+1`, `rbp = 4`, `r12 = 0x140003280` (divisor words),
  `r13 = 0x140006080` (expected rows).
- Round A (states 5/6/7/8): window `(p[0]<<8)|p[1]`; loop `r9 = 0..0xd94-1`
  over the divisors; `idiv`; on zero remainder `inc word [rsp+r8+0x50]`
  **and carry the quotient**, re-testing the same divisor; otherwise
  `r8 += 2, r9 += 1`.
- State `9` (0x140026431): `memcmp(counter, r13 + ((rbp-4)>>1)*0x1b28, 0xd94)`.
- Rounds B/C/D use windows `(p[2],p[3])`, `(p[4],p[5])`, `(p[6],p[7])`
  (`[rsi+1]`,`[rsi+2]` …); then an outer loop does `add rsi,8` →
  windows `8..15`, `16..23`, `24..31`. So the 16 windows tile all 32 bytes
  with no overlap.

### 5. Validating the semantics live (Frida)

Static analysis gives a hypothesis; we confirmed the counter bytes from the
**actual process**:

- `frida.attach` on the live process (retail image base read via
  `Process.findModuleByName('Akaza.exe')`, all hooks re-based by RVA because
  of ASLR), replaced `IsDebuggerPresent` with a `0` stub, and hooked the
  `memset` (`0x2042`) / `memcmp` (`0x21c1`) thunks.
- Observed exactly 16 × `memset(buf, 0, 6952)` followed by
  `memcmp(buf, r13 + row*0x1b28, 3476)` — so the compared slice is the
  **first 0xd94 bytes** of the counter buffer.
- Feeding a controlled input and dumping the counter bytes matched a pure
  Python replay **byte-for-byte** (e.g. `"Fl" → [0:2, 1220:1]`,
  `"AA" → [4:1, 10:1, 108:1]`). No more guessing.

### 6. Solving

1. Extract divisors: 3476 × u16 at RVA `0x3280` (verified ascending, unique,
   no zeros).
2. Extract the 16 expected rows at RVA `0x6080` (stride `0x1b28`).
3. Per round, enumerate `0..65535`, replay the chain, keep windows whose first
   `0xd94` counter bytes equal the row. Every row accepts exactly **one** value:

```
row 0 -> f b    row 1 -> 0 e    row 2 -> 6 9    row 3 -> 8 5
row 4 -> 7 1    row 5 -> d 6    row 6 -> 5 5    row 7 -> 9 1
row 8 -> 1 e    row 9 -> b f    row10 -> e f    row11 -> b f
row12 -> d 0    row13 -> 8 e    row14 -> 1 d    row15 -> 4 3
```

4. Payload: `fb0e698571d655911ebfefbfd08e1d43`.

### 7. Runtime confirmation

```
C:\> echo fb0e698571d655911ebfefbfd08e1d43 | Akaza.exe
Enter the flag:
Correct Flag :D
Flag: FlagY{fb0e698571d655911ebfefbfd08e1d43}
```

Exit code 0. **The flag is accepted.**

---

## Tools

- `pefile` / `lief` + `capstone` for PE parsing and `.0Dev`/`.text` disassembly
- `.pdata`-driven recovery of the 41-state flattening map
- Frida (attach on the ASLR retail base; `IsDebuggerPresent` → `0`) to dump the
  live counter buffers and the `memcmp` sources per round
- Pure-Python replay of the divisor chain + 16 × 65536 window search

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)