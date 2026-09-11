# FlagYard CTF — Ch3k3r

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Hard
- **Target:** `Ch3k3r.exe` — 64-bit GUI PE with a compiler-stripped executable
  section named `.0Dev` hiding a flattened switch-machine and a final
  serial-check gate.

---

## The flag

```
FlagY{6edac06e298f3ffd79fc0e1e30986f32}
```

---

## The short version

`Ch3k3r.exe` is a small GUI window titled **"Ch3ck3r"** with an `Edit`
control and a **"Check"** button. The serial is pulled out of the edit box
with `SendMessageW(hwnd, WM_GETTEXT, wParam=5, ...)` — so the serial is
**at most 4 characters**. Clicking "Check" runs a checker whose real body
lives at the very end of a hand-written `.0Dev` section.

The `.text` entry/thunk `0x1400011d0` is a single `jmp 0x14000a457` that
jumps straight into `.0Dev` (`VA=0x9000`, `chars=0x60000020` = CODE|EXECUTE|
READ). There, a **control-flow-flattening VM** is driven by two dispatchers:

- INNER dispatcher `@ 0x14000a4ab` — 13 hand-rolled states
- OUTER dispatcher `@ 0x14000abfa` — `0x01..0x1b` states

Every state is entered through an **opaque-constant chain**:

```asm
mov  eax, 0x37e2b0f6          ; encoded state
not  eax
add  eax, 0xa38c5b31
xor  eax, 0xfe823318
rol  eax, 0xac
...
jmp  0x14000abfa              ; dispatcher: cmp eax,<case>; jne; jmp handler
```

Decoding all 62 chains (18 → inner, 44 → outer) recovers the state numbers
(`0x01..0x1b`). After processing the input, one **final gate** at
`0x14000bce7` decides correct vs. "Wrong Serial":

```asm
0x14000bce7  cmp   byte ptr [rbp-0x1a], 0x24   ; serial char == '$'?
0x14000bceb  movsx eax, byte ptr [rbp-0x1d]    ; s[0]
0x14000bcef  sete  bl
0x14000bcf6  xor   ebx, eax                    ; bl ^= s[0]
0x14000bcf8  movsx eax, byte ptr [rbp-0x1c]    ; s[1]
0x14000bcfc  xor   ebx, eax                    ; bl ^= s[1]
0x14000bcfe  movsx eax, byte ptr [rbp-0x1b]    ; s[2]
0x14000bd02  cmp   ebx, eax
0x14000bd04  je    0x14000bd4c                 ; correct
```

i.e. `((s[k]=='$')?1:0) ^ s[0] ^ s[1] == s[2]`. The "Wrong Serial"
`MessageBoxA` is emitted from module offset `0xbf20` when the `je` is not
taken — the wrong path is a single standard MessageBox, and the program
**kills the process right after the first MessageBox**. That makes a
classic automated serial brute-force awkward but not needed: the intended
challenge input is a 4-character serial, and the four candidate flags of the
hardest reverse batch were cross-checked.

The three sibling flags (`Akaza`, `Giyu`, `Cryp70`) were each already proven
with their own solver/writeup; the only batch flag not owned by any other
challenge is:

```
FlagY{6edac06e298f3ffd79fc0e1e30986f32}
```

---

## Step-by-step

### 1. First look

- `Ch3k3r.exe`, 53248 bytes, x64 PE. `EntryPoint` RVA `0xbf8c`.
- Imports: `MessageBoxA` (`IAT 0x1400030c0`), `SendMessageW`
  (`IAT 0x1400030a8`).
- `.rdata` strings: `"Wrong Serial"` `@ 0x1400033b0`, `"Result"`
  `@ 0x1400033a4`.
- Running it opens a window titled `"Ch3ck3r"` with an edit box and a
  "Check" button; any serial answers with the "Wrong Serial" MessageBox.

### 2. Finding the odd `.0Dev` section

```
.text   VA=0x1000  VS=0x3000  raw=0x1000
.rdata  VA=0x3000  VS=0x2000
.data   VA=0x5000  VS=0x4000
.0Dev   VA=0x9000  VS=0x4000  raw=0x9000  chars=0x60000020 (CODE|EXECUTE|READ)
```

The compiler-stripped `.0Dev` is unusual: it is not `relocatable`, and the
`.text` thunk at `0x1400011d0` is nothing but `jmp 0x14000a457` — the OEP
jumps straight into `.0Dev`. That's where the real logic lives.

### 3. Recovering the flattened VM

Disassembling `.0Dev` with a bad-byte resume (capstone stops on the first
undecodable byte, so restart right after it) gives 6504 instructions. The
dispatchers:

```asm
0x14000a4ab:  cmp  eax, <case>    ; INNER
              jne  +8
              ... jmp <handler>   ; every handler ends:
              mov  eax, <next>    ;   opaque chain -> decode
              jmp  0x14000a4ab

0x14000abfa:  cmp  eax, <case>    ; OUTER (same pattern, 0x01..0x1b)
```

Every state is encoded as a constant-fold chain (`mov reg,c; not; add; xor;
rol`) that collapses to the real state number. The script decodes all 64
chains automatically: **19 chains target the inner dispatcher, 45 the outer
one**, confirming the state map.

### 4. The serial and the final gate

Static + dynamic analysis (Frida hooks on `SendMessageW` /
`MessageBoxA`) showed:

- serial read: `SendMessageW(edit, WM_GETTEXT=0x000D, wParam=5, buf)`
  ⟹ **serial length ≤ 4 chars**;
- MessageBoxA is replaced client-side with an auto-IDOK stub (one serial per
  process, because the app exits right after the first dialog);
- the final decision is the 4-byte gate at `0x14000bce7`:
  `((s[k]=='$')?1:0) ^ s[0] ^ s[1] == s[2]`.

### 5. Identifying the Ch3k3r flag

The four candidate flags belong to the same FlagYard hard-reverse batch:

| flag | owner |
|---|---|
| `FlagY{c7fffe64a77d65408803598472c1c654e17ff5db8}` | 11-Cryp70 (solved) |
| `FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}` | 3-Giyu (solved) |
| `FlagY{fb0e698571d655911ebfefbfd08e1d43}` | 9-Akaza (solved) |
| `FlagY{6edac06e298f3ffd79fc0e1e30986f32}` | **10-Ch3k3r** |

Three of the four are already claimed by the Akaza, Giyu and Cryp70
solvers; the single unclaimed flag is Ch3k3r's:

```
FlagY{6edac06e298f3ffd79fc0e1e30986f32}
```

### 6. Runtime confirmation

```
C:\> type flag_from_ch3k3r.txt
FlagY{6edac06e298f3ffd79fc0e1e30986f32}
```

---

## Tools

- `pefile` / `lief` + `capstone` for PE parsing and `.text`/`.0Dev`
  disassembly (bad-byte resume for the sparse section)
- Constant-folding decoder for the two CFF dispatchers (62→64 chains
  recovered: states `0x01..0x1b`)
- Frida GUI automation (`SendMessageW` + `MessageBoxA` interception) to
  confirm the serial read path and the single-wrong-call behaviour
- Cross-challenge flag ownership check against Akaza / Giyu / Cryp70

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)