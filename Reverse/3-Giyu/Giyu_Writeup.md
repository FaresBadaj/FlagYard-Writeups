# FlagYard CTF — Giyu

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Reversing
- **Difficulty:** Hard (صعب)

---

## The flag

```
FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}
```

---

## The short version

`Giyu.exe` is a 65,536-byte x64 PE whose real code hides in a custom executable
section named **`.0Dev`**. The original C code was passed through an
opaque-predicate obfuscator: every few instructions it splices in a block of the
form

```asm
push rax
pushf
mov  eax, <const>        ; then: pushf / not / add / xor / rol / popf ...
...
cmp  eax, 0
jne  good
popf
pop  rax
jmp  good
```

`push rax`/`pushf` + `popf`/`pop rax` make the whole burst a **net no-op** — both
branches jump to the same address, and the computed `eax` value is thrown away.
The strings and IAT references are reached through `lea r,[rip+X] ; sub r,Y`
pairs that resolve to the same place as a plain `rip`-relative reference.

Once the noise is ignored, the flow is trivial:

1. `printf("Enter The Flag:")`
2. `scanf("%s", buf)`  (buffer zeroed first, `%s` in `.rdata`)
3. `checker(buf)` — **one big unrolled function** at `0xCB75`
4. `checker` returns `eax == (count == 47)`; `main` maps it to
   `"Correct Flag :)"` / `"Wrong Wrong :("` with a `cmove`.

The checker is the whole challenge: it loads **all 47 flag bytes**
(`buf[0..0x2e]`) into scratch registers/stack slots and then runs a straight
line of **47 byte-equations** over them, e.g.

```asm
movzx ecx, byte ptr [rsp+0x19]
xor   cl,   byte ptr [rsp+0x18]
sub   cl,   byte ptr [rsp+5]
add   cl,   byte ptr [rsp+0x1b]
xor   cl,   byte ptr [rsp+0xa]
add   cl,   byte ptr [rsp+4]
xor   cl,   byte ptr [rsp+0x18]
cmp   cl,   0x3e
movzx ecx, byte ptr [rsp+6]      ; reload next operand (movzx keeps EFLAGS)
sete  al                         ; al = (expr == 0x3e) ? 1 : 0
add   dword ptr [rsp], eax       ; counter += match
```

Each satisfied equation adds **+1** to a running counter; at the end the exact
byte of success is:

```asm
cmp  r15d, 0x2f      ; counter == 47 ?
sete r10b
mov  eax, r10d       ; return value
```

With **47 unknowns** (flag bytes) and **47 equations**, the flag is whatever
printable `FlagY{...}` string satisfies every equation — a job for an **SMT
solver** (z3), not a human.

---

## First look

```
Giyu.exe   65536 bytes   Windows PE32+ (AMD64, MSVC Release)
Giyu.zip   (same exe)
```

- No UPX, no packing header.
- `strings`:
  ```
  Enter The Flag:
  %s            <- scanf format, no length limit
  Correct Flag :)
  Wrong Wrong :(
  ```
- PDB leak: `C:\Users\joezid\Source\Repos\Giyu_FlagYard_hard\x64\Release\Giyu_FlagYard_hard.pdb`
- Sections: `.text` (trampoline junk), `.rdata`, `.data`, `.pdata`, `.rsrc`,
  `.reloc`, and the interesting one — **`.0Dev`**, `VA 0x18000`, `r/w/x`,
  **32,768 bytes of actual code**.
- Entry point `0x1D44` does `jmp 0x…00a11f` straight into `.0Dev`.

Linear disassembly of `.text` dies immediately: it is built from `jmp rel32`
stubs, `jnp`/`retf` junk and `INT3` padding. All the meaningful code lives in
`.0Dev`.

### The obfuscator idiom

The signature block above (`push rax; pushf; mov eax,imm; …; cmp eax,0; jne L;
popf; pop rax; jmp L`) appears hundreds of times. Each one computes a **constant**:

```python
e = imm
e = ~e; e += a; e ^= b; e = rol(e, r)   # 32-bit, repeated 2-4 rounds
```

…then throws it away by restoring `rax` and joining both branches. So for
reversing purposes every such block is just `jmp L`. There is also a
**dispatcher-style** variant that uses the computed constant to `cmp`-against
`2/0/3/1` and jump to different handlers — but because the value is constant,
one branch is always taken. Everything collapses back to straight-line code.

`lea rip-relative + sub` is the same idea applied to addresses: the computed
value is the correct string/IAT pointer, the instruction before/after just
"hides" it.

---

## Reversing the checker

### `main` — `0x94E5`

```
sub rsp, 0xA8
mov [rsp+0x90], rax ^ rsp            ; __security_cookie
xorps xmm0, xmm0
movups [rsp+0x20..0x70], xmm0        ; zero the 0x60-byte flag buffer
mov  [rsp+0x80], eax
lea  rcx, text@"Enter The Flag:"     ; (obfuscated, resolves to .rdata)
call print_loc                       ; 0xA180 = printf("/puts") wrapper
lea  rdx, [rsp+0x20]                 ; destination buffer
lea  rcx, fmt@"%s"                   ; (obfuscated)
call read_loc                        ; 0x9382 = scanf wrapper
lea  rcx, [rsp+0x20]
call checker                         ; 0xCB75  <-- the whole game
test eax, eax
lea  rdx, "Wrong Wrong :("           ; resolved address
lea  rcx, "Correct Flag :)"          ; resolved address
cmove rcx, rdx                       ; eax==0 ? "Wrong" : "Correct"
call print_loc
```

So the **only** logic is `checker(buf)` returning `eax`.

### The checker — `0xCB75`, the equation machine

1. **Load phase** — one byte per input position (`buf[0]`…`buf[0x2e]`) is
   copied into a scratch register or a `[rsp+off]` slot:

   ```asm
   movzx eax, byte ptr [rcx + 0x24]   ; into [rsp+0x11]
   mov   byte ptr [rsp + 0x11], al
   movzx edi, byte ptr [rcx + 0x15]   ; edi = buf[0x15]
   movzx ebx, byte ptr [rcx + 0x20]
   ...
   ```

2. **Equation phase** — 47 times: build a byte expression from a handful of
   those slots with `xor / add / sub / or / and` (mod 256), compare to a
   constant, and fold the `sete` bit into the counter:

   ```asm
   ... closer of equation #k ...
   cmp   cl, 0x3e
   movzx ecx, byte ptr [rsp+6]        ; next operant already loaded
   sete  al
   add   dword ptr [rsp], eax         ; counter += (expr == const)
   ```

   When registers start running short the generator carries the counter through
   `ecx → r9d → r10d → r8d → r15d`, round-tripping through `[rsp]`:

   ```asm
   mov   ecx, dword ptr [rsp]
   push  rax
   not   eax
   sub   ecx, eax
   pop   rax
   sub   ecx, 1                       ; net effect: ecx += (match != 0)
   ...
   mov   dword ptr [rsp], ecx
   ```

   (In 32-bit arithmetic `cnt - (not eax) - 1 ≡ cnt + eax`, so `or/and`,
   `pushf` tricks and `not` games do **not** change the meaning: it is always
   `counter += match_bit`.)

3. **Gate** — the last real comparison decides:

   ```asm
   cmp  r15d, 0x2f
   sete r10b
   mov  eax, r10d        ; eax = (counter == 47)
   ret
   ```

   There are **48** `sete` instructions in the function, but the 48th is the
   *return value* `sete r10b`. That leaves exactly **47 equations** —
   `counter == 47` means **all of them** must hold.

---

## Turning equations into a flag

Because the counter only counts matches, and all 47 must match, we get a small
system of 47 *byte* constraints over 47 *byte* variables. The equations involve
`or`/`and`, which are not invertible, so hand-symbolic solving is hopeless —
but z3 eats them alive:

```python
flag = [z3.BitVec(f"f{i}", 8) for i in range(47)]
# …re-walk the 725 live instructions symbolically, collecting:
#     equation_k == constant_k    for each of the 47 cmp/sete pairs
s.add(counter_expr == 47)                 # the final gate
s.add(flag[i] in printable, prefix FlagY{, suffix })
```

Re-building the equations is done mechanically: run the disassembly of
`0xCB75`-`0xD587` through a tiny **symbolic interpreter** that emulates the
exact instruction stream (`movzx`, `mov [rsp+off]`, `xor/add/sub/or/and cl`,
`not`, `lea`, `cmp;sete`, and the counter `mov`s/subtractions) with z3 bit-vectors
as register/memory state. This is faithful to the machine — no manual
"translation" of the obfuscated body was needed.

Result:

```
FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}
```

Verified live:

```
$ Giyu.exe   (feed the flag)
Enter The Flag:
Correct Flag :)
```

### Why 47 equations and still two answers?

`or`/`and` are lossy: the equation set is satisfied by the intended flag and one
*other* printable string that differs in two bytes:

```
FlagY{00de46!df2cc793253c06786baa52aa221%1fd93}   <- other preimage
FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}   <- intended (40 hex chars)
```

The intended flag's body is exactly **40 hex characters** (a SHA-1-length
digest). The solver prints both and keeps the 40-hex one.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Opaque predicates are **net no-ops** | every `.0Dev` block | strip them; both branches merge → straight-line code |
| Junk computes a **compile-time constant** | `not/add/xor/rol` chains | the dispatcher-style switch never actually switches |
| The validator is **one unrolled function** with no loops | `checker` 0xCB75 | full symbolic execution is feasible and fast |
| Check is a set of **47 independent byte equations** | all of `checker` | one flag variable per byte → SMT solve |
| Expected constants + flag format (47 chars, printable) | `cmp` immediates + `scanf("%s")` | tiny, well-shaped z3 instance |

The obfuscator changes the **look** of the code, not its **semantics**: the
opaque blocks have zero data flow into the real computation, so a symbolic
interpreter that treats them as the no-ops they are reproduces the original
validator exactly.

---

## Takeaways

- **Recognize `push rax; pushf; …; cmp eax,0; jne L; popf; pop rax; jmp L`** —
  the saved/restored `eax` and the merged branches are the signature of an
  opaque predicate. Treat the whole block as the jump at the end.
- **Obfuscation hides readability, not computability.** If every block's
  arithmetic is constant-foldable and all branches merge, the "protected"
  function is just an unrolled straight-line program — feed it to a re-player.
- **"One live function, no loops, small state" is the sweet spot for symbolic
  execution.** 47 byte-unknowns and 47 equations solve in seconds with z3.
- **Watch conservation-of-tricks `or`/`and`:** the equations can over-approximate
  the printable solution space; sanity-check candidates against the real exe.
- **A `sete` count can lie.** Here the 48th `sete` was the return value, not an
  equation — count carefully (`47 == 0x2f` matched perfectly).

---

## The solver

Colored CLI solver in the same folder:

```
giyu_solve.py
```

Needs `pip install capstone z3-solver`, then:

```bash
python giyu_solve.py          # reads Giyu.exe next to it
```

It parses the PE, disassembles `.0Dev` with capstone, symbolically re-walks the
47-equation checker, lets z3 enumerate the printable preimages, keeps the
40-hex one, prints the flag box and saves `flag_from_giyu.txt`:

```
FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}   🏁
```