# FlagYard CTF — tables

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) • **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) • **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) • **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Medium
- **Target:** `tables` — x86-64 non-PIE Linux ELF (base `0x400000`) built from C++.

> *A flag check implemented as a virtual-table state machine.*

---

## The flag

```
FlagY{vt4bl3s_and_vtabl3s_and_m0re_vt3bles}
```

---

## The short version

`tables` reads your answer and walks it **one character at a time through a
C++ object whose behavior is entirely virtual**. Each input byte is sent to a
dispatcher (`0x401390`) that uses a static jump table at `0x404008`, and
every transition *returns a new 8-byte object*. The only thing that changes
between the "advance" and "fail" paths is the returned object's **vtable
pointer**:

- wrong character → shared **fail** object, vtable `0x404440`
- correct character → **advance** object, vtable `0x4045a0 + 0x180 * pos`

So instead of re-deriving every transition stub, we mount a **dynamic
oracle**: break right after the result is stored at `0x4012c1`, read the
returned object's vtable, and accept a character iff its vtable is **not**
the fail vtable. Brute-forcing printable ASCII one position at a time across
all 43 positions recovers the flag deterministically.

---

## Step-by-step

### 1. Triage

```
$ file tables
tables: ELF 64-bit LSB executable, x86-64 ...
```

`readelf -l` — non-PIE, so **file offset = vaddr − `0x400000`** and every
pointer in the binary is a real runtime address. The interesting maps:

```
$ readelf -S tables
.text     at 0x4010c0  (off 0x10c0)
.rodata   at 0x404000  (off 0x4000)
```

Running it:

```
$ ./tables
Enter flag:
test
Wrong!
```

### 2. Find the loop

Tracing back from the "Wrong!" string we find `main` at `0x401090`:

```
0x401218  cin.getline(buf, 0x2c)              ; read up to 44 bytes (43+NULL)
0x401240  obj = new_table_obj()               ; vtable = 0x4042a8
...
0x4012a5  cmp [rbp-0x3c], 0x2b                ; 43 iterations
0x4012a9  jge done
0x4012af  mov rdi, [rbp-0x38]                 ; current object
0x4012b3  movsxd rax, [rbp-0x3c]
0x4012b7  movsx esi, byte [rbp+rax-0x30]      ; input[i]
0x4012bc  call 0x401390                       ; dispatcher
0x4012c1  mov [rbp-0x38], rax                 ; obj = returned
0x4012ce  loop
0x4012d3  rcx = [obj]  ; vtable
0x4012dd  call qword [rcx]                    ; final virtual method = 0x4017e0
```

So the state object is threaded through the loop: **`obj = dispatch(obj, input[i])`**,
43 times, and one final virtual call decides "Correct!" / "Wrong!".

### 3. The dispatcher

`0x401390` computes `idx = c - 0x30`, rejects `idx > 0x4d` and switches on
a **static 0x4e-entry jump table** at `0x404008`:

| entry | char | handler |
|---|---|---|
| 0x00–0x09 | `0`–`9` | `0x401674`–`0x401755` (per-char) |
| 0x0a–0x21 | `:`–`Q` | `0x4017a0` (shared dead branch) |
| 0x22 | `F` | `0x401642` |
| 0x29 | `Y` | `0x40165b` |
| 0x2f | `_` | `0x401629` |
| 0x31–0x5a | `a`–`z` | `0x4013cc`–`0x401686` (per-char) |
| … | rest | `0x4017a0` |

Each per-char handler calls **one virtual slot** of the current object with
the object as `rdi`, e.g. lowercase `a`:

```asm
0x4013cc  mov  rax, [rbp-0x20]     ; current object
0x4013d0  mov  rcx, [rax]          ; -> vtable
0x4013d3  mov  rdi, rax
0x4013d6  call qword [rcx + 8]     ; virtual slot 1
0x4013d9  mov  [rbp-0x8], rax      ; returned object
```

…slot 2 for `b` (`[rcx+0x10]`), slot 3 for `c`, etc. In other words **char
`c` always dispatches to the same slot number** — the state is carried by the
*vtable itself*, which rotates per position.

The shared "dead branch" `0x4017a0` is the fail path: it `new`s an 8-byte
object, zeroes it, and installs the **fail vtable `0x404440`**.

### 4. The interesting part — the vtables

Every transition returns a fresh 8-byte object holding exactly one pointer:

```
fail object   : vtable = 0x404440
advance @ pos : vtable = 0x4045a0 + 0x180 * pos
```

```
advance vtables:
  0x4045a0  slot0  0x4017e0  (final check, shared by all)
  0x4045a0  slot1  0x401800
  0x4045a0  slot2  0x401840
  ...
  0x404720  ...     (pos 1, + 0x180)
```

Because the slot functions are shared across states, the only information
the loop exposes per character is **which vtable the returned object has**.
That is the oracle.

### 5. The oracle

Find `0x4012c1` — the instruction right after the dispatch call stores the
returned object into the state slot (`mov [rbp-0x38], rax`). At that point
`%rax` is the returned object and `*(unsigned long*)$rax` is its vtable.

For every position `i` and every printable candidate `c` we run once under
gdb and check the returned object's vtable. Because position `i` of the
flag advances into vtable `0x4045a0 + 0x180 * i`, the acceptance rule is an
**exact equality**, not a heuristic:

```python
exp = ADV0 + STEP * pos          # ADV0 = 0x4045a0, STEP = 0x180
v   = returned object's vtable
candidate is correct  iff  v == exp
```

The `FlagY{` prefix and the closing `}` are pinned so the oracle only scans
the 36 free characters. The hit counting is done from the Python breakpoint
handler itself (skip yielding control until the `(pos+1)`-th dispatch), and
every position is validated against the exact expected advance vtable —
so stale or off-by-one reads can never be mistaken for a correct character.

Feeding `prefix + candidate + padding`, the oracle determines the next
character of the flag:

```
pos  0/43 char='F'  vtable=0x4045a0     <- advance state 0
pos  1/43 char='l'  vtable=0x404720     <- advance state 1  (+0x180)
pos  2/43 char='a'  vtable=0x4048a0
...
pos 42/43 char='}'  vtable=...          <- final advance state
```

`tables_solve.py` automates the oracle (36 free positions × ~95 printable
characters, one gdb `run` each, hit counting handled by a Python breakpoint
handler) and cross-checks the result live against the real binary.

### 6. Verification

```
$ printf 'FlagY{vt4bl3s_and_vtabl3s_and_m0re_vt3bles}\n' | ./tables
Enter flag:
Correct!
```

---

## Solver

`tables_solve.py` — statically parses the ELF (jump table `0x404008`,
dispatch loop, advance/fail vtables), drives the gdb oracle inside WSL and
prints the recovered flag:

```
python tables_solve.py
★  FLAG RECOVERED  ★
FlagY{vt4bl3s_and_vtabl3s_and_m0re_vt3bles}
```

---

## Tools

- `readelf` / `objdump` — sections, non-PIE base, disassembly
- `gdb` (inside WSL, the ELF only runs under Linux) — breakpoints + oracle
- `tables_solve.py` — automated extraction

---

## Takeaways

- **C++ `virtual` doesn't hide much from a vtable oracle** — when every
  transition returns a NEW object, the vtable of the returned object is the
  state signal; that's the whole check.
- **A static jump table + shared dead-branch handler** means "most inputs go
  to the fail allocator" — only the expected character (or range) reaches a
  distinct transition, which is exactly what makes per-position brute
  forcing cheap and deterministic.
- **Object-oriented state machines are best recovered dynamically**: put a
  breakpoint on the state store, compare the object identity signal, and you
  bypass having to reverse all the per-state stubs.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)