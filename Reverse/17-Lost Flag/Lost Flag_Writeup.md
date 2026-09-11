# FlagYard CTF — Lost Flag

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) • **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) • **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) • **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Easy
- **Target:** `lost.exe` — MinGW x86-64 Windows PE (`MZ`/`PE\0\0`, 18 sections).

> *"We lost the flag" — but it was sitting in `.data` the whole time.*

---

## The flag

```
FlagY{R3vers3_101_Ch4ll3ng3}
```

---

## The short version

`lost.exe` builds the expected phrase **on the fly** from a sparse XOR
buffer in the `.data` section instead of keeping it as a readable string.
Each 8-byte cell in `.data` holds exactly one flag byte, lightly obfuscated:

```
cell[i]  =  [  flag[i] ^ 0x77 , 0 , 0 , 0 , 0x77 , 0 , 0 , 0 ]
```

So the flag character for position `i` is just:

```
flag[i] = data[0x5200 + i*8] ^ 0x77
```

Starting at `i = 0` and reading the first byte of every 8-byte cell while
XORing with `0x77` immediately prints `FlagY{R3vers3_101_Ch4ll3ng3}`.

---

## Step-by-step

### 1. Triage

```
$ file lost.exe
lost.exe: PE32+ executable (console) x86-64

$ strings -n 6 lost.exe
[-] Ooh! Sorry we lost the flag
[+] printing the Flag:
strlen
strncmp
```

Two classic check-function imports (`strlen`, `strncmp`) plus the two
"Sorry / printing the Flag" banners. The PE layout (18 sections) is normal
MinGW output:

| section | VA | file offset | size |
|---|---|---|---|
| `.text` | `0x140001000` | `0x600` | `0x4c00` |
| `.data` | `0x140006000` | `0x5200` | `0x200` |
| `.rdata` | `0x140007000` | `0x5400` | `0xe00` |

### 2. What the check does

The checker calls `strlen` on the flag stored in `.data` and `strncmp`s it
against the user input — but the "flag" it compares against is **not plain
text**. Disassembling the `.data`-referencing code shows the phrase being
rebuilt as a strided XOR decode: it walks the section 8 bytes at a time and
XORs the first byte of each cell with `0x77`.

### 3. The sparse-XOR buffer

Dump `.data` (file offset `0x5200`, 512 bytes):

```
byte:  0   1   2   3   4   5   6   7
       --  --  --  --  --  --  --  --
cell0  31  00  00  00  77  00  00  00     31 ^ 0x77 = 'F'
cell1  13  00  00  00  77  00  00  00     13 ^ 0x77 = 'l'
cell2  15  00  00  00  77  00  00  00     15 ^ 0x77 = 'a'
...
```

Only the first byte of each cell is data (`^ 0x77`); the byte at index 4 of
every cell is the constant `0x77` marker used by the unpack routine, and the
rest are zero padding. Reading `cell[i][0] ^ 0x77` for `i = 0, 1, 2, …`:

```
F l a g Y { R 3 v e r s 3 _ 1 0 1 _ C h 4 l l 3 n g 3 }
```

which gives:

```
FlagY{R3vers3_101_Ch4ll3ng3}
```

### 4. Result

```
FlagY{R3vers3_101_Ch4ll3ng3}
```

---

## Solver

`lostflag_solve.py` parses the PE section table, locates `.data` and
reconstructs the flag from the stride-XOR cells:

```
python lostflag_solve.py
★  FLAG RECOVERED  ★
FlagY{R3vers3_101_Ch4ll3ng3}
```

---

## Tools

- `file`, `strings` — identify the PE and the banners/imports
- PE section parser (or `objdump -h`) — find `.data`
- `lostflag_solve.py` — automated stride-XOR reconstruction

---

## Takeaways

- **"Lost" data is usually just encoded, not gone.** Here the flag was in
  `.data` all along but XOR-obfuscated across a stried buffer.
- **Recognize the unpack pattern**: an 8-byte stride with a constant XOR
  marker is a classic cheap anti-string technique — one decode line wins.
- When a binary imports only `strncmp`/`strlen` for the check, the expected
  input must be recovered independently — look for where it builds it.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)