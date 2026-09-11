# FlagYard CTF — Back2Basics

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) • **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) • **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) • **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Reversing
- **Difficulty:** Easy
- **Target:** `chall` — GCC `-S` assembly source of a C++ program.

> *"Back to basics"*

---

## The flag

```
FlagY{9c1beba9c7b722a981ee69f1de5296d9}
```

---

## The short version

`chall` is not a binary at all — it's the **GNU assembly** that `gcc -S`
produces for a small C++ program (`chall.c`), complete with DWARF debug info.
Reading `main` shows it asks for a secret phrase, requires the length to be
exactly `32`, then walks each position `i` with:

```
call  std::string::operator[](i)
cmpb  $0xNN, %al
```

and bumps a counter when the byte matches. If all 32 characters match it
prints `Here is your flag:FlagY{<your-phrase>}`. So the expected phrase is
literally spelled out in the `cmpb` constants, one byte per position.
Extracting all 32 constants in index order gives the 32-char flag body.

---

## Step-by-step

### 1. Triage

The first 4 bytes are `!_` `(#` — not `MZ`, not `\x7fELF`. Reading further it
opens with `MY PROGRAM` then `.file "chall.c"`, `.text`, `.Ltext0:`, etc.
It's the `.s` output of `gcc -S chall.c` for x86_64 Linux with debug info
(`.debug_info` says `Debian 13.2.0`).

The strings confirm exactly what it is:

```
.string "Hello Friend!\n"
.string "What's your secret phrase?\n"
.string "secret phrase: "
.string "Sorry Friend, that's not the correct phrase\n"
.string "Here is your flag:FlagY{"
.string "}"
```

### 2. Understand the check

In `main`:

```asm
leaq -64(%rbp), %rax
call _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev@PLT   ; string s
...
call _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv@PLT
cmpq $32, %rax          ; if s.length() != 32 -> "Sorry..."
```

Then, for every position, a block like this (position 0 shown):

```asm
leaq -64(%rbp), %rax
movl $0, %esi           ; index i
call _ZN...ixEm@PLT     ; s.operator[](i) -> char*
movzbl (%rax), %eax
cmpb $57, %al           ; expected byte for position 0
sete %al
testb %al, %al
je   .L3
addl $1, -20(%rbp)      ; counter++
```

After all 32 blocks:

```asm
cmpl $32, -20(%rbp)
jne  .L35               ; one mismatch -> "Sorry Friend..."
leaq .LC4(%rip), %rax   ; "Here is your flag:FlagY{"
cout << "Here is your flag:FlagY{" << input << "}";
```

### 3. Pull the constants

Extract each `movl $<i>, %esi` / `cmpb $<v>, %al` pair, in index order:

```python
import re
pairs = re.findall(
    r"movl\s+\$(\d+),\s*%esi.*?movzbl\s+\(%rax\),\s*%eax\s*\n\s*cmpb\s+\$(\d+),\s*%al",
    open('chall', encoding='latin-1').read(),
    re.DOTALL,
)
phrase = ['?']*32
for i, v in pairs:
    phrase[int(i)] = chr(int(v))
print('FlagY{%s}' % ''.join(phrase))
```

Output:

```
9c1beba9c7b722a981ee69f1de5296d9
```

spelled in the expected-chars table (position → byte):

| idx | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
|-----|---|---|---|---|---|---|---|---|---|---|
| val | 57 | 99 | 49 | 98 | 101 | 98 | 97 | 57 | 99 | 55 |

the cmp values are plain ASCII: `9 c 1 b e b a 9 c 7 ...`.

### 4. Result

Since the only way to get the flag is to match all 32 bytes, the flag is:

```
FlagY{9c1beba9c7b722a981ee69f1de5296d9}
```

---

## Tools

- `strings` (or just reading the file) — identify the file as assembly
- a text reader / grep against the `.s` source
- a tiny `re` script to collect the `cmpb` constants

---

## Takeaways

- **Check `file` on everything.** A "binary" may be straight-up source
  (`-S` assembly), which turns hard reversing into copy-paste.
- **When the check is `cmp byte, constant`, recover the flag without
  solving anything** — it's a plaintext table lookup in disguise.
- Look for the classic tell-tale: `operator[]` + immediate comparison =
  keyed-by-index byte check.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)