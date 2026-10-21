# FlagYard CTF — PongPing

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) • **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) • **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) • **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP — challenge by VoidMercy
- **Category:** Reversing
- **Difficulty:** Medium
- **Target:** `pingpong` — stripped x86-64 PIE ELF implementing a Befunge-like 2D stack VM, plus `flagchecker` — a 903,458-byte text maze that is the VM's *program*.

> *The flag is not in the binary — the binary is a CPU, and the maze is the code.*

---

## The flag

```
FlagY{p1ng_p0ng_d1ng_d0ng_th1s_15_7h3_fl4g!}
```

---

## The short version

`pingpong` is a pure interpreter. It reads a `Width`/`Height`, reads that many
grid rows raw from stdin, and runs the bytes as a Befunge-like program (IP from
`(0,0)` heading right, two int32 stacks, `@` halts, `.` pops+prints low byte,
`;` does `scanf("%d")`, `>` skips the next cell **iff** stack top `> 0`). A full
I/O audit shows the ELF has **zero flag data** — every printed byte derives from
input. The real challenge is the second file, which is exactly one maze:

```
903458 = 194 rows x (4656 chars + 1 newline)   ->   W = 4657, H = 194
```

The maze's default path prints a **troll flag** — `FlagY{th1s\x00fl4g\x001s\x00a\x00f4k3...}`,
"this flag is a fake". Every `>` is a **two-way gate**, so we BFS the decision
space (`S` = skip / `D` = don't) across the 194-row maze. Of **14,638** halting
runs, exactly **one** prints a 44-char `FlagY{...}` shell:

```
FlagY{p1ng\x00p0ng\x00d1ng\x00d0ng\x00th1s\x0015\x007h3\x00fl4g\x00}
```

The 8 `\x00`s are **slot units** whose characters are read from stdin (`;` → 0 on
EOF). Tracing the flag path, the cells directly behind every NUL-printing `.`
are seven `_` units and one `!` unit — the op-codes *are* the missing characters.
Patching the three winning gates `>`→`#` (unconditional skip) and feeding the
**unmodified binary** `"4657 194\n" + flagchecker` prints the shell byte-for-byte
(`rc=0`), and filling the wildcards gives the flag.

---

## Step-by-step

### 1. Triage — there is a second file

`checksec` on `pingpong`: Full RELRO, NX, PIE, canary. Imports are **only**
`read`, `write`, `malloc`, `realloc`, `scanf`, `__printf_chk`, `setvbuf`, `exit`
— no `open`, no `fopen`, no network. `.rodata` holds just `"Width? "`, `"Height? "`,
`"%u"`, `"%d"`. `main` is tiny:

1. `printf("Width? ")` → `scanf("%u", &W)`
2. `printf("Height? ")` → `scanf("%u", &H)`
3. `grid = malloc(W*H)`; `read(0, grid + i*W, W)` × H rows (return value ignored)
4. `run(grid, vm)` — and never returns anything controllable

A syscall-level trace (`LD_PRELOAD`) confirms the same flow, plus `,` =
`read(0,&c,1)` and `.` = `write(1,&c,1)` inside the VM loop. So the program is a
pure function of stdin: **the flag must be a grid we were supposed to feed it.**
The lab ships a second file, `flagchecker` — a 903,458-byte text file that fits a
Befunge grid exactly: `903458 = 4657 × 194`.

### 2. The VM

Decoded from the two dispatcher jump tables (~62 handlers), a Befunge-family
esolang with those quirks that matter:

- default cells push their byte value; `@` halts; `>`/`<`/`=` skip-next **iff** top `>0`/`<0`/`==0`
- `.`/`:` pop → `write(1, low byte)` / `printf("%d")`
- `;` → `scanf("%d")` (schrader: 0 on EOF), `#` unconditional skip, `\`/`/`/`_`/`|` mirrors
- `0x01` self-write, `?`/`!` grid load/store, `]`/`[` jumps, `$` push-next sign-ext
- **no bounds checking, no wrap** — leaving the grid reads heap garbage (crashes)

### 3. The maze

`flagchecker` is 194 self-printing units, each shaped `X . ; \x01 - > \` marching
**+24 columns per row** (`X` = payload letter, digit, or `F Y { } _ !`). The
default walk printed the troll:

```
$ printf '4657 194\n' + flagchecker | ./pingpong
FlagY{th1s\x00fl4g\x001s\x00a\x00f4k3\x00fl4g\x00t00\x00b4d\x00f0r\x00you\x00}
```

"this flag is a fake flag too bad for you" — 48 bytes, the red herring. The units
are steered by gates: `>` skips the next cell iff top-of-stack `> 0`. Row 5 is a
junction where descending points lead to troll / `d` / `a` / `p1ng` / `t`
territories.

### 4. BFS the gate decisions

Every gate = a binary decision (`S` skip / `D` straight). Enumerate the decision
space depth-first with a simulation per decision set, dedupe on
`(position, direction, output)`, keep every `HALT`. Result: **14,638 distinct
halting runs**, and among all outputs **exactly one** is a 44-char `FlagY{…}`:

```
FlagY{p1ng\x00p0ng\x00d1ng\x00d0ng\x00th1s\x0015\x007h3\x00fl4g\x00}
  -> gates that must SKIP: (5,125), (5,129), (5,133)
```

("p1ng p0ng d1ng d0ng th1s 15 7h3 fl4g" — 37 chars + `FlagY{` + `}` = 44).

### 5. Fill the wildcards

The 8 `\x00`s are slot units: room cells are read via `;` (`scanf`), and with
closed stdin they collapse to 0. On the flag path the cell directly *behind*
each NUL-printing `.` is traced — seven `_` units and one `!` unit. The unit's
op-code is the intended character:

```
slot units in path order:  _ _ _ _ _ _ _ !
FlagY{p1ng_p0ng_d1ng_d0ng_th1s_15_7h3_fl4g!}
```

Length = 44 ✓ (the challenge hint was a checksum).

### 6. Proof on the real binary

Trust but verify — patch the three gates `(5,125)`, `(5,129)`, `(5,133)` from
`>` (0x3E) to `#` (0x23, unconditional skip) and run the **unmodified**
`pingpong` with `"4657 194\n"` + patched flagchecker:

```
rc=0   output = FlagY{p1ng\x00p0ng\x00d1ng\x00d0ng\x00th1s\x0015\x007h3\x00fl4g\x00}   (44 B, exact)
```

The interpreter physically walks the path; the shell is not a model artifact.

---

## Solver

`solve_pongping.py` — pure Python 3 (stdlib only): parses `flagchecker`,
BFSes the gate decision space, derives the wildcards, patches the three gates,
runs the real binary as the final oracle and saves `flag_from_pongping.txt`.

```
python solve_pongping.py
```

```
  ╔══════════════════════════════════════════════════════════╗
  ║              P O N G P I N G   S O L V E R               ║
  ║    BFS over 194x4657 gate maze: gates -> 44-char flag    ║
  ╚══════════════════════════════════════════════════════════╝
  [ 15.0%] ✓ grid geometry 903458 = 194 x 4657  ->  W=4657, H=194
  [ 85.0%] ✓ 14,638 halting runs enumerated - one 44-char shell found
  gates to skip: [(5, 125), (5, 129), (5, 133)]
  [ 91.0%] ✓ slot units on flag path = '_______!'  ->  wildcard chars
  [ 97.0%] ✓ real binary rc=0, output == shell (44 bytes)

  ╔══════════════════════════════════════════════════════════╗
  ║                   ★  FLAG RECOVERED  ★                   ║
  ║      FlagY{p1ng_p0ng_d1ng_d0ng_th1s_15_7h3_fl4g!}        ║
  ╚══════════════════════════════════════════════════════════╝
```

---

## Tools

- `checksec` / `readelf` / `objdump` — import table, `.rodata`, dispatcher tables
- `LD_PRELOAD` syscall tracer — confirm read/write/scanf flow
- `solve_pongping.py` — decision-space BFS + wildcard fill + binary verification

---

## Takeaways

- **"One file" is an assumption, not a fact.** The flag was never in the ELF and
  never on a server — it was in the second shipped file. Re-audit what you think
  you know.
- **Constrain by output shape first.** 14,638 executable paths collapse to one
  candidate with a 44-char `FlagY{…}` filter.
- **Self-printing mazes are branch bombs.** A handful of conditional gates over
  194 rows explodes into thousands of outputs — enumerate the gate decisions,
  not the grid bytes.
- **Authors hide hints in structure.** Seven `_` units and one `!` unit *are* the
  seven underscores and the exclamation mark; the wildcard characters are the
  op-codes themselves.
- **Verify on the real binary.** Patching gates to `#` and re-running the
  unmodified program turns the emulator's answer into a physical proof.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)
- **Reference:** public solver scripts used to cross-validate the gate-BFS
  (indrajith11/flagyard-ctf-writeups-) — [PongPing](https://github.com/indrajith11/flagyard-ctf-writeups-/tree/main/PongPing)