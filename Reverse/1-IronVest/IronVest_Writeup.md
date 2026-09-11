# FlagYard CTF — IronVest

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Reversing
- **Difficulty:** Easy (سهل)

> *"I believe we've built a strong defensive design—no one should be able to jump to the hidden places."*

---

## The flag

```
FlagY{7b4e3a2c1d8f9e0a5b6c7d8e9f0a1b2c}
```

---

## First look

`IronVest.exe` is a tiny 15 KB Windows PE (x64, C++ / Visual Studio Release build — the PDB path inside even leaks the original project folder: `...\Reverse\Easy\1\One1\x64\Release\One1.pdb`).

At runtime it plays a little game — it asks for a number between `0` and `255`, gives you a few attempts, and counts them down:

```
Enter a number (0-255):
Wrong answer! Attempts remaining: %d
Too many failed attempts. Challenge failed.
```

And it's wrapped in what looks like serious "armor", which is exactly what the description brags about:

- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- `CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW` — walks running processes (looking for debuggers)
- `GetThreadContext` — tamper detection
- `GetTickCount` — timing checks

Killed the debugger, thought the flag was safe… **but the flag is sitting in plaintext inside the binary.**

---

## The whole trick

A single `strings` pass on `IronVest.exe` and the "hidden place" shows itself immediately:

```
Your flag is: %s
Welcome!!
Access denied.
Enter a number (0-255):
...
FlagY{7b4e3a2c1d8f9e0a5b6c7d8e9f0a1b2c}
```

No packing, no encryption, no obfuscation. A 64-bit, anti-debug-hardened executable whose secret is stored as a readable ASCII literal in `.rdata`.

**Root cause:** anti-debugging is "iron" on the outside, but the flag handling never touches the crypto or the protection logic. Defence layers protect the *flow* of the program; they do nothing to hide a constant that is embedded verbatim in the data section.

---

## Takeaways

- **Strings are always the first step.** For an "Easy" reverse challenge, half the game is knowing that the flag has to live somewhere in the binary — and ASCII strings are the easiest place to look.
- **Anti-debug ≠ anti-strings.** `IsDebuggerPresent` blocks a debugger, not a passive scan of the file.
- **Hint decoding:** *"no one should be able to jump to the hidden places"* — the "hidden places" refer to the exotic code paths (easter eggs, extra "hidden" checks you'd only reach with clever jumping). But the flag was never hidden there; it was in plain sight.

```
strings IronVest.exe | grep -i flagy
FlagY{7b4e3a2c1d8f9e0a5b6c7d8e9f0a1b2c}
```