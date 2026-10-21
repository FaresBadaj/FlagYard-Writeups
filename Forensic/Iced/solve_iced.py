#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICED  -  FlagYard Forensics Solver

Hard / Forensics

"The attacker successfully gained access to a target machine. The attacker
utilized a legitimate Windows binary to drop malicious code, evading
traditional security measures. Additionally, the attacker employed
obfuscation techniques to further conceal the malicious activity, making
detection and analysis more challenging."

A KAPE-style collection (AppData + Prefetch) of the victim's Windows box,
user "Marwan Elshafei".

Footprint of the breach:

    * prefetch/CERTUTIL.EXE-28F1E0C1.pf ... certutil ran on the box
      (a legitimate, signed Windows binary - the "LOLBin" of the story)
    * AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\   ... certutil's
      download cache - it keeps the UNMODIFIED bytes of every URL it grabs
    * AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\  ... cached
      browsing of the attacker's GitHub repo
    * Notepad++ session.xml points at downloader.html / install.ps1

The URL cache metadata discloses the two downloaded payloads (both hosted
on the attacker's GitHub repo  Marwan18/API ):

    https://raw.githubusercontent.com/Marwan18/API/main/secret.ps1
    https://raw.githubusercontent.com/Marwan18/API/main/exfiltration.ps1

Both scripts are PowerShell one-liners hidden behind classic obfuscation
(string-fragment shuffle with  ("{N}..." -f 'a','b',...), 'Cvx' -> "'",
char arithmetic  j+Y+O -> '"', base64 -> [Convert]::FromBase64String and
[System.Text.Encoding]::Unicode.GetString, executed with IEX).

Recovering them:

    1. resolver: find every payload cached under CRYPTNET + INetCache.
    2. un-shuffle: rebuild the literal built by  -f <fragments>.
    3. un-quote:   replace 'Cvx' with "'" and the jYO marker with '"'.
    4. un-base64:  pull the argument of FromBase64String, decode it,
                   try UTF-16LE / UTF-8 / Latin-1.
    5. flag:       the $flag = "..." assignments drop the secret;
                   secret.ps1  -> "FlagY{...}"   (VALUE FLAG)
                   exfiltration.ps1 -> "FLAGY{...}"  (DECOY, wrong case)

Target is the challenge folder (default: the folder of this script).
"""
from __future__ import annotations

import base64
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# coloured output (same design as the other FlagYard solvers)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GRAY = "\033[90m"
    WHITE = "\033[97m"

def enable_vt():
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            mode = ctypes.c_uint()
            h = k32.GetStdHandle(-11)
            k32.GetConsoleMode(h, ctypes.byref(mode))
            k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def bar(frac):
    w = 20
    f = max(0.0, min(1.0, frac))
    full = int(round(f * w))
    return "[%s%s] %5.1f%%" % ("\u2588" * full, "\u2591" * (w - full), f * 100.0)

def step(msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s%s%s" % (C.BOLD + color + icon + " ",
                             C.DIM, C.BOLD, msg, C.RESET), flush=True)

def ok(msg):
    step(msg, icon="\u2713", color=C.GREEN)

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("I C E D   S O L V E R",
              "LOLBin drop -> obfuscated payloads -> flag"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel + author credits
# ---------------------------------------------------------------------------
W = 58

def _row(segs):
    out = "  \u2551"
    for t, pre, post in segs:
        if pre:
            out += pre + t + (post or "") + C.RESET
        else:
            out += t
    out += " " * max(0, W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

_TG = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"

def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("General", C.BOLD + C.WHITE, "")])
    _row([("   FlagYard CTF  |  Lab Training Write-ups", C.DIM + C.CYAN, "")])
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   Telegram  \u203a  ", "", ""),
          ("@ptok3", _osc("https://t.me/ptok3", _TG), _OSC_END),
          ("      t.me/ptok3", C.DIM + C.GRAY, "")])
    _row([("   GitHub    \u203a  ", "", ""),
          ("github.com/FaresBadaj", _osc("https://github.com/FaresBadaj", "\033[1;36m"), _OSC_END)])
    _row([("   LinkedIn  \u203a  ", "", ""),
          ("linkedin.com/in/FaresBadaj", _osc("https://www.linkedin.com/in/FaresBadaj", "\033[1;34m"), _OSC_END)])
    _row([("   Credly    \u203a  ", "", ""),
          ("credly.com/users/faresbadaj", _osc("https://www.credly.com/users/faresbadaj", "\033[1;33m"), _OSC_END)])
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   Forensics  \u203a  ", "", ""),
          ("Iced - SAFCSP", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - LOLBin / Cached Payloads", C.DIM + C.GRAY, "")])
    print("  " + "\u255a" + "\u2550" * W + "\u255d")


def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)

def big_flag(flag, chrono):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono,
              "secret.ps1 = flag | exfiltration.ps1 = decoy"):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# payload discovery
# ---------------------------------------------------------------------------
def _text(path):
    return path.read_bytes().decode("latin1", errors="replace")

def find_payloads(folder: Path):
    hits = {}
    pats = ["**/CryptnetUrlCache/Content/*",
            "**/INetCache/IE/**/*.ps1"]
    for pat in pats:
        for p in folder.glob(pat):
            try:
                if p.stat().st_size <= 0:
                    continue
            except OSError:
                continue
            t = _text(p)
            if ("Cvx" in t and "-f" in t) or ("'iex" in t and "FromBa" in t):
                hits[str(p).lower()] = p
    return sorted(hits.values(), key=lambda p: p.stat().st_size)

# ---------------------------------------------------------------------------
# deobfuscation
# ---------------------------------------------------------------------------
def _secret_from_b64(b64: str):
    b64 = b64.strip()
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    raw = base64.b64decode(b64)
    for enc in ("utf-16-le", "utf-8", "latin1"):
        try:
            t = raw.decode(enc)
        except Exception:
            continue
        for m in re.finditer(r"[A-Za-z]+Y\{[0-9a-fA-F]{32,}\}", t):
            yield m.group(0)

def deob_v1(data: str):
    """ (("{N}..." -f 'f1',...)).rEPLacE('Cvx',[char]39) | iex  (secret.ps1) """
    m = re.search(r'\(\(\s*"(.*?)"\s*-\s*f\s*', data, re.S)
    if not m:
        return None
    tpl = m.group(1)
    rest = data[m.end():]
    try:
        stop = rest.index("'))") + 1
    except ValueError:
        return None
    args = re.findall(r"'([^']*)'", rest[:stop])
    if len(args) < 2:
        return None
    built = tpl.format(*args)
    s1 = built.replace("Cvx", chr(39))
    try:
        start = s1.index("iex (") + len("iex (")
        end = s1.rindex("')")
    except ValueError:
        return None
    cmd = s1[start:end].replace("'+'", "").replace("jYO", '"')
    return cmd

def deob_v2(data: str):
    """ (('iex '+'...'+'{0}...')-f[cHAR]34) | &( $SheLLid... )  (exfiltration.ps1) """
    if "FromBa" not in data or "'iex" not in data:
        return None
    toks = re.findall(r"'([^']*)'", data)
    joined = "".join(toks).replace("{0}", chr(34))
    return joined

def secrets_from(data: str):
    cmd = deob_v1(data) or deob_v2(data)
    if not cmd:
        return []
    m = re.search(r'FromBase64String\(\s*"([^"]+)"\s*\)', cmd)
    if not m:
        return []
    return list(dict.fromkeys(_secret_from_b64(m.group(1))))

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(folder):
    folder = Path(folder)
    step("searching for cached payloads (CryptnetUrlCache + INetCache)")
    payloads = find_payloads(folder)
    if not payloads:
        fail("no obfuscated payload found under %s" % folder)
        return None
    ok("obfuscated payloads found: %d" % len(payloads))

    step("de-obfuscating PowerShell drop/stage-2 scripts")
    flags = []
    seen = set()
    for p in payloads:
        t = _text(p)
        sec = secrets_from(t)
        if not sec:
            continue
        rel = str(p).replace(str(folder), "").lstrip("\\/")
        for s in sec:
            if s in seen:
                continue
            seen.add(s)
            real = s in ("FlagY{" + re.search(r"[0-9a-fA-F]{32}", s).group(0) + "}",)
            print("   %s%c %-48s -> %s%s%s"
                  % (C.GREEN if s.startswith("FlagY{") else C.RED,
                     "\u2713" if s.startswith("FlagY{") else "!",
                     rel, s, "   (decoy)" if not s.startswith("FlagY{") else "",
                     C.RESET))
            flags.append(s)
    if not flags:
        fail("no secret recovered")
        return None

    step("picking the real flag (FlagY{...} - correct casing)")
    for s in flags:
        if re.fullmatch(r"FlagY\{[0-9a-fA-F]{32}\}", s):
            return s
    return None

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    step("challenge folder %s" % base)

    flag = exploit(base)
    if flag:
        ok("FLAG = %s" % flag)
        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_iced.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail("flag not recovered")

if __name__ == "__main__":
    main()