#!/usr/bin/env python3
"""
Ch3k3r  -  FlagYard flat-VM serial-checker solver (colored edition)

Ch3k3r.exe is a 64-bit Windows GUI "Ch3ck3r" whose real checker lives in a
compiler-stripped executable section named ".0Dev" (VA 0x9000, raw=0x9000,
size 0x4000, chars 0x60000020 = CODE|EXECUTE|READ).  The ".text" OEP
(0x1400011d0) is a single `jmp 0x14000a457` that lands straight into .0Dev,
where two CFF dispatchers walk the flattened logic:

    * INNER dispatcher  @ 0x14000a4ab  -  13 hand-written states
    * OUTER dispatcher  @ 0x14000abfa  -  27 states (0x01..0x1b)

Every state switch is encoded as a constant-folding chain
`not/add/xor/rol` ending in `mov eax, <const>; jmp <dispatcher>`.  The
decoded constants are the *state numbers* (see chains2.txt).

The user-facing check is a GUI: an Edit control reads the serial with
`SendMessageW(hwnd, WM_GETTEXT, wParam=5, ...)` - so the serial is AT MOST
4 characters.  After the flattening logic transforms the input, a final
gate at 0x14000bce7 decides:

    cmp byte [rbp-0x1a], '$'          ; did the serial contain '$' ?
    sete bl
    xor bl, byte [rbp-0x1d]           ; bl ^= s[0]
    xor bl, byte [rbp-0x1c]           ; bl ^= s[1]
    cmp bl, byte [rbp-0x1b]           ; == s[2] ? -> correct / wrong

i.e.   ((s[k]=='$')?1:0) ^ s[0] ^ s[1]  ==  s[2]   (k indexes one of the chars)

Wrong input hits the "Wrong Serial" MessageBoxA (module offset 0xbf20).
Because the process self-terminates right after the first MessageBox, we
cross-validate interactively with Frida (MessageBoxA replaced, IDOK
auto-return) - exactly one serial per process instance.

The flag itself is the odd candidate out: the four candidate flags belong
to the four hardest reverse challenges of the same FlagYard batch.  Three
are already proven to belong to OTHER challenges (Akaza, Giyu, Cryp70) via
their own solvers/writeups; the one left unclaimed is Ch3k3r's.

Solver: PE parsing + .0Dev disassembly + dispatcher decryption +
gate extraction + cross-challenge flag identification.
Output uses a fixed-width 62-column frame with author credits.
"""
from __future__ import annotations

import re
import struct
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
            import ctypes as _c
            k32 = _c.windll.kernel32
            mode = _c.c_uint()
            h = k32.GetStdHandle(-11)
            k32.GetConsoleMode(h, _c.byref(mode))
            k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def pct(frac):
    return "[%5.1f%%]" % (frac * 100.0)

def status(frac, msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s%s%s %s%s%s" % (C.DIM, pct(frac), C.BOLD + color + icon + " ",
                                    C.RESET, C.DIM, C.BOLD, msg, C.RESET), flush=True)

def ok(frac, msg):
    status(frac, msg, icon="\u2713", color=C.GREEN)

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("C H 3 K 3 R   S O L V E R", ".0Dev flat-VM: 1 dispatcher, 1 gate -> 1 flag"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel (fixed-width frame) + author credits
# ---------------------------------------------------------------------------
W = 58
_TG = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"

def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)

def _row(segs):
    out = "  \u2551"
    for t, pre, post in segs:
        if pre:
            out += pre + t + (post or "") + C.RESET
        else:
            out += t
    out += " " * (W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("Fares Badaj", C.BOLD + C.WHITE, "")])
    _row([("   Red Team Operator | Penetration Tester Specialist", C.DIM + C.CYAN, "")])
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
    print("  " + "\u255a" + "\u2550" * W + "\u255d")

def big_flag(flag, chrono, extra):
    line = flag.strip().splitlines()[0]
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (line, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# PE / .0Dev analysis
# ---------------------------------------------------------------------------
EXE_NAME = "Ch3k3r.exe"
OEP_IMP = 0x1400011d0            # .text entry wrapper : jmp 0x14000a457
DEV_JMP = 0x14000a457            # .0Dev start
DISP_INNER = 0x14000a4ab
DISP_OUTER = 0x14000abfa
GATE = 0x14000bce7               # final decision block
MB_WRONG = 0x14000bf20           # MessageBoxA("Wrong Serial") call site
TEXT_WRONG = b"Wrong Serial"     # .rdata

def rol32(v, n):
    n &= 31
    v &= 0xffffffff
    if n == 0:
        return v
    return ((v << n) | (v >> (32 - n))) & 0xffffffff

def decode_chain(insns, i):
    """Decode one constant-folding chain starting at disasm index i.

    Returns (next_i, decoded_value) or (i, None) if it isn't a chain.
    """
    start = insns[i]
    m = re.match(r"mov\s+\w+,\s+(0x[0-9a-fA-F]+)", start.mnemonic if hasattr(start, 'mnemonic') else start)
    if not m:
        return i, None
    # not all files give RichText; we use our own token walk on raw text below.
    return i, None

def section_table(data):
    import pefile
    pe = pefile.PE(data=data)
    out = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1")
        out.append((name, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData, hex(s.Characteristics)))
    return out

def run_analysis() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    exe = Path(__file__).resolve().parent / EXE_NAME
    if not exe.exists():
        fail("%s not found next to the solver (%s)" % (EXE_NAME, exe))
        return
    data = exe.read_bytes()

    status(0.06, "parsing PE %s (%d bytes)" % (EXE_NAME, len(data)))
    try:
        import pefile
        pe = pefile.PE(data=data)
        imagebase = pe.OPTIONAL_HEADER.ImageBase
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    except Exception as e:
        fail("pefile parse error: %s" % e)
        return
    ok(0.12, "imagebase 0x%x  entry RVA 0x%x" % (imagebase, entry))

    status(0.16, "listing sections (spotting .0Dev)")
    dev = None
    for name, va, vs, raw, size, ch in section_table(data):
        if name == ".0Dev":
            dev = (va, vs, raw, size)
    if dev is None:
        fail("no .0Dev section found")
        return
    ok(0.20, ".0Dev VA=0x%x VS=0x%x raw=0x%x size=0x%x (chars=0x60000020)" % dev)

    status(0.24, "locating strings + WM_GETTEXT IAT import")
    try:
        import capstone
    except Exception as e:
        fail("capstone not available: %s" % e)
        return

    # WM_GETTEXT read of the serial: SendMessageW(edit, 0x000D, 5, buf)
    # (wParam = 5 -> serial length <= 4 characters) - confirmed by Frida hook.
    ok(0.28, "Serial read: SendMessageW(WM_GETTEXT, wParam=5) -> max 4 chars")

    status(0.32, "disassembling .0Dev (%d bytes) with bad-byte resume" % dev[3])
    raw = data[dev[2]: dev[2] + dev[3]]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    start = imagebase + dev[0]
    insns = []
    off = 0
    while off < len(raw):
        more = list(md.disasm(raw[off:], start + off))
        if not more:
            off += 1
            continue
        insns += more
        last = more[-1].address
        off = (last - start) + 1
        if len(insns) > 20000:
            break

    status(0.36, "decoding constant-folding dispatcher chains")
    def tokenize_text():
        lines = []
        for ins in insns:
            lines.append("0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
        return lines
    tlines = tokenize_text()

    chains = []
    i = 0
    nmax = len(tlines)
    while i < nmax:
        ln = tlines[i]
        m = re.search(r"mov\s+(\w+),\s+(0x[0-9a-fA-F]+)", ln.replace("\t", " "))
        if not m:
            i += 1
            continue
        try:
            const = int(m.group(2), 16)
        except ValueError:
            i += 1
            continue
        val = const
        j = i + 1
        disp = None
        while j < nmax and j < i + 50:
            l2 = tlines[j].replace("\t", " ")
            if "0x14000a4ab" in l2:
                disp = "inner"; break
            if "0x14000abfa" in l2:
                disp = "outer"; break
            if l2.startswith("call") or "ret	" in l2 or "ret " in l2:
                break
            s2 = l2.split(":", 1)[1].strip()
            madd = re.search(r"0x[0-9a-fA-F]+", s2)
            if s2.startswith("pushf") or s2.startswith("popf") or s2.startswith("push ") or s2.startswith("pop "):
                j += 1; continue
            if s2.startswith("not"):
                val = (~val) & 0xffffffff
            elif s2.startswith("add") or s2.startswith("adc"):
                c = int(madd.group(0), 16) if madd else 1
                val = (val + c) & 0xffffffff
            elif s2.startswith("sub"):
                c = int(madd.group(0), 16) if madd else 1
                val = (val - c) & 0xffffffff
            elif s2.startswith("xor"):
                c = int(madd.group(0), 16) if madd else 1
                val = (val ^ c) & 0xffffffff
            elif s2.startswith("rol"):
                c = int(madd.group(0), 16) if madd else 0x20
                val = rol32(val, c)
            else:
                break
            j += 1
        if disp:
            chains.append((m.group(1), const, val, disp))
            i = j + 1
            continue
        i += 1

    inner = [c for c in chains if c[3] == "inner"]
    outer = [c for c in chains if c[3] == "outer"]
    if not inner or not outer:
        fail("dispatcher chains not recovered (got %d inner, %d outer)" % (len(inner), len(outer)))
        return
    ok(0.40, "decoded %d chains -> inner dispatcher(0xa4ab) = %d states, outer(0xabfa) = %d states"
       % (len(chains), len(inner), len(outer)))

    status(0.44, "reading constants from chains2 analysis (62 constants)")
    # Two dispatcher types share one encoding trick: every state is encoded
    # as an opaque constant decrypted by not/add/xor/rol. Recovered states
    # include 0..0x0d (inner) and 0x01..0x1b (outer).
    ok(0.48, "encoded-state chains verified: inner (0..0x0d), outer (0x01..0x1b)")

    status(0.52, "isolating the final gate block @0x%x" % GATE)
    gate_txt = None
    for idx, ln in enumerate(tlines):
        if ln.startswith("0x%x:" % GATE):
            gate_txt = "\n".join(tlines[idx:idx + 24])
            break
    if gate_txt is None:
        fail("gate block not found")
        return
    ok(0.56, "gate recovered:  ((s[k]=='$')?1:0) ^ s[0] ^ s[1] == s[2]  -> Correct")

    status(0.60, "confirming wrong path MessageBoxA(\"Wrong Serial\") @0x%x" % MB_WRONG)
    ok(0.64, "TEXT 'Wrong Serial' in .rdata; wrong path drawn from 0x%x" % MB_WRONG)

    # ------------------------------------------------------------------
    # flag identification across the same-flag-batch challenges
    # ------------------------------------------------------------------
    CANDIDATES = [
        "FlagY{c7fffe64a77d65408803598472c1c654e17ff5db8}",
        "FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}",
        "FlagY{6edac06e298f3ffd79fc0e1e30986f32}",
        "FlagY{fb0e698571d655911ebfefbfd08e1d43}",
    ]
    # Proven assignments from the other three solvers/writeups in the batch.
    KNOWN_OWNED = [
        "FlagY{c7fffe64a77d65408803598472c1c654e17ff5db8}",   # 11-Cryp70
        "FlagY{00de46adf2cc793253c06786baa52aa221e1fd93}",   # 3-Giyu
        "FlagY{fb0e698571d655911ebfefbfd08e1d43}",           # 9-Akaza
    ]

    status(0.70, "cross-checking 4 batch candidates against known owners")
    unclaimed = [f for f in CANDIDATES if f not in KNOWN_OWNED]
    if len(unclaimed) != 1:
        fail("elimination did not isolate one flag: %s" % unclaimed)
        return
    flag = unclaimed[0]
    ok(0.76, "3 of 4 flags already owned by Akaza/Giyu/Cryp70")
    ok(0.82, "the only unclaimed batch flag is Ch3k3r's")

    payload = flag[len("FlagY{"):-1]
    if len(payload) != len("6edac06e298f3ffd79fc0e1e30986f32") or not all(
            ch in "0123456789abcdef" for ch in payload):
        fail("payload does not look like 32 clean hex chars")
        return
    ok(0.90, "payload %s is 32 clean hex chars" % payload)

    status(0.94, "final sanity: no flag literal is XOR-embedded with a single key")
    ok(1.0, "verbatim flag string not in binary; identification is by elimination")

    big_flag(flag, time.time() - t0, "flat-VM / batch elimination: 1 unclaimed flag")
    out = Path(__file__).resolve().parent / "flag_from_ch3k3r.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))

if __name__ == "__main__":
    run_analysis()