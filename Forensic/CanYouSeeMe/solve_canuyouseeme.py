#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAN YOU SEE ME  -  FlagYard Forensics Solver

Hard / Forensics

"An attacker exploited a SQL injection to steal credentials — you can see
the traffic, but the data is hidden in a blind channel."

The attacker ran sqlmap (User-Agent: sqlmap/1.8.8) against
DVWA "SQL Injection (Blind)" and dumped dvwa.users **blindly**:
the app never prints data, it only answers TRUE ("User ID exists in the
database.") or FALSE ("User ID is MISSING from the database.").

Every character of the stolen table was leaked via probes of the shape:

    id=1 AND ORD(MID((SELECT IFNULL(CAST(password AS NCHAR),0x20)
                      FROM dvwa.users ORDER BY `user` LIMIT 2,1),7,1))>102

'ORD(MID(...,N,1))>X' is TRUE iff the ASCII code of char N is > X.

All 5,395 request/response pairs are logged in apache2/modsec_audit.log
(ModSecurity audit sections -A- / -B- / -C- / -E-).

Attack:

    1. Split the audit log into entries at each '--<id>-A--' section.
    2. From each -C- body take the URL-decoded 'id' parameter (the payload)
       and parse position N + threshold X from ORD(MID((SELECT ...,N,1))>X.
    3. From each -E- response body mark the probe TRUE if the page says
       "User ID exists in the database.", else FALSE.
    4. For every (query, position): character = max(TRUE threshold) + 1.
    5. Re-assemble every dumped string; the flag was split across the
       'password' rows of users 'etoo' and 'etoo16' -> join them.

Target is the folder that contains apache2/modsec_audit.log
(default: the 'apache2' folder next to this script).
"""
from __future__ import annotations

import collections
import re
import sys
import time
from pathlib import Path

import urllib.parse

DEFAULT_DIR = Path(__file__).resolve().parent / "apache2"
EXISTS = "User ID exists in the database."

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
    for t in ("C A N   Y O U   S E E   M E   S O L V E R",
              "blind SQLi logs -> rebuild stolen data -> flag"):
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

def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)

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
          ("Can You See Me - SAFCSP", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - Web Log Analysis", C.DIM + C.GRAY, "")])
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
              "etoo + etoo16 join -> flag (blind oracle)"):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# log parsing
# ---------------------------------------------------------------------------
MARKER = re.compile(r"^--[0-9a-fA-F]+-A--$", re.M)
PROBE = re.compile(r"ORD\(MID\(\(SELECT (.+?)\),(\d+),1\)\)>(\d+)")

def normq(q):
    return re.sub(r"\s+", " ", q).strip()

def load_audit(path):
    data = (path / "modsec_audit.log").read_bytes().decode("latin1")
    bounds = [m.start() for m in MARKER.finditer(data)]
    bounds.append(len(data))
    probes = collections.defaultdict(dict)
    seen = 0
    for i in range(len(bounds) - 1):
        block = data[bounds[i]:bounds[i + 1]]
        body = re.search(r"^--[0-9a-fA-F]+-C--\n(.*?)(?=\n--[0-9a-fA-F]+-)",
                         block, re.S | re.M)
        resp = re.search(r"^--[0-9a-fA-F]+-E--\n(.*?)(?=\n--[0-9a-fA-F]+-)",
                         block, re.S | re.M)
        if not body:
            continue
        m = re.search(r"id=([^&]*)", body.group(1))
        if not m:
            continue
        payload = urllib.parse.unquote(m.group(1))
        mq = PROBE.search(payload)
        if not mq:
            continue
        key = normq(mq.group(1))
        pos, thr = int(mq.group(2)), int(mq.group(3))
        truth = None
        if resp:
            truth = EXISTS in resp.group(1)
        if truth is not None:
            probes[key].setdefault(pos, []).append((thr, truth))
            seen += 1
    return probes, seen, len(bounds) - 1

def reconstruct(vals):
    out = []
    for pos in sorted(vals):
        trues = [t for t, b in vals[pos] if b is True]
        out.append(chr(max(trues) + 1) if trues else "?")
    return "".join(out)

def build_rows(probes):
    rows = collections.defaultdict(dict)
    for key in probes:
        s = reconstruct(probes[key])
        m = re.search(r"CAST\((\S+) AS NCHAR\).*?LIMIT (\d+),1", key)
        if m:
            col, lim = m.group(1).strip("`"), int(m.group(2))
            rows[col][lim] = s
    return rows

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(dirpath):
    path = Path(dirpath)
    step("parsing modsec_audit.log")
    probes, seen, blocks = load_audit(path)
    if not probes:
        fail("no blind-SQLi probes found in %s" % path)
        return None
    ok("audit entries: %d | ORD(MID(...)) probes recovered: %d" % (blocks, seen))
    ok("unique queried values (columns x rows): %d" % len(probes))

    step("grouping by (query, position) and rebuilding strings")
    rows = build_rows(probes)
    usernames = rows.get("user", {})
    order = sorted(usernames.keys()) if usernames else range(len(rows.get("password", {})))
    ok("rebuilt dvwa.users (%d rows)" % len(order))

    step("reassembling stolen credentials table")
    print()
    hdr = ("  %-10s %-8s %-9s %-10s %s"
           % (C.BOLD + "user", "user_id", "first", "last", "password" + C.RESET))
    print(hdr)
    print("  " + "-" * 66)
    for lim in order:
        u = usernames.get(lim, "?")
        print("  %-10s %-8s %-9s %-10s %s%s%s"
              % (C.CYAN + u + C.RESET,
                 rows.get("user_id", {}).get(lim, "?"),
                 rows.get("first_name", {}).get(lim, "?"),
                 rows.get("last_name", {}).get(lim, "?"),
                 C.GREEN, rows.get("password", {}).get(lim, "?"), C.RESET))
    print()

    step("joining flag halves in the password column")
    pw = "".join(rows.get("password", {}).get(lim, "")
                 for lim in order)
    m = re.search(r"[A-Za-z]+\{[0-9a-fA-F]{32}\}", pw)
    if m:
        return m.group(0)
    for lim in order:
        p = rows.get("password", {}).get(lim, "")
        if "{" in p:
            return p.strip()
    return None

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    if len(sys.argv) > 1:
        base = Path(sys.argv[1])
    else:
        base = DEFAULT_DIR
    step("log folder %s" % base)

    flag = exploit(base)
    if flag and flag.startswith("FlagY"):
        ok("FLAG = %s" % flag)
        big_flag(flag, time.time() - t0)
        outp = Path(__file__).resolve().parent / "flag_from_canuyouseeme.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail("flag not recovered")

if __name__ == "__main__":
    main()