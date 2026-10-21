#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COLLECTOR  -  FlagYard Forensics Solver

Medium / Forensics

"The antivirus has detected multiple files being dropped on the machine.
 We need to identify the downloaded files and retrieve the flag."

The box ships a full Windows event-log export (logs\\*.evtx).  On the
night of 2024-07-24 the machine CASTELBLACK\vagrant ran a PowerShell
bootstrap (AnAn.ps1, PID 6808) that created a burst of BITS transfer
jobs inside a few seconds:

    Microsoft-Windows-Bits-Client/Operational
        Event ID 3   "The BITS service created a new job."

Each job is logged with a tiny piece of metadata:

    Transfer job: X          <- jobTitle (the LOG'S JOKE: one char each)
    Job ID: {...}
    Owner: CASTELBLACK\vagrant
    Process Path: ...\powershell.exe
    Process ID: 6808

The attacker used Windows' own BITS service to smuggle the flag out in
the JOB TITLE field, character by character, so a naive search for
"FlagY" or "Flag" in the messages finds nothing.  The default job is
named "BITS Transfer" (a decoy created with 0 files); every other job
has a single-character title.

Reading the "Transfer job:" line of every Event ID 3 record, in
chronological order, and dropping the default "BITS Transfer" job,
spells the flag:

    F l a g Y { 0 c 0 a 6 d f 5 d 8 8 9 8 1 1 f 5 0 3 f 3 9 9 6 f 7 7 b 5 6 6 0 }

Solver pipeline:

    1. locate logs\Microsoft-Windows-Bits-Client*Operational.evtx
    2. parse events (python-evtx) and keep the Event ID 3 records
    3. read the jobTitle stored in each event's Data section
    4. ignore the default "BITS Transfer" job, join the single chars
    5. validate against  FlagY{32-hex}  and print the flag box

Target is the challenge folder (default: the folder of this script).
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

try:
    from Evtx.Evtx import Evtx as _OpenEvtx
except ImportError:
    _OpenEvtx = None

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

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("C O L L E C T O R   S O L V E R",
              "BITS jobTitle  |  flag hidden in transfer names"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel + author credits
# ---------------------------------------------------------------------------
W = 58

def _row(segs):
    out = "  \u2551"
    for t, pre, post in segs:
        if pre:
            out += pre + t + (post or "") + C.RESET
        else:
            out += t
    out += " " * max(0, W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

_GRAD = "\033[1;38;2;0;136;204m"
_TG = "\033[1;38;2;0;136;204m"
_OSC_END = "\x1b]8;;\x1b\\"

def _osc(url, color):
    return "\x1b]8;;%s\x1b\\%s" % (url, color)

def _credits():
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   made with ", C.GREEN, ""), ("\u2764", "\033[1;31m", ""),
          ("  by  ", C.GREEN, ""), ("General", C.BOLD + C.WHITE, "")])
    _row([("   FlagYard CTF  |  Lab Training Write-ups", C.DIM + C.CYAN, "")])
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
    print("  " + "\u2560" + "\u2550" * W + "\u2563")
    _row([("   Forensics  \u203a  ", "", ""),
          ("Collector - SAFCSP", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - BITS / Log Dusting", C.DIM + C.GRAY, "")])
    print("  " + "\u255a" + "\u2550" * W + "\u255d")


def big_flag(flag, chrono, extra):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# BITS evtx parsing
# ---------------------------------------------------------------------------
_EVENTID_RE = re.compile(r"<EventID[^>]*>\s*(\d+)\s*</EventID>")
_DATA_RE = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
FLAG_RE = re.compile(r"FlagY\{[0-9a-fA-F]{32}\}")

class BitsJob:
    __slots__ = ("title", "job_id", "owner", "process_path", "process_id")

    def __init__(self, title, job_id, owner, process_path, process_id):
        self.title = title
        self.job_id = job_id
        self.owner = owner
        self.process_path = process_path
        self.process_id = process_id

    def __repr__(self):
        return "BitsJob(title=%r)" % self.title

def parse_bits_jobs(evtx_path: Path):
    """Return (jobs, total_records); jobs are Event-ID-3 records in order."""
    jobs = []
    total = 0
    with _OpenEvtx(str(evtx_path)) as log:
        for rec in log.records():
            total += 1
            xml = rec.xml()
            m = _EVENTID_RE.search(xml)
            if not m or m.group(1) != "3":
                continue
            data = dict(_DATA_RE.findall(xml))
            jobs.append(BitsJob(
                title=data.get("jobTitle", ""),
                job_id=data.get("jobId", ""),
                owner=data.get("jobOwner", ""),
                process_path=data.get("processPath", ""),
                process_id=data.get("processId", ""),
            ))
    return jobs, total

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def find_bits_evtx(folder: Path):
    for p in sorted(folder.rglob("*.evtx")):
        if "Bits-Client" in p.name and "Operational" in p.name:
            return p
    return None

def exploit(folder):
    folder = Path(folder)
    step("locating Microsoft-Windows-Bits-Client/Operational log")
    bits = find_bits_evtx(folder)
    if not bits:
        fail("no BITS Client Operational .evtx under %s" % folder)
        return None
    ok("found %s" % bits.relative_to(folder))

    if _OpenEvtx is None:
        fail("python-evtx is required:  pip install python-evtx")
        return None

    step("parsing Event ID 3 records (job created)")

    jobs, total = parse_bits_jobs(bits)
    if not jobs:
        fail("no BITS job-created events")
        return None
    ok("processed %d records, %d job-created events" % (total, len(jobs)))

    owner = jobs[0].owner
    proc = jobs[0].process_path
    pid = jobs[0].process_id
    first = "2024-07-24 18:34:54 UTC"
    last = "2024-07-24 18:35:02 UTC"

    title = [j.title for j in jobs if j.title and j.title != "BITS Transfer"]
    if len(title) != 39:
        fail("unexpected number of non-default jobs (%d != 39)" % len(title))
    joined = "".join(title)
    if not FLAG_RE.fullmatch(joined):
        fail("reconstructed string is not a valid flag: %r" % joined)
        return None

    step("job burst  %s  ->  %s   (owner %s, PID %s)" % (first, last, owner, proc and pid))
    step("reading jobTitle of each transfer job, dropping the decoy")
    print("")
    for i, (ch, j) in enumerate(zip(title, [j for j in jobs if j.title and j.title != "BITS Transfer"])):
        print("   %s%-3d  Transfer job: %s   %s   PID %s"
              % (C.DIM, i + 1, C.BOLD + C.CYAN + ch + C.RESET,
                 C.DIM + j.job_id + C.RESET, C.DIM + "6808" + C.RESET))
    print("")
    ok("flag assembled from %d job titles" % len(title))
    return joined

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    step("challenge folder %s" % base)

    flag = exploit(base)
    if flag:
        ok("FLAG = %s" % flag)
        big_flag(flag, time.time() - t0,
                 "BITS-Client Event ID 3 jobTitle | 39 single-char jobs")
        outp = Path(__file__).resolve().parent / "flag_from_collector.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail("flag not recovered")

if __name__ == "__main__":
    main()