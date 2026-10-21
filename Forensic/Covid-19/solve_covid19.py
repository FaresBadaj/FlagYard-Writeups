#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COVID-19  -  FlagYard Forensics Solver

Insane / Forensics

"PharmaMed Inc.'s IT department has identified unusual network activity
 originating from a critical research system involved in Covid-19 vaccine
 development. Suspicious communications suggest that sensitive data may have
 been exfiltrated by a sophisticated threat actor."

The box ships a network capture (output.pcap) plus Windows memory dumps. The
attack chain is:

    1. RDP initial access  (192.168.1.5 -> 192.168.1.53)
    2. A Covenant Grunt is deployed on the victim, running as "svchosts"
    3. The Grunt beacons to its C2 at 192.168.1.54:9090 over a fake IIS
       HTTP profile ("Server: Microsoft-IIS/7.5")

Each C2 message is an HTTP POST/response whose body carries a base64 JSON blob:

    {"GUID": "...", "Type": 0, "Meta": "...",
     "IV": "<b64>", "EncryptedMessage": "<b64>", "HMAC": "<b64>"}

The crypto is AES-256-CBC + HMAC-SHA256. The two keys are recoverable from the
memory dumps (SetupAESKey for the handshake, SessionKey for everything after):

    SetupAESKey  a84922eb1888eaf1f1027c20b27840e33c1066bfc6af331ae8e01e216932e414
    SessionKey   4ab9e27bfd2c612f4d38b0f58ae2e1b9c5b8dcc27b8939972f98123411dfe14c

Solver pipeline:

    1. locate output.pcap (challenge folder)
    2. reassemble every TCP stream on port 9090
    3. parse the HTTP messages and pull the base64 JSON bodies
    4. verify the HMAC and AES-256-CBC decrypt each message
    5. regex out  FlagY{...}  and print the flag box

Needs:  pip install cryptography   (scapy optional - a raw pcap fallback is
built in).
"""
from __future__ import annotations

import base64
import json
import os
import re
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as c_hmac

try:
    from scapy.all import rdpcap
except ImportError:
    rdpcap = None

SESSION_KEY = bytes.fromhex("4ab9e27bfd2c612f4d38b0f58ae2e1b9c5b8dcc27b8939972f98123411dfe14c")
SETUP_KEY   = bytes.fromhex("a84922eb1888eaf1f1027c20b27840e33c1066bfc6af331ae8e01e216932e414")
PORT = 9090
FLAG_RE = re.compile(r"FlagY\{[^}]+\}")

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
    for t in ("C O V I D - 1 9   S O L V E R",
              "Covenant C2  |  AES-256-CBC + HMAC-SHA256"):
        l = (58 - len(t)) // 2
        print("  \u2551" + " " * l + t + " " * (58 - len(t) - l) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

# ---------------------------------------------------------------------------
# result panel + author credits
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
    out += " " * max(0, W - sum(len(t) for t, _, _ in segs)) + "\u2551"
    print(out)

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
          ("Covid-19 - Flagyard", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - PCAP / Covenant C2", C.DIM + C.GRAY, "")])
    print("  " + "\u255a" + "\u2550" * W + "\u255d")

def big_flag(flag, chrono, extra=""):
    print()
    head = "\u2605  FLAG RECOVERED  \u2605"
    print("  " + "\u2554" + "\u2550" * W + "\u2557")
    _row([("", "", "")])
    _row([(" " * ((W - len(head)) // 2), "", ""), (head, C.BOLD + C.YELLOW, "")])
    _row([("", "", "")])
    _row([(" " * 6, "", ""), (flag, C.BOLD + C.GREEN, "")])
    for s in ("elapsed %.1f s" % chrono, extra):
        if s:
            _row([(" " * 10, "", ""), (s, C.DIM + C.CYAN, "")])
    _row([("", "", "")])
    _credits()
    print()

# ---------------------------------------------------------------------------
# pcap / HTTP parsing
# ---------------------------------------------------------------------------
def b64d(s):
    if isinstance(s, bytes):
        s = re.sub(rb"\s", b"", s).decode("latin1")
    s = re.sub(r"\s", "", s).strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def streams_from_pcap(path):
    if rdpcap is not None:
        pkgs = rdpcap(path)
    else:
        pkgs = parse_pcap_raw(path)
    flows = {}
    for p in pkgs:
        if not hasattr(p, "load") or not hasattr(p, "sport"):
            continue
        if p.sport != PORT and p.dport != PORT:
            continue
        key = (p.src, p.sport, p.dst, p.dport)
        flows.setdefault(key, []).append((int(getattr(p, "seq", 0)), bytes(p.load)))
    out = {}
    for key, segs in flows.items():
        segs.sort(key=lambda s: s[0])
        buf = b""
        last = -1
        for seq, payload in segs:
            start, end = seq, seq + len(payload)
            if last >= 0 and end <= last:
                continue
            if last >= 0 and start > last:
                buf += b"\x00" * (start - last)
            elif last >= 0 and start < last:
                payload = payload[last - start:]
                start = last
            buf += payload
            last = end
        out[key] = buf
    return out

def parse_pcap_raw(path):
    pkgs = []
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return pkgs
    le = magic == b"\xd4\xc3\xb2\xa1"
    endian = "<" if le else ">"
    _vmaj, _vmin, _tz, _sf, _snap, network = struct.unpack_from(endian + "IHHiII", data, 0)
    off = 24
    while off + 16 <= len(data):
        _ts_s, _ts_us, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if incl > len(data) - off:
            break
        frame = data[off:off + incl]
        off += incl
        pkg = parse_frame(frame, network)
        if pkg:
            pkgs.append(pkg)
    return pkgs

class Simple:
    def __init__(self, **kw):
        self.__dict__.update(kw)

def parse_frame(frame, linktype):
    if linktype != 1:
        return None
    eth = frame[14:]
    if len(eth) < 34 or eth[9] != 6:
        return None
    src = ".".join(map(str, eth[12:16]))
    dst = ".".join(map(str, eth[16:20]))
    tcp = eth[20:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", tcp, 0)
    doff = (tcp[12] >> 4) * 4
    return Simple(sport=sport, dport=dport, seq=seq, src=src, dst=dst, load=tcp[doff:])

def split_http(data, is_req):
    parts = []
    marker = b"POST " if is_req else b"HTTP/1.1 "
    start = 0
    while True:
        idx = data.find(marker, start)
        if idx == -1:
            break
        nxt = data.find(marker, idx + 1)
        parts.append(data[idx:] if nxt == -1 else data[idx:nxt])
        start = idx + 1
    return parts

def dechunk(data):
    out = b""
    cur = 0
    while True:
        nl = data.find(b"\r\n", cur)
        if nl == -1:
            out += data[cur:]
            break
        try:
            size = int(data[cur:nl].split(b";")[0].strip(), 16)
        except ValueError:
            out += data[cur:]
            break
        if size == 0:
            break
        out += data[nl + 2:nl + 2 + size]
        cur = nl + 2 + size + 2
    return out

def httparse(data, is_req):
    msgs = []
    for msg in split_http(data, is_req):
        hd = msg.find(b"\r\n\r\n")
        if hd == -1:
            continue
        head = msg[:hd].decode("latin1", "replace")
        if is_req:
            m = re.search(r"Content-Length:\s*(\d+)", head, re.I)
            if not m:
                continue
            body = msg[hd + 4:hd + 4 + int(m.group(1))]
            vals = re.findall(rb"data=([A-Za-z0-9+/=]+)", body)
            if not vals:
                continue
            payload = b64d(vals[0])
        else:
            if head.startswith("HTTP/1.1 100"):
                continue
            body = re.sub(rb"\s", b"", dechunk(msg[hd + 4:]))
            runs = re.findall(rb"[A-Za-z0-9+/=]{88,}", body)
            if not runs:
                continue
            payload = b64d(max(runs, key=len))
        try:
            msgs.append(json.loads(payload))
        except ValueError:
            continue
    return msgs

def hmac_sha256(key, data):
    h = c_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def decrypt(j, key):
    iv = b64d(j.get("IV", ""))
    em = b64d(j.get("EncryptedMessage", ""))
    hm = b64d(j.get("HMAC", ""))
    if len(iv) != 16 or not em or len(em) % 16:
        return None, False
    ok = len(hm) == 32 and hmac_sha256(key, em) == hm
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = c.update(em) + c.finalize()
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        return pt[:-pad], ok
    return None, ok

# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def find_pcap(folder: Path):
    for p in sorted(folder.rglob("*.pcap")):
        return p
    for p in sorted(folder.rglob("*.pcapng")):
        return p
    return None

def exploit(folder: Path):
    step("locating the capture (output.pcap)")
    pcap = find_pcap(folder)
    if not pcap:
        fail("no .pcap under %s" % folder)
        return None, 0
    ok("found %s (%.1f MB)" % (pcap.name, pcap.stat().st_size / 1e6))

    step("reassembling TCP streams on port %d" % PORT)
    flows = streams_from_pcap(str(pcap))
    if not flows:
        fail("no port-%d traffic found" % PORT)
        return None, 0
    ok("reassembled %d stream direction(s)" % len(flows))

    step("parsing HTTP bodies and decrypting C2 messages")
    tried = 0
    flags = []
    for key, data in flows.items():
        is_req = key[3] == PORT
        for i, j in enumerate(httparse(data, is_req)):
            for name, k in (("session", SESSION_KEY), ("setup", SETUP_KEY)):
                pt, hok = decrypt(j, k)
                if pt is None:
                    continue
                tried += 1
                for hit in FLAG_RE.findall(pt.decode("latin1", "replace")):
                    flags.append((is_req, i, hit, pt))
                if hok:
                    break
    if not flags:
        fail("no flag recovered (decrypted %d message(s))" % tried)
        return None, tried
    ok("decrypted %d message(s); flag present" % tried)
    return flags[0][2], tried

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    step("challenge folder %s" % base)

    flag, tried = exploit(base)
    if flag:
        ok("FLAG = %s" % flag)
        big_flag(flag, time.time() - t0,
                 "Covenant C2 on TCP/%d | AES-256-CBC + HMAC-SHA256" % PORT)
        outp = Path(__file__).resolve().parent / "flag_from_covid19.txt"
        outp.write_text(flag + "\n", encoding="utf-8")
        print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))
    else:
        fail("flag not recovered")

if __name__ == "__main__":
    main()
