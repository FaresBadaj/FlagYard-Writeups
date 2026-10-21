#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POCHITA  -  FlagYard Forensics Solver

Hard / Forensics

A ~800 MB macOS-zipped evidence drop of a Windows workstation:  the outer
Pochita.zip holds a single entry  Pochita/Artifacts1.7z  which is *not* a
7-Zip archive at all - it is a plain ZIP whose only member is an FTK Imager
"Custom Content Image":

    Pochita.zip  (zip,  deflate)
      └── Pochita/Artifacts1.7z   (actually a ZIP, deflate)
            └── Artifacts.ad1     (AD1 = "ADSEGMENTEDFILE", 911 MB)

The .ad1 is NOT a disk image you can mount: it is FTK's per-file container
that stores a whole NTFS volume as a flat list of individually zlib-deflated
file streams plus a linked-list item tree.  No pyad1lib needed - the parser
below is ~60 lines of struct + zlib.

Inside the Administrator profile the interesting trail is an AI coding
assistant (Cursor / VS Code fork) that was used to plant a C2 beacon and then
told to erase the evidence:

  1. ~/.cursor/projects/<hash>/agent-transcripts/*.jsonl
        the assistant's own conversation log.  Six projects, thirteen
        transcripts, and exactly ONE of them talks about a "maintenance
        beacon", a hard-coded relay URL, silent exception swallowing and a
        commit message crafted so it "won't draw review attention".

  2. ~/AppData/Roaming/Cursor/Projects/<repo>/.git
        Cursor's per-project git repo.  The beacon was committed, then
        `git reset --hard HEAD~1` was run - so refs/heads/main no longer
        points at it, but the loose objects (commit 64a0c6eb, tree
        78a0aeb8, blob ed458d69) are still sitting in .git/objects and
        ORIG_HEAD still names the orphan commit.

  3. blob ed458d69 = the *poisoned* exporters.py, whose only difference from
        the clean version in HEAD is

            _BEACON_URL = "https://maintenance-relay-19f2.internal:8443/beacon?id=a3c7e1"

The flag is the MD5 of that C2 URL:

    FlagY{md5(c2_url)}

Solver pipeline:

    1. unpack the two zip layers (cached, so only the first run pays ~2 min)
    2. walk the AD1 item tree in memory - no extraction of the 1.1 GB profile
    3. grep the Cursor agent-transcripts for the beacon request  -> repo name
    4. read the repo's ORIG_HEAD, resolve commit -> tree -> <file> blob
    5. diff the orphan blob against the checked-out file, regex out the URL
    6. md5(url) -> FlagY{...}

Target is the challenge folder (default: the folder of this script).
"""
from __future__ import annotations

import hashlib
import difflib
import json
import mmap
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import zipfile
import zlib
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

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for t in ("P O C H I T A   S O L V E R",
              "AD1 image -> AI transcripts -> orphaned git blob -> C2"):
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
          ("Pochita - SAFCSP", _osc("https://flagyard.com", "\033[1;36m"), _OSC_END)])
    _row([("   Category  \u203a  ", "", ""),
          ("Forensics - AI Logs / Git Forensics", C.DIM + C.GRAY, "")])
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
# FTK Imager AD1 ("ADSEGMENTEDFILE") reader - pure stdlib
# ---------------------------------------------------------------------------
AD1_MAGIC = b"ADSEGMENTEDFILE"
AD1_BASE = 0x200            # item/file descriptors are relative to this
AD1_HEADER_SIG = (1330398273, 1094928711, 1095584076)

class AD1:
    """Minimal reader for FTK Imager custom-content images (.ad1).

    Layout used here (little-endian):
        0x000  "ADSEGMENTEDFILE\\0"  signature
        BASE+0x18  u32  chunk size (0x10000 in practice)
        BASE+0x24  u32  offset of the first item descriptor

    Item descriptor, at BASE + <rel>:
        +0x00 u64 next sibling      +0x08 u64 first child
        +0x10 u64 metadata list     +0x18 u64 chunk descriptor
        +0x20 u64 logical size      +0x28 u32 item type
        +0x2C u32 name length       +0x30 name (utf-8)
                 u64 parent

    Chunk descriptor, at BASE + <rel>:  u64 count, then count+1 u64 offsets
    delimiting `count` individually zlib-deflated slices of the file body.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.f = open(self.path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:15] != AD1_MAGIC:
            raise ValueError("not an AD1 image (bad signature)")
        self.chunk_size = self.u32(AD1_BASE + 0x18) or 0x10000
        self.first_item = self.u32(AD1_BASE + 0x24)

    def close(self):
        try:
            self.mm.close()
        finally:
            self.f.close()

    # -- primitive reads ----------------------------------------------------
    def u32(self, off):
        return struct.unpack_from("<I", self.mm, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.mm, off)[0]

    def b(self, off, n):
        return self.mm[off:off + n]

    # -- item tree ----------------------------------------------------------
    def item(self, rel):
        off = AD1_BASE + rel
        namelen = self.u32(off + 0x2C)
        return {
            "rel": rel, "off": off,
            "next_sib": self.u64(off + 0x00),
            "first_child": self.u64(off + 0x08),
            "meta": self.u64(off + 0x10),
            "cdesc": self.u64(off + 0x18),
            "size": self.u64(off + 0x20),
            "itype": self.u32(off + 0x28),
            "name": self.b(off + 0x30, namelen).decode("utf-8", "replace"),
        }

    def walk(self):
        """Iterative DFS of the linked item list -> [(relpath, item), ...]."""
        out = []
        stack = [(self.first_item, "")]
        guard = 0
        while stack:
            rel, prefix = stack.pop()
            guard += 1
            if guard > 4_000_000:
                raise RuntimeError("item tree loop detected")
            while rel:
                it = self.item(rel)
                path = prefix + "/" + it["name"] if prefix else it["name"]
                out.append((path, it))
                if it["first_child"]:
                    stack.append((it["first_child"], path))
                rel = it["next_sib"]
        return out

    def index(self):
        """{path-without-root-prefix: item} for O(1) lookups."""
        items = self.walk()
        base = items[0][0]
        return items, base, {p[len(base) + 1:]: it for p, it in items}

    # -- file bodies --------------------------------------------------------
    def read_file(self, it):
        if not it["cdesc"] or it["meta"] <= it["cdesc"]:
            return b""
        d = AD1_BASE + it["cdesc"]
        n = self.u64(d)
        offs = [self.u64(d + 8 + 8 * i) for i in range(n + 1)]
        out = bytearray()
        for i in range(n):
            blob = self.b(AD1_BASE + offs[i], offs[i + 1] - offs[i])
            out += zlib.decompressobj().decompress(blob)
        return bytes(out)

    def read_path(self, idx, path):
        it = idx.get(path)
        if it is None or it["first_child"]:
            raise KeyError(path)
        return self.read_file(it)


# ---------------------------------------------------------------------------
# stage 1 - unpack the two zip layers (cached)
# ---------------------------------------------------------------------------
CACHE_DIRNAME = "pochita_cache"
AD1_SIZE = 955850949        # uncompressed size of Artifacts.ad1

def _stream_zip_member(zf: zipfile.ZipFile, member, dst: Path, label: str):
    total = member.file_size or 1
    live = sys.stdout.isatty()
    got = 0
    t0 = time.time()
    with zf.open(member) as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(1 << 22)
            if not chunk:
                break
            fo.write(chunk)
            got += len(chunk)
            if live and total > (8 << 20):
                print("\r    %s%-46s %s%s" % (C.DIM, label, bar(got / total), C.RESET),
                      end="", flush=True)
    if live and total > (8 << 20):
        print("\r" + " " * 78 + "\r", end="")
    return got, time.time() - t0


def locate_evidence_zip(folder: Path):
    cands = [p for p in folder.glob("*.zip") if p.stat().st_size > (64 << 20)]
    if not cands:
        return None
    return max(cands, key=lambda p: p.stat().st_size)


def ensure_ad1(folder: Path):
    """Return (ad1_path, cached_bool) - unpacking only happens once."""
    cache = Path(tempfile.gettempdir()) / CACHE_DIRNAME
    cache.mkdir(parents=True, exist_ok=True)
    ad1 = cache / "Artifacts.ad1"
    if ad1.exists() and ad1.stat().st_size == AD1_SIZE:
        return ad1, True, cache

    src = locate_evidence_zip(folder)
    if src is None:
        raise FileNotFoundError("no evidence *.zip (>64 MB) in %s" % folder)
    ok("evidence archive %s (%d bytes)" % (src.name, src.stat().st_size))

    step("unpacking the nested archive (first run only, ~2 min)")
    mid = cache / "Artifacts1.7z"
    with zipfile.ZipFile(src) as z:
        members = [i for i in z.infolist() if i.filename.lower().endswith("artifacts1.7z")]
        if not members:
            raise FileNotFoundError("no *Artifacts1.7z member inside %s" % src.name)
        got, dt = _stream_zip_member(z, members[0], mid,
                                     "layer 1/2  %s" % members[0].filename)
    ok("layer 1  %-34s %10d bytes  %5.1f s" % (members[0].filename, got, dt))

    with zipfile.ZipFile(mid) as z2:
        members = [i for i in z2.infolist() if i.filename.lower().endswith(".ad1")]
        if not members:
            raise FileNotFoundError("Artifacts1.7z is not a zip holding an .ad1")
        got, dt = _stream_zip_member(z2, members[0], ad1,
                                     "layer 2/2  %s" % members[0].filename)
    ok("layer 2  %-34s %10d bytes  %5.1f s" % (members[0].filename, got, dt))

    # the mislabelled "1.7z" is really a zip - say so, it is half the puzzle
    kind = "ZIP"
    with zipfile.ZipFile(mid) as z2:
        meth = {i.compress_type for i in z2.infolist()}
    ok("Artifacts1.7z is really a %s (method %s), not a 7z archive"
       % (kind, ",".join(str(m) for m in sorted(meth))))
    mid.unlink(missing_ok=True)
    return ad1, False, cache


# ---------------------------------------------------------------------------
# stage 2 - read the AI assistant transcripts
# ---------------------------------------------------------------------------
CURSOR_ROOT = "[root]/Users/Administrator/"
TRANSCRIPT_RE = re.compile(
    r"^\[root\]/Users/Administrator/\.cursor/projects/([^/]+)/agent-transcripts/(.+)$")
REPO_NAME_RE = re.compile(r"Bootstrapping\s+([A-Za-z0-9_-]+)")

def scan_transcripts(img: AD1, idx):
    """Return [(project_hash, transcript_name, text, score)] sorted by hits."""
    hits = []
    for path, it in idx.items():
        m = TRANSCRIPT_RE.match(path)
        if not m or it["first_child"] or m.group(2).startswith("$"):
            continue
        try:
            text = img.read_file(it).decode("utf-8", "replace")
        except Exception:
            continue
        score = sum(text.lower().count(w) for w in
                    ("beacon", "relay", "c2", "hard-code", "swallow",
                     "won't draw review", "reset --hard"))
        hits.append((m.group(1), m.group(2), text, score))
    return hits


def repo_name_for(img: AD1, idx, project_hash: str, transcript: str):
    """The bootstrap transcript of the same project names the repository."""
    for path, it in idx.items():
        m = TRANSCRIPT_RE.match(path)
        if not m or m.group(1) != project_hash or it["first_child"]:
            continue
        try:
            text = img.read_file(it).decode("utf-8", "replace")
        except Exception:
            continue
        r = REPO_NAME_RE.search(text)
        if r:
            return r.group(1)
    r = REPO_NAME_RE.search(transcript)
    return r.group(1) if r else None


# ---------------------------------------------------------------------------
# stage 3 - git plumbing over loose objects read straight out of the AD1
# ---------------------------------------------------------------------------
class GitRepo:
    """Just enough git to resolve ORIG_HEAD -> commit -> tree -> blob."""

    def __init__(self, img: AD1, idx, prefix):
        self.img = img
        self.idx = idx
        self.prefix = prefix          # AD1 path of the .git folder

    def text(self, rel):
        return self.img.read_path(self.idx, self.prefix + "/" + rel).decode(
            "utf-8", "replace")

    def may(self, rel):
        p = self.prefix + "/" + rel
        it = self.idx.get(p)
        return it is not None and not it["first_child"]

    def object(self, sha):
        raw = self.img.read_path(
            self.idx, "%s/objects/%s/%s" % (self.prefix, sha[:2], sha[2:]))
        data = zlib.decompress(raw)
        nul = data.find(b"\x00")
        header = data[:nul].decode("ascii", "replace")
        return header.split()[0], header, data[nul + 1:]

    def tree_entries(self, tree_sha):
        _, _, body = self.object(tree_sha)
        out, i = [], 0
        while i < len(body):
            j = body.index(b"\x00", i)
            mode, name = body[i:j].split(b" ", 1)
            out.append((mode.decode(), name.decode("utf-8", "replace"),
                        body[j + 1:j + 21].hex()))
            i = j + 21
        return out

    def commit_tree(self, commit_sha):
        _, _, body = self.object(commit_sha)
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("tree "):
                return line.split()[1]
        return None

    def commit_message(self, commit_sha):
        _, _, body = self.object(commit_sha)
        return body.decode("utf-8", "replace").strip().split("\n\n")[-1].strip()

    def commit_parent(self, commit_sha):
        _, _, body = self.object(commit_sha)
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("parent "):
                return line.split()[1]
        return None


URL_CONST_RE = re.compile(
    r"""^\s*([A-Z_]*URL[A-Z_]*|[A-Z_]*ENDPOINT[A-Z_]*)\s*=\s*["'](https?://[^"']+)["']""",
    re.MULTILINE)


def find_repos(img: AD1, idx):
    """Every .git folder Cursor kept under AppData/Roaming/Cursor/Projects."""
    out = []
    pref = CURSOR_ROOT + "AppData/Roaming/Cursor/Projects/"
    for path, it in sorted(idx.items()):
        if not path.startswith(pref) or not path.endswith("/.git"):
            continue
        name = path[len(pref):].split("/")[0]
        if not any(idx.get(path + "/" + f) for f in
                   ("HEAD", "config", "objects", "ORIG_HEAD")):
            continue
        out.append((name, GitRepo(img, idx, path)))
    return out


def examine_repo(name, repo: GitRepo):
    """Return a dict describing the reset-and-hide evidence, or None."""
    if not repo.may("ORIG_HEAD"):
        return None
    orphan = repo.text("ORIG_HEAD").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", orphan):
        return None
    try:
        otype, ohdr, obody = repo.object(orphan)
    except Exception:
        return None
    if otype != "commit":
        return None

    head_ref = repo.text("refs/heads/main").strip() if repo.may("refs/heads/main") else ""
    reflog = repo.text("logs/HEAD") if repo.may("logs/HEAD") else ""

    tree = repo.commit_tree(orphan)
    entries = repo.tree_entries(tree)
    parent = repo.commit_parent(orphan)
    ptree = repo.commit_tree(parent) if parent else None
    pentries = dict((n, s) for _, n, s in repo.tree_entries(ptree)) if ptree else {}

    changed = []
    for _, fname, fsha in entries:
        if pentries.get(fname) != fsha:
            changed.append((fname, fsha))
    return {
        "name": name,
        "orphan": orphan,
        "head_ref": head_ref,
        "tree": tree,
        "message": repo.commit_message(orphan),
        "reflog": reflog,
        "changed": changed,
        "repo": repo,
    }


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------
def exploit(folder):
    folder = Path(folder)

    step("locating the evidence archive in %s" % folder)
    ad1_path, cached, cache = ensure_ad1(folder)
    if cached:
        ok("AD1 image cached at %s" % ad1_path)
    else:
        ok("AD1 image ready at %s" % ad1_path)

    step("opening the FTK custom-content image (no extraction, mmap walk)")
    img = AD1(ad1_path)
    try:
        items, base, idx = img.index()
    except Exception as e:
        fail("AD1 parse failed: %r" % (e,))
        return None
    ok("magic ADSEGMENTEDFILE | chunk 0x%x | %d items under %s"
       % (img.chunk_size, len(items), base.rsplit("/", 1)[-1]))
    ok("volume prefix %s" % base)

    # ---- 1. the assistant's own transcript log --------------------------
    step("hunting the AI assistant transcripts (.cursor/agent-transcripts)")
    hits = scan_transcripts(img, idx)
    if not hits:
        fail("no Cursor agent-transcripts found")
        return None
    hits.sort(key=lambda t: (-t[3], t[1]))
    for phash, tname, _text, score in hits:
        hot = score > 0
        print("   %s%s %s%-46s %shits=%d%s"
              % (C.GREEN if hot else C.DIM, "\u2713" if hot else "-", C.DIM,
                 "%s/%s" % (phash[:12], tname),
                 C.YELLOW if hot else "", score, C.RESET))
    best = [h for h in hits if h[3] > 0]
    if not best:
        fail("no transcript mentions a beacon")
        return None
    phash, tname, text, score = best[0]
    ok("beacon request found in %s" % tname)

    repo_nm = repo_name_for(img, idx, phash, text)
    ok("that Cursor project is repository '%s'" % repo_nm)

    step("replaying the conversation that asked for it")
    for line in text.strip().splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("ts", 0) < 1776122200:
            continue
        who = rec.get("role", "?")
        col = C.MAGENTA if who == "user" else C.CYAN
        body = rec.get("content", "")
        body = re.sub(r"\s+", " ", body).strip()
        if len(body) > 300:
            body = body[:297] + "..."
        print("   %s%-9s%s %s" % (col, who, C.RESET, body))

    # ---- 2. the reset-and-hide git repo ---------------------------------
    step("auditing every Cursor project repo for a reset-and-hide")
    repos = find_repos(img, idx)
    ok("repositories under AppData/Roaming/Cursor/Projects: %d (%s)"
       % (len(repos), ", ".join(n for n, _ in repos)))

    suspects = []
    for name, repo in repos:
        if repo_nm and name != repo_nm:
            continue
        info = examine_repo(name, repo)
        if info and info["changed"]:
            suspects.append(info)
        elif info:
            print("   %s- %-22s %sno reset, nothing dangling%s"
                  % (C.DIM, name, C.DIM, C.RESET))
    if not suspects:
        fail("no repository with an orphaned commit found")
        return None
    for s in suspects:
        print("   %s\u2713 %-22s %sORIG_HEAD %s != main %s%s"
              % (C.GREEN, s["name"], C.DIM, s["orphan"][:12], s["head_ref"][:12], C.RESET))

    info = suspects[0]
    repo = info["repo"]
    step("reflog of %s" % info["name"])
    for line in info["reflog"].strip().splitlines():
        if "reset" in line:
            print("   %s%s%s" % (C.YELLOW, line, C.RESET))
        else:
            print("   %s%s%s" % (C.DIM, line, C.RESET))

    step("orphan commit %s  \"%s\"" % (info["orphan"][:12], info["message"]))
    ok("tree %s  |  files changed vs its parent: %s"
       % (info["tree"][:12], ", ".join(n for n, _ in info["changed"])))

    # ---- 3. pull the poisoned blob out of .git/objects -------------------
    step("diffing the orphaned blob against the checked-out file")
    c2 = None
    for fname, fsha in info["changed"]:
        _, ohdr, obody = repo.object(fsha)
        ok("blob %s  %-14s %s" % (fsha[:12], fname, ohdr))
        blob = obody.decode("utf-8", "replace")

        wt = CURSOR_ROOT + "AppData/Roaming/Cursor/Projects/%s/%s" % (info["name"], fname)
        live = ""
        if wt in idx:
            try:
                live = img.read_file(idx[wt]).decode("utf-8", "replace")
            except Exception:
                live = ""
        print("")
        for ln in difflib.ndiff(live.splitlines(), blob.splitlines()):
            if ln.startswith("  "):
                continue
            plus = ln.startswith("+ ")
            print("   %s%s %s%s%s"
                  % (C.GREEN if plus else C.RED, "+" if plus else "-",
                     C.BOLD if plus else C.DIM, ln[2:], C.RESET))
        print("")

        m = URL_CONST_RE.search(blob)
        if m:
            c2 = (m.group(1), m.group(2), fname, fsha)
            ok("hard-coded %s in the orphaned blob: %s" % (m.group(1), m.group(2)))

    if not c2:
        fail("no hard-coded URL constant found in the orphaned blobs")
        return None

    const, url, fname, fsha = c2
    step("the working tree was already reset, so %s no longer has it" % fname)
    ok("%s = %s" % (const, url))

    h = hashlib.md5(url.encode("utf-8")).hexdigest()
    return "FlagY{%s}" % h, url, h, info, c2


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    t0 = time.time()
    enable_vt()
    banner()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    step("challenge folder %s" % base)

    res = exploit(base)
    if not res:
        fail("flag not recovered")
        return
    flag, url, digest, info, c2 = res
    ok("FLAG = %s" % flag)
    big_flag(flag, time.time() - t0, "md5 of the orphaned _BEACON_URL")
    outp = Path(__file__).resolve().parent / "flag_from_pochita.txt"
    outp.write_text(flag + "\n", encoding="utf-8")
    print("  %s[+] saved to %s%s" % (C.GREEN, outp, C.RESET))


if __name__ == "__main__":
    main()
