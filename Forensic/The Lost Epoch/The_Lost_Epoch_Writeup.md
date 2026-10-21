# FlagYard CTF — The Lost Epoch

**Writeup by [General]**

> **General** — *CTF Player | Forensics & Cryptography*
>
> **Platform:** [FlagYard](https://flagyard.com) · **Box:** SAFCSP

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Forensics
- **Difficulty:** Hard

> *"An internal archive service went down mid-rotation. Five sealed v4
> records were wiped from the live tree — but the raw ext2 blocks were
> never zeroed, and the sealer's crypto tool is still on disk."*

---

## The flag

```
FlagY{7a3f9c2e1d5b8a4e6f0c3d7b9a2e5f1c}
```

---

## The short version

A 16 MB ext2 filesystem (`audit.ext2.img`) contains five **V4UN-sealed**
records — one *manifest* (953 B, epoch-0007) and four *fragments* (201 B
each, epochs 0017 / 0031 / 0042 / 0073). The directory entries for all
five were deleted, but the inodes and data blocks are still readable, so
the sealed blobs carve out cleanly with a minimal ext2 reader.

The bundled `/usr/lib/v4_unseal` binary defines the container: **scrypt +
AES-256-GCM**, with the *password* SLOT and *context* SLOT doing the
opposite of what feels natural:

1. **Carve the blobs.** Read every inode, keep files whose data starts
   with the blob magic `0x9c704d1c` → inodes 47–51.
2. **Reverse `v4_unseal`.** The key is `scrypt(password, salt =
   CONST16 ‖ BE32(epoch) ‖ role(11B) ‖ context, N=2^17, r=8, p=1)`;
   AES-GCM with `IV=blob[8:20]`, `AAD=LE32(epoch)`, tag = last 16 B.
3. **Recover the rotation token** from the Python core dump
   (`rotation_daemon.core`): a live `PyBytes(120)` framed between
   `<<<BELL-LABS-AUDIT-V4-ROTATION-TOKEN-BEGIN>>>` / `...-END>>>`
   sentinels, plus an environment line `TOKEN_HEX=...` — both agree on
   `f88cbc9f59b949a698c91756f5cad13782ae7e5d379fb8401e76d5a112b92e6e`.
4. **Flip the convention (the whole puzzle).** For every record it is
   **`password = filename`** (the basename) and **`context = secret`**
   (token for the manifest, KDF seed for each fragment) — not the other
   way around. `manifest.sealed.v4` + token + epoch 7 decrypts the
   manifest: JSON carrying `fragment_kdf_seeds` and the flag digest.
5. **Feed the seeds in.** Each fragment decrypts with
   **`password = basename`**, **`context = bytes.fromhex(seed)`**,
   `epoch` from the seed record, `roleflag = 0` → 8 hex chars each.
6. **Assemble.** `7a3f9c2e + 1d5b8a4e + 6f0c3d7b + 9a2e5f1c` by ascending
   `fragment_idx`, wrap in `FlagY{...}`, and SHA-256 matches the manifest
   digest byte-for-byte.

A legacy **v2** container self-validates with its own embedded digest
(`FlagY{c0ffee00deadbeef1234567890abcdef}`) — a deliberate decoy, only
the `plan9-venti-secret-v4` digest is current.

---

## The challenge box

The filesystem is a compact, minimal ext2 volume:

```
/etc/sealed/migration.notes             ← the hint file
/var/sealed/active/current.token        ← current-rotation metadata (decoy)
/var/sealed/active/current.manifest     ← active_epoch = 100 (decoy)
/var/sealed/historical/epoch-00XX/      ← 5 dirs, entries wiped
/var/lib/audit/rotation_daemon.core     ← Python process core dump
/usr/lib/v4_unseal                      ← ELF crypto tool (no argv)
/var/log/audit.recent, /var/log/syslog  ← rotation timeline
/tmp/sealed/*                           ← legacy v2 decoys
/etc/secrets/*                          ← not_flagY{...} decoys
```

`v4_unseal` reads hardcoded paths `/tmp/v4_input.bin` → `/tmp/v4_output.bin`
(no command-line arguments), which is exactly the hint that the *sealer*
always calls it with a constructed container of fixed shape.

---

## Step 1 — carve the sealed blobs (minimal ext2 reader)

`debugfs` (or a ~60-line pure-Python reader) recovers everything. The five
sealed records survive as orphan `dtime` inodes; their data blocks are
intact:

| inode | size | role | located | first block |
|---|---|---|---|---|
| 47 | 953 B | manifest | epoch-0007 | 633 |
| 48 | 201 B | fragment #1 session | epoch-0017 | 634 |
| 49 | 201 B | fragment #2 client  | epoch-0031 | 635 |
| 50 | 201 B | fragment #3 host    | epoch-0042 | 636 |
| 51 | 201 B | fragment #4 factotum | epoch-0073 | 637 |

Each file starts with `1c 4d 70 9c` — the on-disk little-endian form of
the blob magic `0x9c704d1c`, followed by `P` (u32 payload length: 945 for
the manifest, 193 for fragments).

> **Carve pitfall:** the `v4_unseal` ELF itself is *sparse* (holes in its
> block map). Skipping a hole instead of zero-filling shifts every later
> byte of the file and produces a corrupted binary — holes are logical
> zeros, not "absent".

---

## Step 2 — reverse `v4_unseal` into the V4UN format

Disassembly gives the container layout the sealer feeds the tool:

```
[ "V4UN" ‖ u32 passlen ‖ u32 epoch ‖ u32 roleflag
  ‖ u32 ctxlen ‖ u32 bloblen ]
[ password bytes ][ context bytes ]
[ blob := 0x9c704d1c ‖ u32 P ‖ nonce(12) ‖ ciphertext ‖ tag(16) ]
```

Key schedule (rebuild this in Python and round-trip it against the real
binary before touching any real data):

```
role   = (roleflag == 0) ? "v4:fragment" : "v4:manifest"   # 11 ASCII bytes
salt   = aabbccddeeff00112233445566778899 ‖ BE32(epoch) ‖ role ‖ context
key    = scrypt(password, salt=salt, N=2^17=131072, r=8, p=1)
AAD    = LE32(epoch)
iv     = blob[8:20];  ct = blob[20:-16];  tag = blob[-16:]
```

**Discipline that saved hours:** seal a blob in Python and unseal it with
the original binary. When the binary returns success, every field meaning
is *proven*, not assumed. The container maths, salt placement, scrypt
constants and GCM nonce/AAD handling were all verified this way.

---

## Step 3 — recover the rotation token from the core dump

`rotation_daemon.py` is a *token holder*. The notes hint the token is
framed by sentinels, and the core dump keeps the live object:

```
BEGIN = b"<<<BELL-LABS-AUDIT-V4-ROTATION-TOKEN-BEGIN>>>"   (43 bytes)
END   = b"...-END>>>"
audit_record = BEGIN + rotation_token + END                 # PyBytes(120)
```

Scanning the heap for the framed `PyBytes(120)` object and cross-checking
the process environment (`TOKEN_HEX=f88c...`) yields the 32-byte token
(quadruple-confirmed):

```
f88cbc9f59b949a698c91756f5cad13782ae7e5d379fb8401e76d5a112b92e6e
```

---

## Step 4 — the role-reversal insight

With `password = token, context = filename-strings` nothing decrypts —
11,000+ brute combinations of every obvious candidate failed. The mental
reset: **`v4_unseal`'s two user fields are not "password" and "data"**.

> **password = the FILENAME.  context = the SECRET MATERIAL.**

For the manifest under epoch-0007 that gives a single-word unlock:

| field | value |
|---|---|
| password | `manifest.sealed.v4` |
| context | rotation token (32 raw bytes) |
| epoch | 7 |
| roleflag | manifest (≠ 0) |

It decrypts to the manifest JSON — which then hands over the fragment
seeds plus the flag digest:

```json
{
  "scheme": "plan9-venti-secret-v4",
  "fragment_count": 4,
  "assembly": "concatenate fragment.data by ascending fragment_idx",
  "wrap_template": "FlagY{<fragments-concatenated>}",
  "digest": "08f1ce47378363dbc21c28aa27576b55f837d2faab491e2a92b3d535f6335f5c",
  "fragment_kdf_seeds": [
    { "basename": "session.sealed.v4",  "epoch": 17, "seed": "14f193b410e46eb34a155735140dd7a6" },
    { "basename": "client.sealed.v4",   "epoch": 31, "seed": "7a577655c82dc2ca5628f3d92aa8fb4f" },
    { "basename": "host.sealed.v4",     "epoch": 42, "seed": "ef62802f1821b3fdbc189f68def60f5e" },
    { "basename": "factotum.sealed.v4", "epoch": 73, "seed": "8dbb93997d4d3e82daca6c74f000e015" }
  ]
}
```

---

## Step 5 — unseal the four fragments

Same recipe per fragment (`roleflag = 0` → `"v4:fragment"`):

| password | context (seed bytes) | epoch | plaintext `data` |
|---|---|---|---|
| `session.sealed.v4` | `14f193b410e46eb34a155735140dd7a6` | 17 | `7a3f9c2e` |
| `client.sealed.v4` | `7a577655c82dc2ca5628f3d92aa8fb4f` | 31 | `1d5b8a4e` |
| `host.sealed.v4` | `ef62802f1821b3fdbc189f68def60f5e` | 42 | `6f0c3d7b` |
| `factotum.sealed.v4` | `8dbb93997d4d3e82daca6c74f000e015` | 73 | `9a2e5f1c` |

Each fragment plaintext is JSON:

```json
{
  "scheme": "plan9-venti-secret-v4",
  "epoch": 17,
  "fragment_idx": 1,
  "fragment_of": 4,
  "data": "7a3f9c2e"
}
```

---

## The calculation

```
7a3f9c2e   (fragment_idx 1, epoch 17)
+ 1d5b8a4e + 6f0c3d7b + 9a2e5f1c
= 7a3f9c2e1d5b8a4e6f0c3d7b9a2e5f1c
→ FlagY{7a3f9c2e1d5b8a4e6f0c3d7b9a2e5f1c}

sha256("FlagY{7a3f9c2e1d5b8a4e6f0c3d7b9a2e5f1c}")
   = 08f1ce47378363dbc21c28aa27576b55f837d2faab491e2a92b3d535f6335f5c   ✓
   == manifest digest
```

---

## Result

```
★  FLAG RECOVERED  ★
FlagY{7a3f9c2e1d5b8a4e6f0c3d7b9a2e5f1c}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| Deleted records never zero their data blocks | ext2 inode/block layer | Five sealed blobs survive as orphan inodes, fully carveable |
| Sealing tool left on disk | `/usr/lib/v4_unseal` | The whole container format is recoverable by reversing |
| Rotation token kept live in memory during the window | `rotation_daemon.py` | Core dump exposes the token, framed by searchable sentinels |
| Files created with sparse block maps | image builder | Naive file extraction shifts/spoils the binary — must zero-fill holes |

> The real hook of this box: the *names* of the records and the *secrets*
> were deliberately split across the two user fields of the container, so
> a solver who guesses the intuitive mapping gets a correct-looking format
> that still fails cryptographically.

---

## Takeaways

- **Delete ≠ gone.** On ext2, unlinked inodes and their blocks stay
  recoverable unless overwritten — `dtime`, directory slack and orphan
  inodes are standard carve targets.
- **Round-trip before you trust.** A re-implemented crypto format is
  worthless until it can seal something the *original binary* unseals.
  That test isolates model bugs from parameter bugs.
- **Cores are treasure cheats.** Python core dumps keep live objects
  (PyBytes, PyUnicode) with exact lengths and framing — find the sentinel,
  find the secret.
- **When a protocol "almost works", swap the fields.** `password` /
  `context` was a naming trap: the two inputs played exactly the roles the
  solver assumed were reversed.

---

## The solver

`solve_lost_epoch.py` is standalone (pure-Python ext2 reader + `cryptography`,
no `debugfs` needed). It locates every block starting with the blob magic,
recovers the manifest, follows `fragment_kdf_seeds` to decrypt the four
fragments, assembles the body and verifies SHA-256 against the manifest
digest:

```
python solve_lost_epoch.py [path/to/audit.ext2.img]
★  FLAG RECOVERED  ★
FlagY{7a3f9c2e1d5b8a4e6f0c3d7b9a2e5f1c}
        elapsed 31.3 s
        manifest digest verified | fragments 1->4 | v2 decoy ignored
```

It saves the flag to `flag_from_lost_epoch.txt`.

---

## Credit

- **Writeup by:** General
- **Challenge author:** SAFCSP (Box: *The Lost Epoch*, SAFCSP).