# FlagYard CTF — Locked Secrets

**Writeup by [General]**

> **General** — *CTF Player | Forensics & Cryptography*
>
> **Platform:** [FlagYard](https://flagyard.com) · **Box:** SAFCSP

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Forensics
- **Difficulty:** Hard

> *"A Windows workstation shipped with a BitLocker-protected data drive.
> The password never left the domain — it lives in a forgotten Group
> Policy file. The volume is still fully encrypted, but the key that opens
> it is one policy away."*

---

## The flag

```
FlagY{a8b4c9a8d9e0f5b9a77b89a7b1a5b9f8}
```

---

## The short version

Two artifacts ship together: a **triage of the system drive** (`triage image\E`)
and a **raw physical disk image** (`bitlocker drive\bitlocker_drive.E01`) of a
second drive whose only partition is **BitLocker-encrypted** (BDE-FVE). The
whole chain — password → VMK → FVEK → Elephant diffuser → NTFS → flag — goes:

1. **The password is hidden in the triage, not in the disk.** A KAPE-style
   collect of the OS volume carries
   `E\Windows\SYSVOL\domain\Policies\{F6E536A8-…}\Machine\Preferences\
   Groups\Groups.xml` — a domain Group Policy that creates a local account
   (`SM` / `mr.shosho`). Its `cpassword` attribute is a **GPP-encrypted
   blob**, decryptable with the hard-coded AES-256-CBC key
   `4e9906e8…` (zero IV, UTF-16LE) → **`Passw0rd123!@Meme`**.
2. **The E01 is the encrypted disk.** 145,408 sectors, partition type `07`,
   starting at LBA 128. Its `.E01.txt` gives the verified hashes
   (MD5 `a14dbeed…`) — a full 74,448,896-byte raw image rebuilds cleanly
   from the EnCase™ chunk table (2272 chunks).
3. **BDE metadata says "user password + Elephant".** The FVE volume at
   sector 128 starts with `-FVE-FS-`; the metadata block at rel `0x2100000`
   (description: `WIN-688U8N3F5QG New Volume 9/6/2024`) carries a VMK entry
   protected by a **password protector** (method `0x1001`) and a FVEK marked
   **method `0x8000` = AES-128-CBC + Elephant diffuser**.
4. **The key schedule.** Double-SHA256 stretch (`salt=abf2b1bf…`, 2^20
   rounds) + AES-CCM unwrap of the VMK blob → user key `9b4691c6…` → VMK
   `db67a3f8…` → decrypt the FVEK entry → key `0ee2577d…` + tweak
   `d53ca515…`.
5. **Elephant decryption.** Each 512-byte sector is AES-128-CBC'd with the
   sector-number-derived IV and **diffused with Elephant A/B** (the legacy
   `0x8000` scheme). Decrypting the *stored header* region (rel `0x27da000`)
   exposes the real NTFS VBR (`eb 52 90 NTFS`), bps 512, sectors/cluster 8,
   **$MFT LCN 5802** (rel `0x16aa000`).
6. **The flag file.** Parsing $MFT records (record size 246 B, resident
   `$DATA`) yields **`the flag.txt`** (short name `THEFLA~1.TXT`) — the same
   file `F:\the flag.txt` that `…\Recent\the flag.lnk` on the triage drive
   points to. Its resident content is the flag.

---

## The challenge box

```
Locked Secrets\
├─ triage image\                      # KAPE-style collect of the system drive (C:\ -> E:\)
│  ├─ 2024-09-06T13_17_45_* (ConsoleLog / CopyLog / SkipLog)
│  └─ E\
│     ├─ Windows\SYSVOL\domain\Policies\{F6E536A8-76F2-4111-A113-C19D882367AF}\
│     │     Machine\Preferences\Groups\Groups.xml        <- the GPP cpassword
│     ├─ Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\
│     │     the flag.lnk                                -> F:\the flag.txt
│     └─ Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\
│           BitLocker Recovery Key *.lnk                (3 recovery-key shortcuts)
└─ bitlocker drive\
   ├─ bitlocker_drive.E01             # raw physical disk, 145408 sectors
   └─ bitlocker_drive.E01.txt         # FTK Imager case log + verified hashes
```

The recoverable layer is minimal: **no `$MFT` of the target partition is
given** — the entire target volume is ciphertext. The OS triage hands over the
one weak link: the BitLocker **password stored in a domain Group Policy file**.

---

## Step 1 — the password is a GPP `cpassword`

The triage contains the domain SYSVOL share. In
`Policies\{F6E536A8-…}\Machine\Preferences\Groups\Groups.xml` a preferred
local group is defined with an encrypted password:

```xml
<User name="SM" changed="2024-09-06 12:12:55" ...>
  <Properties action="C" fullName="mr.shosho" ...
    cpassword="Xpk4DyKDjYQQ/EUHClHlP+m6AKRQL5cC+JABNiw5C9aUMrmXIH2Mkky4a8tKUxIq"
    userName="SM"/>
</User>
```

GPP secrets are AES-encrypted with a **well-known key and zero IV**:

```
key   = 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
iv    = 00 * 16
plain = AES-256-CBC-decrypt( base64(cpassword), key, iv )
      = b"Passw0rd123!@Meme"   (UTF-16LE)
```

That is the BitLocker user password.

---

## Step 2 — rebuild the raw disk from the E01

`bitlocker_drive.E01` is an EnCase™ container. Two 16-byte signatures anchor
the file: the `disk` section (`0x15d`) and the `table` section (`0x43c3d0e`)
of 2272 little-endian chunk offsets. A chunk marked with bit 31 is a zlib
stream (max 51200 B) at `offset & 0x7fffffff`; otherwise 0x8000 raw bytes
were stored directly:

```
sector count @ disk+0x5c = 145408      chunk count @ disk+0x50 = 2272
chunks * 0x8000 == sectors * 512 == 74,448,896 B   ✓ geometry

for k in 0..2272:
    v   = u32(table+0x64 + 4k)
    b   = zlib-decompress(E01[v&0x7fffffff : +0x20000]) if v&0x80000000
          else E01[v : +0x8000]
    disk[k*0x8000 : (k+1)*0x8000] = b[:0x8000]
```

The rebuilt image verifies byte-for-byte against the source hashes:

```
MD5  a14dbeedbbe755d96f587c29b0447f9c   ✓ (matches .E01.txt)
SHA1 585ef2af93fba23e6e00a2292f99685f13750651   ✓
```

The 0th sector is a classic MBR: entry 0, partition type `07` (NTFS), start
**LBA 128**, size 139,264 sectors — the BitLocker (FVE) volume.

---

## Step 3 — read the BDE metadata and unwrap the keys

Sector 128 starts with the FVE magic `-FVE-FS-`. The volume-header descriptor
points at the boot segment; the metadata block lives at **rel `0x2100000`**
(copies at `0x2caa000`, `0x3855000`):

```
rel 0x2100000  "-FVE-FS-"    meta hdr @ +0x40 (size 0x2b8, ver 1)
      description (type 7)   "WIN-688U8N3F5QG New Volume 9/6/2024"
      VMK entry      (type 2)  keyid e3e4100e-d1fe-b74b-8446-9440c183ec71
      FVEK entry     (type 3, valtype 5)  key_id 80 1b 17 af 5c 00 db 01
      method 0x8000      ->  AES-128-CBC + Elephant (legacy diffuser)
```

The VMK entry's properties are a **password protector** (stretch property with
salt `abf2b1bffa79d82652de981b62155a92`) plus an AES-CCM blob. The unlock is
two hops:

```
stretch: last = sha256(last ‖ initial ‖ salt ‖ u64(i)), i = 0 .. 2^20-1
         initial = sha256(sha256(pw_utf16le))
user key = 9b4691c69e064c17b99fc92800fd819e5aee1d650539bad4f03bfe03c3a58e89
VMK      = AES-CCM-decrypt(blob, key=user key)
         = db67a3f8e895d90e969af2e9c3b916d9dfa30338b2f5a6a31a3a01f18c44c65b
```

Same CCM unwrap on the FVEK entry yields the disk keys:

```
FVEK   = 0ee2577d4196ce7033380592e9aafeee
TWEAK  = d53ca515628f042b391e5fc960dccc4d    (AES uses key[:16], tweak[:16])
```

> **Protector pitfall:** the password stretch property stores its intended
> key-usage byte as `01 10 00 00` (0x1001), while the recovery protector in
> the *sibling* VMK entry uses `00 10 00 00` (0x1000). Matching only `0x1000`
> silently skips the real password protector — the CCM tag check is the
> arbiter, so every stretch property must be attempted.

---

## Step 4 — Elephant: AES-128-CBC + the diffusers

Legacy BitLocker (`0x8000`) encrypts sectors with the **Elephant** scheme.
Per 512-byte sector:

```
sector key  = ECB(TWEAK, addr_le16 ‖ 0^8)                     [first 16 B]
            ‖ ECB(TWEAK, addr_le16 ‖ 0x80-set-byte)            [next 16 B]
IV          = ECB(FVEK,  addr_le16 ‖ 0^8)
cipher      = AES-128-CBC(IV, elephant-decrypt(sector))
```

`elephant-decrypt` runs the inverse diffuser pair on the 128 32-bit words —
**diffuser B** (3 passes, right-rotate by 32-bit word, `R = [0,10,0,25]`) then
**diffuser A** (5 passes, `R = [9,0,13,0]`), then XORs the 32-byte sector key.

The trick for analysis: the first encrypted sectors hold the **stored copy of
the NTFS header**. Decrypting rel `0x27da000` (size `0x2000`, per the
volume-header descriptor) gives the real boot sector:

```
eb 52 90 "NTFS"    bps 512   spc 8   $MFT LCN 5802
$MFT region = rel 0x16aa000
```

---

## Step 5 — the $MFT and the flag file

Decrypting the $MFT runs of the restored NTFS volume and parsing the FILE
records (record size 246 B, resident `$DATA`) locates **`the flag.txt`**
(short name `THEFLA~1.TXT`). Its resident content is the flag — the very file
that `F:\the flag.txt` on the triage `Recent\the flag.lnk` shortcut advertised
all along.

---

## The calculation

```
cpassword blob  ->  AES-256-CBC(4e9906e8…, zero IV, UTF-16LE)
                =  Passw0rd123!@Meme                                  # BitLocker password

stretch(pw, abf2b1bffa79d82652de981b62155a92, 2^20) -> 9b4691c69e064c17b99fc92800fd819e…
AES-CCM(user_key, VMK blob)                       -> db67a3f8e895d90e969af2e9c3b916d9d…
AES-CCM(VMK, FVEK blob)                           -> FVEK 0ee2577d4196ce7033380592e9aafeee
                                                    TWEAK d53ca515628f042b391e5fc960dccc4d

sector 0x16aa000+ → $MFT record "the flag.txt" (THEFLA~1.TXT) →
FlagY{a8b4c9a8d9e0f5b9a77b89a7b1a5b9f8}
```

---

## Result

```
★  FLAG RECOVERED  ★
FlagY{a8b4c9a8d9e0f5b9a77b89a7b1a5b9f8}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| BitLocker password managed in a domain Group Policy file | `SYSVOL\…\Groups\Groups.xml` `cpassword` | Password protected only by a public, hard-coded AES key — decryptable by anyone |
| GPP secrets share a known key with an empty IV | `Machine\Preferences\Groups` | The one weak link the whole unlock chain hangs on |
| Whole-volume cryptography exposes the stored boot-sector copy | FVE volume, rel `0x27da000` | Decrypting just the stored NTFS header reveals live filesystem geometry (`$MFT` LCN) |
| Legacy method `0x8000` shipped in production | BDE-FVE metadata | Predictable per-sector IV/sector keys + 2007-era diffusers — no per-volume fill |
| Recent shortcut left on the OS drive | `Recent\the flag.lnk` | Tells the analyst the prized file was `F:\the flag.txt` before a single sector was decrypted |

> The real hook of this box: **nothing about BitLocker itself is broken.**
> The crypto holds. The failure is operational — the password sat inside a
> domain policy file that ships in the OS triage.

---

## Takeaways

- **GPP `cpassword` is not encryption.** AES-256-CBC with a published key
  and zero IV is obfuscation; any SYSVOL that leaks `Groups.xml` leaks its
  account passwords.
- **The E01 chunk table is the whole source of truth.** Bit 31 = zlib
  stream, otherwise raw — with `.E01.txt` hashes you can prove the rebuild
  is bit-exact before touching any crypto.
- **BitLocker = an exercise in key management.** The volume cipher is
  strong; among the password protector, recovery protector and the known
  GPP key, the *operational* blunder decides who can open the disk.
- **Never decrypt the whole volume.** The stored header copy hands you
  `$MFT` geometry for free, so only the header + MFT runs ((rel
  `0x16aa000`)) need decryption.
- **Let the CCM tag decide.** Both VMK protectors look identical until one
  of them authenticates 44 bytes of VMK — try them all, don't guess by the
  usage byte.

---

## The solver

`solve_locked_secrets.py` — points at the challenge folder, decrypts the GPP
`cpassword`, rebuilds and verifies the E01, unwraps VMK → FVEK, applies the
Elephant diffusers to the stored NTFS header + `$MFT`, and extracts the flag:

```
python solve_locked_secrets.py
✓ Groups.xml …\Groups\Groups.xml
✓ drive image   …\bitlocker drive\bitlocker_drive.E01
✓ GPP cpassword -> Passw0rd123!@Meme
✓ disk image 74448896 bytes (2272 chunks, 2272 stored)
✓ image integrity verified (MD5 a14dbeedbbe755d96f587c29b0447f9c)
✓ FVE volume at LBA 128 (71303168 bytes)
✓ metadata block @ rel 0x2100000
✓ VMK  db67a3f8e895d90e969af2e9c3b916d9dfa30338b2f5a6a31a3a01f18c44c65b
✓ FVEK 0ee2577d4196ce7033380592e9aafe eed53ca5 15628f042b391e5fc960dccc4d
✓ NTFS  bps=512 spc=8 $MFT LCN=5802 (rel 0x16aa000, rec 246 B)
✓ FLAG = FlagY{a8b4c9a8d9e0f5b9a77b89a7b1a5b9f8}
★  FLAG RECOVERED  ★
        elapsed ~8 s
        gpp -> stretch -> vmk -> fvek -> elephant -> $MFT
```

It saves the flag to `flag_from_locked_secrets.txt`.

---

## Credit

- **Writeup by:** General
- **Challenge author:** SAFCSP (Box: *Locked Secrets*, SAFCSP).