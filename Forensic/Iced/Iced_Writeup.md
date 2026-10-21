# FlagYard CTF — Iced

**Writeup by [General]**

> **General** — *CTF Player | Forensics & Web Security*
>
> **Platform:** [FlagYard](https://flagyard.com) · **Box:** SAFCSP

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Forensics
- **Difficulty:** Hard

> *"The attacker successfully gained access to a target machine. The attacker
> utilized a legitimate Windows binary to drop malicious code, evading
> traditional security measures. Additionally, the attacker employed
> obfuscation techniques to further conceal the malicious activity, making
> detection and analysis more challenging."*

---

## The flag

```
FlagY{d41d8cd98f00b204e9800998ecf8427e}
```

---

## The short version

The artifact is a **KAPE-style forensic collection** of a Windows 10 box
(user `Marwan Elshafei`) — only `AppData\*` and `prefetch\*` were gathered.
Inside that humble slice of disk the whole story is written:

1. **The drop primitive (the "legitimate Windows binary").** The system ran
   `certutil.exe` — a **signed, blessed Microsoft binary**. `certutil` and
   the CryptoAPI URL cache store *every byte it downloads* in

   ```
   AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\<md5(url)>
   ```

   The `MetaData` files sitting next to them reveal the source URLs — the
   attacker pulled two PowerShell payloads from their own GitHub repo
   **`Marwan18/API`**:

   ```
   https://raw.githubusercontent.com/Marwan18/API/main/secret.ps1
   https://raw.githubusercontent.com/Marwan18/API/main/exfiltration.ps1
   ```

   `prefetch\CERTUTIL.EXE-*.pf` confirms the binary ran; And IE's
   `INetCache\IE\27DOAR8L\exfiltration[1].htm` is a cached GitHub *blob
   page* of the same repo — the attacker (and later the analyst) browsed
   `github.com/Marwan18/API/blob/main/exfiltration.ps1`.

2. **The obfuscation.** Both scripts are PowerShell one-liners famously
   mangled: mixed-case cmdlets (`InvOkE-ExPResSION`, `rEPLacE`,
   `tOStRINg`), the string written as a `("{N}..."-f 'frag','frag',...)`
   fragment shuffle, `'Cvx'` acting as an apostrophe (replaced with
   `[char]39`), `j+Y+O` char-arithmetic producing a quote
   (`[char]106+[char]89+[char]79` → `"`), then `[Convert]::FromBase64String`
   + `[System.Text.Encoding]::Unicode.GetString`, all handed to `IEX`.

3. **The secret.** Splicing the string back together and un‑base64ing the
   inner layer yields a PowerShell assignment:

   ```
   secret.ps1        ->  $flag = "FlagY{d41d8cd98f00b204e9800998ecf8427e}"   <- the flag
   exfiltration.ps1  ->  $flag = "FLAGY{d9e52c0c07a1223a0898e4d9ef41fb36bcbc354be6a7497d33ed2b6b6b6d523f}"   <- decoy
   ```

   Only `secret.ps1` carries a **valid FlagYard flag** (lower-case `FlagY{`
   + a 32-hex md5). `exfiltration.ps1` is the trap — capital `FLAGY{` and a
   48-hex value that is nothing a checker would accept.

---

## The challenge box

The shipped folder is the output of a **KAPE** collection run
(`prefetch\KAPE.EXE-*.pf`, `GKAPE.EXE-*.pf`, and Sysmon `.pf` entries are
the collection tooling being killed). The evidence that matters is tiny —
two cached blobs — but it is wrapped in a lot of **noise** on purpose:

- The IE `INetCache` is flooded with **Microsoft Store** API responses
  (`skus[1..N].json`, `update100[1].xml`) — irrelevant browsing chatter.
- A cached `README[1].md` from **`Orange-Cyberdefense/GOAD`** plus
  `goad[1].sh` — a pentest AD-lab README the user happened to open; a
  decoy to keep you browsing the wrong "malware" repo.
- `INetCache\IE\R8197T8H\exfiltration[1].ps1` is **0 bytes** — a truncated
  IE download of the same script. The *complete* copy lives in the
  CryptoAPI cache.
- `Notepad++\session.xml` lists `downloader.html`, `install.ps1` and the
  `CryptnetUrlCache\Content\B8041...` blob — a forensic analyst's own
  working set, confirming exactly which artifacts are the interesting ones.

---

## Step 1 — the LOLBin: certutil drops the payloads

`prefetch\CERTUTIL.EXE-28F1E0C1.pf` says `certutil` ran — the challenge's
*"legitimate Windows binary that evades traditional security measures"*.
When `certutil` (or the CryptoAPI's `CryptRetrieveObjectByUrl`) fetches a
URL, the returned object is cached under

```
AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\<MD5(URL)>
```

with the URL stored in the sibling `MetaData\<MD5(URL)>` file. Extracting
that UTF-16 blob gives the C2 / delivery addresses:

```
MetaData\F0EC1EB3E872E51DCE0F808468F29F73   :  /.raw.githubusercontent.com/Marwan18/API/main/secret.ps1
MetaData\B8041CEBB05BB6256C3C9C2291CFDA4B   :  raw.githubusercontent.com/Marwan18/API/main/exfiltration.ps1
MetaData\B9257E384D5896D4E151972A6812FE37   :  github.com/Marwan18/API/blob/main/exfiltration.ps1
```

The content files are **byte-exact copies of what was downloaded**:

```
Content\F0EC1EB3E872E51DCE0F808468F29F73  (1005 B)  =  secret.ps1
Content\B8041CEBB05BB6256C3C9C2291CFDA4B  ( 534 B)  =  exfiltration.ps1
```

`prefetch` also shows `SYSMON.EXE`/`SYSMON64.EXE` — the collection host had
Sysmon installed; the payload fetch was already long gone by acquisition,
but its white-listed download left these perfect copies behind.

## Step 2 — unwinding the obfuscation

`secret.ps1` starts as a monster literal that PowerShell builds via the
format operator — every character is scattered as a shuffled fragment:

```powershell
 (("{4}{58}{17}{20}{53}{47}{42}{69}{66}{48}{44}...{52}{8}{38}{60}{26}"
    -f 'xTCvx','ThmMDBiMjA0ZC','aC','vx+','InvOkE',...))
     .rEPLacE('Cvx',[stRing][CHar]39)
     | .( $VERbosePREfEReNCe.tOStRINg()[1,3]+'x'-jOIN'' )
```

Reading the anti-analysis tricks one by one:

| Trick | Decodes to | Why it is used |
|---|---|---|
| Mixed-case command names | `InvOkE-ExPResSION`, `rEPLacE`, `tOStRINg` | Bypass case-sensitive AV / heuristics |
| `("{N}..." -f 'frag', 'frag', ...)` | reassembled literal | String is unreadable until the 72 fragments are re-indexed |
| `'Cvx'` → `[char]39` | `'` (apostrophe) | Quote characters hidden behind a token |
| `[char]106+[char]89+[char]79` → `[char]34` | `"` (double quote) | Even the *quotes around base64* are forged from code points |
| `.tOStRINg()[1,3]+'x'` on `$VerbosePreference` | `i` + `e` + `x` = `iex` | Concealed Invoke-Expression pipeline |
| `[Convert]::FromBase64String(...)` + `[Text.Encoding]::Unicode.GetString` | final text | Real content only exists after a B64 round-trip |

After the fragment shuffle is solved, the middle layer is revealed:

```
iex ([System.Text.Encoding]::Unicode.GetString(
     [System.Convert]::FromBase64String("JGZsYWcgPSJGbGFnWXtkNDFkOGNk..."
                                        "OThmMDBiMjA0ZTk4MDA5OThlY2Y4NDI3ZX0i")))
```

Un‑base64ing that payload finally prints the real content:

```
$flag = "FlagY{d41d8cd98f00b204e9800998ecf8427e}"
```

(Fun fact: the hash happens to equal `md5("")` — the attacker embedded the
finished flag string directly; the empty-input coincidence is just flavour.)

Repeating the same surgery on `exfiltration.ps1` (its own `(''iex''+...-f[cHAR]34)`
wrapper) produces:

```
$flag = "FLAGY{d9e52c0c07a1223a0898e4d9ef41fb36bcbc354be6a7497d33ed2b6b6b6d523f}"
```

Wrong prefix (`FLAGY`), wrong length (48 hex, not 32) — a **decoy** planted
to punish sloppy solvers that grab the first `*Y{...}` they see.

## Step 3 — the flag

## The calculation

Re-walking the two cached scripts mechanically — the 72 shuffled fragments
→ `-f` splice → `Cvx` → `'` → `jYO` → `"` → `FromBase64String` → UTF‑16LE:

```
secret.ps1          :  ("{4}{58}...{26}" -f 'xTCvx','ThmMDBiMjA0ZC',...)   # 72 fragments
                        .rEPLacE('Cvx',[stRing][CHar]39)                   # 'Cvx' -> '
                        iex ([System.Text.Encoding]::Unicode.GetString(
                             [Convert]::FromBase64String("JGZsYWcgPSJ...")))  # base64
                        ->  $flag = "FlagY{d41d8cd98f00b204e9800998ecf8427e}"        # THE FLAG

exfiltration.ps1    :  (('iex '+'...'+'-f[cHAR]34) | &( $SheLLid[1]+$sHellID[13]+'X')
                        ->  $flag = "FLAGY{d9e52c0c07a1223a0898e4d9ef41fb36bcbc354be6a7497d33ed2b6b6b6d523f}"
                                                                           # DECOY (rejected:
                                                                           #  'FLAGY' prefix + 48 hex)
```

```
★  FLAG RECOVERED  ★
FlagY{d41d8cd98f00b204e9800998ecf8427e}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| `certutil` (a signed, trusted LOLBin) used to fetch payloads | `prefetch\CERTUTIL.EXE-*.pf` | Download completed without triggering AV/EDR; call blended into legitimate admin traffic |
| CryptoAPI URL cache keeps raw downloads + URLs | `CryptnetUrlCache\Content\*` + `MetaData\*` | Byte-exact copy of the *attacker's* scripts survives on disk forever |
| PowerShell obfuscation relies only on string surgery | `secret.ps1`, `exfiltration.ps1` | Fully reversible — the plaintext `$flag = "..."` is one B64 hop away |
| Attacker re-used public GitHub infrastructure | repo `Marwan18/API` | Delivery address reconstructed from cache metadata = OSINT correlation |
| IE/Edge short-term cache truncates downloads | `INetCache\...\exfiltration[1].ps1` (0 B) | Looks like the payload "disappeared", but the URI cache kept the full copy |

> The real hook of this box: the **defender's own caching** — a harmless,
> legitimately-used Windows binary — is what stored the attacker's code
> and its delivery URLs in pristine detail.

---

## Takeaways

- **LOLBins are the new beachhead.** "Legitimate binary" ≠ benign. On
  Windows, `certutil`, `bitsadmin`, `msiexec`, `regsvr32`, `rundll32` are
  signed and trusted — forensics must treat their *caches* as crime scenes.
- **`CryptnetUrlCache\Content` + `MetaData` = free malware copies + URLs.**
  Every object fetched via `CryptRetrieveObjectByUrl`/`certutil` stays on
  disk, content and source URL side by side.
- **PowerShell obfuscation is cosmetic.** `-f` shuffles, `'+'` joins,
  `[char]N` arithmetic and `IEX` are string surgery — normalise casing,
  re-index the fragments and the base64 layer falls out.
- **Decoys hide in plain sight.** Capital `FLAGY{...}` and a 48-hex value
  is a trap; the accepted flag format wins (`FlagY{` + 32-hex md5).

---

## The solver

`solve_iced.py` — points at the challenge folder, scans
`CryptnetUrlCache`/`INetCache` for cached PowerShell payloads, reverses
both obfuscation flavours, prints every recovered secret (tagging the
decoy) and writes the real flag:

```
python solve_iced.py
✓ …/CryptnetUrlCache\Content\B8041CEBB05BB6256C3C9C2291CFDA4B -> FLAGY{d9e52c0c07a1223a0898e4d9ef41fb36bcbc354be6a7497d33ed2b6b6b6d523f}   (decoy)
✓ …/CryptnetUrlCache\Content\F0EC1EB3E872E51DCE0F808468F29F73 -> FlagY{d41d8cd98f00b204e9800998ecf8427e}
★  FLAG RECOVERED  ★
FlagY{d41d8cd98f00b204e9800998ecf8427e}
        elapsed 0.8 s
        secret.ps1 = flag | exfiltration.ps1 = decoy
```

It saves the flag to `flag_from_iced.txt`.

---

## Credit

- **Writeup by:** General
- **Challenge author:** SAFCSP (Box: *Iced*, SAFCSP).