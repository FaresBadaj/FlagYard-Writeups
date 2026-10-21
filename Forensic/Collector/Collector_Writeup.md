# FlagYard CTF — Collector

**Writeup by [General]**

> **General** — *CTF Player | Forensics & Web Security*
>
> **Platform:** [FlagYard](https://flagyard.com) · **Box:** SAFCSP

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Forensics
- **Difficulty:** Medium

> *"The antivirus has detected multiple files being dropped on the machine. We need to identify the downloaded files and retrieve the flag."*

---

## The flag

```
FlagY{0c0a6df5d889811f503f3996f77b5660}
```

---

## The short version

The box ships a **full Windows event-log export** (`logs\*.evtx`). The
whole incident is one professional **Living-off-the-Land (LotL)** pass over
a single Windows service — **BITS**, the Background Intelligent Transfer
Service — and the flag sits in a place nobody greps for:

- On `2024-07-24 18:34` a PowerShell one-liner on `CASTELBLACK\vagrant`
  bypassed the execution policy and ran **`C:\Users\vagrant\Desktop\AnAn.ps1`**
  (Event ID 4104, Script Block Logging, PID 6808).
- That script created a **burst of 40 BITS transfer jobs in ~8 seconds**
  (`Microsoft-Windows-Bits-Client/Operational`, Event ID 3 —
  *"The BITS service created a new job"*).
- One job is the decoy: its `jobTitle` is the default **`BITS Transfer`**.
- The other **39 jobs** each carry a **single character** in their
  **`jobTitle`** field. Read them in chronological order and they spell the
  whole flag — so a naive message search for `FlagY` or `Flag` finds
  nothing:

```
Transfer job: F   Transfer job: l   Transfer job: a   ...  Transfer job: }
```

Why does this evade detection? BITS transfers look like mundane Windows
update traffic; the *name* of each job was re-purposed as a covert channel
for exfiltrated data, and it is invisible until you walk the whole event
stream.

---

## The challenge box

`logs\Microsoft-Windows-Bits-Client%4Operational.evtx` — 89 records, all
from the domain `castelblack.north.sevenkingdoms.local`:

| Event ID | Meaning | Count |
|---|---|---|
| 3 | **The BITS service created a new job** | 40 |
| 5 | Job cancelled | 40 |
| 306 | Loaded the job list from disk (boot) | 8 |
| 302 | Service start delay | 1 |

Every "job created" record (Event ID 3) carries the same payload envelope:

```
The BITS service created a new job.
Transfer job: F                                    <- jobTitle
Job ID: {a146951c-ed35-41a0-a683-d2b52069bea8}
Owner: CASTELBLACK\vagrant
Process Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process ID: 6808
```

Rendered as XML, the character lives in the `EventData` section — a field a
human glancing at the message will read as "just the job name":

```xml
<EventData>
  <Data Name="jobTitle">F</Data>
  <Data Name="jobId">{a146951c-ed35-41a0-a683-d2b52069bea8}</Data>
  <Data Name="jobOwner">CASTELBLACK\vagrant</Data>
  <Data Name="processPath">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="processId">6808</Data>
</EventData>
```

---

## Step 1 — the launcher (PowerShell Event ID 4104)

`Microsoft-Windows-PowerShell/Operational` logs every script block. At
`18:34:50` PID 6808 executed the bootstrap:

```
if((Get-ExecutionPolicy) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\vagrant\Desktop\AnAn.ps1'
```

This tells us *who* is generating the BITS burst — and `Process ID: 6808`
already matches in the first BITS Event 3 record.

## Step 2 — collect every "Transfer job" name (Event ID 3)

Chronologically (`-Oldest`), filtering for Event ID 3 and dropping the
default **`BITS Transfer`** job, the `jobTitle` field reads:

```
 1  F    11  6    21  1    31  f
 2  l    12  d    22  f    32  7
 3  a    13  f    23  5    33  7
 4  g    14  5    24  0    34  b
 5  Y    15  d    25  3    35  5
 6  {    16  8    26  f    36  6
 7  0    17  8    27  3    37  6
 8  c    18  9    28  9    38  0
 9  0    19  8    29  9    39  }
10  a    20  1    30  6
```

## Step 3 — the flag

## The calculation

```
getting the job list   : Event ID 3 in BITS Client/Operational (-Oldest)
filter                 : drop the decoy "BITS Transfer" job (filecount 0)
read                   : jobTitle of every remaining job, in order
joined                 : F l a g Y { 0 c 0 a 6 d f 5 d 8 8 9 8 1 1 f 5
                          0 3 f 3 9 9 6 f 7 7 b 5 6 6 0 }
flag                   = FlagY{0c0a6df5d889811f503f3996f77b5660}
```

```
★  FLAG RECOVERED  ★
FlagY{0c0a6df5d889811f503f3996f77b5660}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| BITS `jobTitle` used as a covert-channel field | `Microsoft-Windows-Bits-Client/Operational`, Event 3 | Flag is broadcast as 39 single-character job names — invisible to `grep Flag` |
| BITS is a legitimate, whitelisted Windows service | System service `BITS` | Transfers look like normal Windows Update/download traffic |
| Only one default-looking decoy job named `BITS Transfer` | Event 3 @ `18:34:54` | Distracts from the real data channel (all jobs `filecount: 0`, so no payload on disk to find) |
| Script Block Logging enabled | PowerShell/Operational 4104 | The `AnAn.ps1` launcher and its PID (6808) are preserved |
| Full event-log export shipped by the box | `logs\*.evtx` | Defense-in-depth logs become the entire attack timeline |

> The real hook of this box: the *attacker didn't hide the data at all* —
> they handed it to Windows' own BITS service and relied on the name field
> being treated as "metadata, not evidence".

---

## Takeaways

- **Metadata is evidence.** The flag wasn't inside a file — it was in the
  *transfer job name*. Attackers abuse `jobTitle`/window titles/registry
  value names because nobody indexes them.
- **LotL beats AV.** BITS, `certutil`, `schtasks` are legitimate Windows
  features; "Living off the Land" blends into normal admin traffic. Watch
  the *logs of the service*, not just the network.
- **Walk the whole stream.** A single event is noise; the *sequence* of 39
  single-char jobs is the message. Chronological ordering matters.
- **Name your decoys well.** One default-looking `BITS Transfer` job with
  zero files is enough to make a sloppy triage stop right there.

---

## The solver

`solve_collector.py` — points at the challenge folder, parses
`Microsoft-Windows-Bits-Client%4Operational.evtx` with `python-evtx`,
collects every Event ID 3 `jobTitle` in order, drops the `BITS Transfer`
decoy, joins the 39 characters and prints the flag:

```
pip install python-evtx
python solve_collector.py
★  FLAG RECOVERED  ★
FlagY{0c0a6df5d889811f503f3996f77b5660}
        elapsed 0.3 s
        BITS-Client Event ID 3 jobTitle | 39 single-char jobs
```

It saves the flag to `flag_from_collector.txt`.

---

## Credit

- **Writeup by:** General
- **Challenge author:** SAFCSP (Box: *Collector*, SAFCSP).