# FlagYard CTF — Can You See Me

**Writeup by [General]**

> **General** — *CTF Player | Forensics & Web Security*
>
> **Platform:** [FlagYard](https://flagyard.com) · **Box:** SAFCSP

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Forensics
- **Difficulty:** Hard

> *"An attacker exploited a SQL injection to steal credentials — you can see the traffic, but the data is hidden in a blind channel."*

---

## The flag

```
FlagY{f09319a33342ad624b1ea55704766623}
```

---

## The short version

An attacker ran **sqlmap** (`sqlmap/1.8.8`) against the DVWA
**"SQL Injection (Blind)"** endpoint and dumped the whole `dvwa.users`
table **character by character** using boolean probes like

```
id=1 AND ORD(MID((SELECT IFNULL(CAST(password AS NCHAR),0x20)
                  FROM users ORDER BY `user` LIMIT 2,1),7,1))>102
```

The application never prints the data — it only answers *"User ID exists in
the database."* (TRUE) or *"User ID is MISSING..."* (FALSE). Every single
probe and its response was recorded in the Apache **ModSecurity audit log**,
so we replay the attack backwards and rebuild the stolen table:

1. **Parse the audit log.** ModSecurity stores each request/response pair in
   one block with `-A- / -B- / -C- / -E-` sections — 5,395 entries.
2. **Read each probe.** The `id` parameter holds `ORD(MID((SELECT ...),N,1))>X`;
   the `-E-` response holds the TRUE/FALSE bit ("User ID exists...").
3. **Turn thresholds into characters.** For each (query, position) the
   biggest `X` that still evaluated TRUE gives the character: `chr(X+1)`.
4. **Re-assemble every string.** sqlmap dumped the whole `dvwa.users` —
   usernames, ids, names and **md5 password hashes**.
5. **Join the flag.** The flag was split across two `password` rows —
   `etoo` holds `FlagY{f09319a33342ad6` and `etoo16` holds
   `24b1ea55704766623}`.

---

## The challenge box

The web log is a DVWA (PHP) application with the classic blind-SQLi sink:

```php
$id = $_GET['id'];

$prep  = mysqli_prepare($con, "SELECT first_name, last_name FROM users
                              WHERE user_id = '" . $id . "'");
```

No output is ever echoed — the page only tells us whether a row matched
(`User ID exists in the database.`) or not. That boolean is the whole
oracle, and it is what sqlmap used to leak the database one bit at a time.

---

## Step 1 — parse the ModSecurity audit log

Each entry in `apache2/modsec_audit.log` is one request/response pair:

```
--3c43...-A-- [17/...] ... 10.0.2.15 ... 10.0.2.6
--3c43...-C--
id=1+AND+ORD%28MID%28%28SELECT+...AS+NCHAR%29%2C0x20%29%29+FROM+dvwa.users+ORDER+BY+%60user%60+LIMIT+2%2C1%29%2C7%2C1%29%29%3E102--+-...
--3c43...-E--
User ID exists in the database.
```

Regex-splitting on each `--<id>-A--` marker gives 5,395 independent blocks.
From `-C-` we URL-decode the `id` parameter and extract `position N` and
`threshold X` from `ORD(MID((SELECT ...),N,1))>X`; from `-E-` we read the
boolean answer. This recovers **5,116 probes** against **138 distinct
query/column instances** — i.e. the complete dump of one table.

## Step 2 — rebuild each string with `max(TRUE) + 1`

sqlmap splits every character into at most 8 threshold probes. For the 7th
character of the `LIMIT 2` password row the probes look like:

| Threshold X | Response             | Meaning |
|---|---|---|
| 64 | `User ID exists in the database.` | char > 64 |
| 96 | `User ID exists...`               | char > 96 |
| 112 | `User ID is MISSING...`           | char ≤ 112 → false |
| 104 | `User ID exists...`               | char > 104 |
| 108 | `User ID is MISSING...`           | char ≤ 108 → false |
| 106 | `User ID exists...`               | char > 106 |

The last TRUE threshold is **106**, so the character is `chr(107)` = `k`.
In general: `char = max(X where TRUE) + 1`. Repeating this for every
position of every queried value reconstructs the entire table:

```
user    user_id   first    last     password
1337    3         Hack     Me       8d3533d75ae2c3966d7e0d4fcc69216b
admin   1         admin    admin    5f4dcc3b5aa765d61d8327deb882cf99
etoo    16        ?        ?        FlagY{f09319a33342ad6
etoo16  94        ?        ?        24b1ea55704766623}
gordonb 2         Gordon   Brown    e99a18c428cb38d5f260853678922e03
pablo   4         Pablo    Picasso  0d107d09f5bbe40cade3de5c71e9e9b7
smithy  5         Bob      Smith    5f4dcc3b5aa765d61d8327deb882cf99
```

`etoo` (LIMIT 4) and `etoo16` (LIMIT 5) are consecutive password rows whose
values concatenate into the flag.

## The calculation

```
char      = max(threshold X that answered TRUE) + 1

probe     : ORD(MID((SELECT ... LIMIT 2,1),7,1)) > 106   ->  TRUE
char      : chr(106 + 1) = 'k'

flag      : password rows of etoo and etoo16 join back together:
            etoo    =  FlagY{f09319a33342ad6
            etoo16  =  24b1ea55704766623}
joined    =  FlagY{f09319a33342ad624b1ea55704766623}
```

---

## Result

```
★  FLAG RECOVERED  ★
FlagY{f09319a33342ad624b1ea55704766623}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| Unfiltered `id` concatenated into a SQL string | `sqli_blind` handler | Boolean-based blind SQL injection |
| Application only echoes "exists / missing" | view | Turns the query into a `TRUE/FALSE` oracle for sqlmap |
| Full verbose ModSecurity audit logging | Apache `modsec_audit.log` | The entire dump process — every payload + answer — is stored on disk |
| No request-size / payload-rate limits | Apache config | 5,395 injection requests blended into normal traffic |

> The real hook of this box: the *defender*'s own security log is what lets
> us recover the *stolen* data.

---

## Takeaways

- **The log is an oracle too.** When an app answers boolean questions,
  its *access* or *WAF* log doubles as a record of the attack itself —
  good for forensics, bad if that log gets leaked.
- **Blind ≠ invisible.** Blind SQLi only hides the direct output; with
  ModSecurity audit logs (or timing, or response size) the data is fully
  recoverable, bit by bit.
- **A flag split across rows is still one flag.** `etoo` + `etoo16`
  concatenated the stolen secret across two records — an easy way to hide
  data from a casual glance.

---

## The solver

`solve_canuyouseeme.py` — points at the folder containing
`apache2/modsec_audit.log`, parses all `ORD(MID(...))>X` probes, rebuilds
the `dvwa.users` table and prints the flag:

```
python solve_canuyouseeme.py
★  FLAG RECOVERED  ★
FlagY{f09319a33342ad624b1ea55704766623}
        elapsed 1.0 s
        etoo + etoo16 join -> flag (blind oracle)
```

It saves the flag to `flag_from_canuyouseeme.txt`.

---

## Credit

- **Writeup by:** General
- **Challenge author:** SAFCSP (Box: *Can You See Me*, SAFCSP).