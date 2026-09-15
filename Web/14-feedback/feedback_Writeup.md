FlagYard | feedback (Web — Easy) — Writeup

**Fares Badaj**

---

## Info

| | |
|---|---|
| Challenge | feedback |
| Difficulty | Easy |
| Category | Web |
| Platform | FlagYard Training Labs (SAFCSP) |
| Description | *Submit your feedback.* |
| Flag | `FlagY{78909649470553629b1438ebc5e435b8}` |

---

## 1. Recon

Flask + SQLite app with register / login. Once logged in, a logged-in user
can POST `feedback` to `/`. The flag lives in a dedicated `flag` table that is
**never rendered anywhere** — it is only seeded at startup:

```python
db.insert("INSERT INTO flag(flag) VALUES (?)", "FlagY{fake_flag}")
```

## 2. Injection point

`app.py:95` builds the INSERT with string formatting — only the `username`
value is parameterized, the `feedback` value is concatenated raw:

```python
query = db.insert(
    "INSERT INTO feedback(username, feedback) VALUES(?,'%s')" % feedback,
    session['username'])
```

So the feedback field is a clean second-order SQL injection point:

```sql
INSERT INTO feedback(username, feedback) VALUES('me','{FEEDBACK}')
```

## 3. The constraints that make a blind oracle

Two facts in the schema give us everything we need:

* `feedback(username text NOT NULL, feedback text NOT NULL)`
* SQL errors are swallowed — `db.insert` returns `True/False`, and the page
  distinguishes:
  * INSERT ok          → `Thanks for the feedback`
  * INSERT raised      → `Something went wrong`

Classic "error branch reads a missing table" does **not** work here: SQLite
resolves table names at *prepare* time, so `FROM zzzz` throws even when its
CASE branch is never taken.

## 4. The NULL-constraint oracle

Instead of missing tables, abuse the **NOT NULL** constraint on the
`feedback` column. Close the string slot, and make the second VALUE a single
concatenation expression:

```
feedback = ' || (CASE WHEN COND THEN NULL ELSE 'x' END) || '
```

```sql
INSERT INTO feedback(username, feedback)
VALUES('me',
       '' || (CASE WHEN (SELECT substr(flag,1,1) FROM flag) = 'F'
                   THEN NULL ELSE 'x' END) || '')
```

* **CHAR MATCHES** → the CASE yields `NULL` → `feedback` violates `NOT NULL`
  → sqlite3 raises → *"Something went wrong"*
* **CHAR DIFFERS** → the CASE yields `'x'` → INSERT succeeds → *"Thanks for
  the feedback"*

(Inverted, but deterministic.)

## 5. Char-by-char extraction

Probe `substr(flag, n, 1) = c` for every position with charset
`FlagY{}0123456789abcdef`. The `flag` row is `FlagY{<md5>}` so only the
6-character head + 32 hex + braces need enumerating.

Result (179 s, ~280 requests):

```
FlagY{78909649470553629b1438ebc5e435b8}
```

## 6. Blacklist bypass

The app also filters feedback for `exec, load, blob, glob, union, join, like,
match, regexp, in, limit, order, hex, where`. The oracle never needs any of
them — `substr`, `flag`, `select`, `null` pass untouched.

---

## Root cause

* SQLf string-formatted concatenation of user input into an INSERT
  (`VALUES(?,'%s')`) while only one binding is parameterized.
* Schema constraint (`NOT NULL`) exported as a usable boolean oracle because
  errors are swallowed but mapped to a distinct UI message.

## Remediation

* Parameterize **every** value (`VALUES(?,?)`); never format user input into
  SQL.
* Gate feedback behind same policy as DB (allow/deny), sanitize input.
* Do not let backend exceptions produce distinguishable client states.

## Files

* `solve_feedback.py` — automated blind SQLi extractor.
* `flag_from_feedback.txt` — `FlagY{78909649470553629b1438ebc5e435b8}`.