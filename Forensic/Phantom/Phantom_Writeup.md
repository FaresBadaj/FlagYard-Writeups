# FlagYard CTF — Phantom

**Writeup by [Fares Badaj](https://www.linkedin.com/in/FaresBadaj)**

> **Fares Badaj** — *Red Team Operator | Penetration Tester Specialist*
>
> **Telegram:** [@ptok3](https://t.me/ptok3) · **GitHub:** [github.com/FaresBadaj](https://github.com/FaresBadaj) · **LinkedIn:** [linkedin.com/in/FaresBadaj](https://www.linkedin.com/in/FaresBadaj) · **Credly:** [credly.com/users/faresbadaj](https://www.credly.com/users/faresbadaj)

- **Platform:** FlagYard (Lab Training CTF)
- **Category:** Forensics
- **Difficulty:** Easy (سهل)

---

## The flag

```
FlagY{54ddc3c7d064822eed932015d8740336}
```

---

## The short version

The box ships the `Local` (AppData) folder of a Windows profile. The thing
that matters hides in the Explorer's *thumbnail cache*:

```
Local\Microsoft\Windows\Explorer\thumbcache_1280.db
```

Windows keeps a thumbnail of every picture Explorer has ever shown. When a
file is deleted the **thumbnail outlives the original** — the picture is gone,
its preview is not. `thumbcache_1280.db` (1 MiB) contains exactly **one** cache
entry whose payload is a **902×1280 JPEG** starting at file offset `0x70`:

```
entry header                  file                    payload
+0x00  "CMMM"                 thumbcache_1280.db
+0x18  data size = 108691     0x70  FF D8 FF ..       (JPEG, 902×1280)
+0x1c  width     = 902        0x1A903  FF D9
+0x20  height    = 1280
```

Carving that JPEG out of the blob and OCR'ing it prints the hidden message:

```
Even when a file is gone, a picture might still hold the truth.
Dig deep into the cache.
Congratulations! You found the flag.
```

The flag was **not hidden in bytes** — it is *painted as real text inside the
picture*. That is why the solve needs an OCR step.

---

## First look

- Running the whole profile under a thumbnail parser (e.g. Thumbcache Viewer,
  `thumbcache_parser`) instantly flags the anomaly: `thumbcache_1280.db`
  describes an entry `902×1280` while the sibling `.db` files only store tiny
  icons.
- The `.db` blob is a **flat sequence of cache entries**. Each entry:
  - starts with the ASCII magic `CMMM` (`0x4D4D4D43`),
  - declares its payload size, width and height in its header
    (`+0x18` / `+0x1c` / `+0x20`),
  - packs the real encoded thumbnail right after the header.
- The only three `CMMM` signatures sit at `0x00`, `0x18` and `0x1A906`; the
  meaningful wall clock is:

   ```
   @ 0x18   data_size = 108691   width = 902   height = 1280   -> the flag tile
   ```

- A JPEG signature `FF D8 FF` appears exactly once in the whole file — at
  **offset `0x70`**, the payload of that entry. Everything past
  `0x1A903` (the `FF D9` end-of-image) is empty padding to the 1 MiB boundary.

Take just those bytes (`0x70` .. `0x1A903`), write them to `flag_tile.jpg`,
open the picture — the text is visible to the naked eye.

---

## Understanding the "deleted" image

The original image was removed from disk, but Explorer never re-encodes a
thumbnail on every listing: it stores one preview per picture in
`thumbcache_<size>.db`. Deleting the source **does not delete the cache
entry**.

The header fields prove what the payload is without decoding anything:

```
0x1A893 = 108691  ->  payload length    (== JPEG bytes between FF D8 and FF D9)
0x386   = 902     ->  thumbnail width   (the preview keeps the original aspect)
0x500   = 1280    ->  thumbnail height
```

So the challenge is less "reverse engineering" and more "know Windows keeps
pictures alive in `iconcache`/`thumbcache`". The flag medium is the image
itself.

---

## Recovering the flag

Carve the JPEG (`FF D8 FF … FF D9`) straight out of the `.db`:

```python
data = open(r"Local\Microsoft\Windows\Explorer\thumbcache_1280.db", "rb").read()
j = open("flag_tile.jpg", "wb")
j.write(data[data.index(b"\xff\xd8\xff"):
            data.index(b"\xff\xd9", data.index(b"\xff\xd8\xff")) + 2])
```

Then read the picture (or OCR it, since the text is white-on-grey):

```
$ "C:\Program Files\Tesseract-OCR\tesseract.exe" flag_tile.jpg stdout

Even when a file is
gone, a picture might
still hold the truth. Dig
deep into the cache.
Congratulations! You
found the flag.
FlagY{54ddc3c7d064822eed932015d8740336}
```

Done — the flag was `FlagY{...}` all along, baked into the pixels of a
"deleted" preview.

---

## Why the whole thing falls apart

| Weakness | Where | Consequence |
|---|---|---|
| Thumbnails live in a plain file with magic `CMMM` | `thumbcache_1280.db` | trivially parsable / carvable, no encryption |
| Header stores plaintext width / height / size | entry `+0x18/+0x1c/+0x20` | the interesting tile is located without even decoding |
| JPEG payload stored unencoded between `FF D8`..`FF D9` | entry payload @ `0x70` | one `bytes.index` call recovers the whole picture |
| Deleting a file never purges its thumbnail | Explorer cache lifecycle | the "deleted" picture survives on disk |
| Flag text rendered as pixels, not bytes | inside the image | reproducibly recoverable by OCR |
| The profile is full of `iconcache_*.db` decoys | `Local\...\Explorer` | a good distraction, but only `thumbcache_1280.db` carries a real image |

The "hard" part is just knowing that Windows caches previews of deleted
pictures.

---

## Takeaways

- **Thumbnail caches are forensic gold.** `thumbcache_*.db` / `iconcache_*.db`
  under `Local\Microsoft\Windows\Explorer` preserve previews of files —
  including ones that no longer exist.
- **Cache headers give everything away.** Width, height and payload size live
  in plaintext in the `CMMM` entry; you can triage the interesting image
  before decoding anything.
- **Carving beats parsing.** A single JPEG magic (`FF D8 FF … FF D9`) is
  enough to extract the payload; no full cache-spec parser is required.
- **Not every flag lives in bytes.** When a flag is *printed as text* inside
  an image, OCR is the natural verification step, but sometimes the flag is
  readable by eye directly.
- **The "random" `.db` noise is intentional.** Small icon caches around it
  are decoys; the outlier dimensions (`902×1280`) point to the real picture.

---

## The solver

Colored CLI solver in the same folder, **pure Python (stdlib only)** plus an
optional `tesseract` for the OCR step:

```
solve_phantom.py
```

```bash
python solve_phantom.py            # scans the challenge folder next to it
python solve_phantom.py <folder>   # or point at any extracted profile
```

It finds every `thumbcache_*.db`, parses the `CMMM` entries, carves the
embedded JPEG/PNG payloads, OCR's them and prints the winning flag box, then
saves `flag_from_phantom.txt`:

```
  ✓ tesseract found: C:\Program Files\Tesseract-OCR\tesseract.exe
  ✓ thumbcache databases: 15
    Local\Microsoft\Windows\Explorer\thumbcache_1280.db  w= 902 h=1280 data_size=108691
    thumbcache_1280_112_0.jpg  <ff d8 ff e0 00 10 4a 46>  OCR: FlagY{54ddc3c7d064822eed932015d8740336}

★  FLAG RECOVERED  ★
FlagY{54ddc3c7d064822eed932015d8740336}
        elapsed 0.9 s
        thumbcache_1280.db @ 0x70 | OCR via tesseract
```

---