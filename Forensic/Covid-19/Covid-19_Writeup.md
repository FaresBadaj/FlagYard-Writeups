# FlagYard CTF — Covid-19

**Writeup by [General]**

> **General** — *CTF Player | Forensics & Web Security*
>
> **Platform:** [FlagYard](https://flagyard.com)

- **Platform:** FlagYard (Lab Training CTF)
- **Author:** Flagyard
- **Category:** Forensics
- **Difficulty:** Insane

> *"PharmaMed Inc.'s IT department has identified unusual network activity originating
> from a critical research system involved in Covid-19 vaccine development. Suspicious
> communications suggest that sensitive data may have been exfiltrated by a sophisticated
> threat actor. Your task is to investigate the captured network traffic, system memory,
> and other artifacts to uncover the details of the breach and retrieve the exfiltrated
> data. The flag is hidden within the exfiltrated content."*

---

## The flag

```
FlagY{00d02ed1af60207ae9320b55a1551b3a}
```

---

## The short version

The box ships a **network capture (`output.pcap`)** and two **Windows memory dumps**
(`powershell.DMP`, `svchosts.DMP`). The whole incident is one C2 channel:

- After **RDP initial access** (`192.168.1.5 → 192.168.1.53`) and credential theft
  (`mimikatz`), a **Covenant Grunt** is deployed on the victim and disguised as
  `svchosts`.
- The Grunt beacons to its C2 at **`192.168.1.54:9090`** over an **HTTP profile that
  masquerades as IIS** (`Server: Microsoft-IIS/7.5`).
- Every message body is a **base64 JSON** blob using **AES-256-CBC + HMAC-SHA256**.
- The two keys are recoverable from the **memory dumps**:

  | Key | Value (hex) | Usage |
  |---|---|---|
  | `SetupAESKey` | `a84922eb1888eaf1f1027c20b27840e33c1066bfc6af331ae8e01e216932e414` | handshake |
  | `SessionKey`   | `4ab9e27bfd2c612f4d38b0f58ae2e1b9c5b8dcc27b8939972f98123411dfe14c` | all task traffic |

- Reassemble the TCP streams, decrypt every C2 message, and the **flag appears in a task
  output**:

  ```json
  {"status":"3","output":"FlagY{00d02ed1af60207ae9320b55a1551b3a}"}
  ```

---

## Step 1 — the attack chain in the PCAP

Filtering for the C2 port `9090` (`192.168.1.53:50209 ↔ 192.168.1.54:9090`) exposes the
implant traffic. Earlier packets show the RDP session and the `mimikatz` / .NET assembly
downloads that set it up. The channel itself looks like IIS web traffic:

```
POST /en-us/test.html HTTP/1.1
Cookie: ASPSESSIONID=ae67e78388; SESSIONID=1552332971750
User-Agent: Mozilla/5.0 (…) Chrome/41.0.2228.0

i=a19ea23062db990386a3a478cb89d52e&data=<base64(JSON)>&session=75db-99b1-…-320bea73
```

The JSON carried in `data=` (requests) and in the response body is:

```json
{
  "GUID": "ae67e78388",
  "Type": 0,
  "Meta": "…",
  "IV": "<base64>",
  "EncryptedMessage": "<base64>",
  "HMAC": "<base64>"
}
```

## Step 2 — the keys (from the memory dumps)

`strings` over the memory dumps surfaces the two AES-256 keys. The handshake uses
`SetupAESKey`; everything after the handshake is protected by `SessionKey`.

## Step 3 — decrypt

For each message:

1. base64-decode `IV`, `EncryptedMessage`, `HMAC`;
2. check integrity: `HMAC-SHA256(SessionKey, EncryptedMessage) == HMAC`;
3. `AES-256-CBC` decrypt with `SessionKey` + the message IV;
4. strip PKCS7 padding — the plaintext is JSON.

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as c_hmac
import base64

KEY = bytes.fromhex("4ab9e27bfd2c612f4d38b0f58ae2e1b9c5b8dcc27b8939972f98123411dfe14c")

def decrypt(j, key=KEY):
    iv = base64.b64decode(j["IV"])
    em = base64.b64decode(j["EncryptedMessage"])
    hm = base64.b64decode(j["HMAC"])
    h = c_hmac.HMAC(key, hashes.SHA256()); h.update(em)
    assert h.finalize() == hm, "HMAC mismatch"
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = c.update(em) + c.finalize()
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad else pt
```

## Step 4 — the flag

Decrypting all ~40 request/response messages, one task output carries the flag:

```json
{"status":"3","output":"FlagY{00d02ed1af60207ae9320b55a1551b3a}"}
```

The same value also appears base64-encoded in another message
(`RmxhZ1l7MDBkMDJlZDFhZjYwMjA3YWU5MzIwYjU1YTE1NTFiM2F9`), which decodes to the
identical string.

```
★  FLAG RECOVERED  ★
FlagY{00d02ed1af60207ae9320b55a1551b3a}
```

---

## Root causes (what actually went wrong)

| Weakness | Where | Consequence |
|---|---|---|
| C2 traffic hidden in a fake IIS HTTP profile | TCP/9090, `Server: Microsoft-IIS/7.5` | Blends into web noise on the wire |
| Symmetric keys left in memory | `powershell.DMP`, `svchosts.DMP` | AES-256 session compromised once dumps are read |
| No forward secrecy / static session key | Covenant Grunt config | All captured traffic is decryptable offline |
| Exfiltrated data returned in C2 task output | JSON `output` field | The flag sits in plaintext after decryption |
| RDP + `mimikatz` for initial access | `192.168.1.5 → .53` | Full host compromise without a remote exploit |

---

## Takeaways

- **Identify the implant first.** The IIS-looking headers are a Covenant HTTP profile —
  a known C2, not a webserver. Port + beacon pattern gives it away.
- **Memory is where the keys live.** PCAP alone is opaque; the dumps hand you the
  `SetupAESKey`/`SessionKey`.
- **Reassemble before you parse.** C2 bodies span TCP segments; order by `seq` and you
  get clean JSON.
- **Verify, then decrypt.** The HMAC tells you which key/IV are correct before you try to
  read the plaintext.

---

## The solver

`solve_covid19.py` — points at the challenge folder (default: the folder of the script),
reassembles the port-9090 streams, parses the HTTP bodies, verifies the HMAC and
AES-256-CBC-decrypts each message with the embedded keys, then prints the flag box:

```
pip install cryptography
python solve_covid19.py
★  FLAG RECOVERED  ★
FlagY{00d02ed1af60207ae9320b55a1551b3a}
        elapsed 25.0 s
        Covenant C2 on TCP/9090 | AES-256-CBC + HMAC-SHA256
```

It saves the flag to `flag_from_covid19.txt`.

---

## Credit

- **Writeup by:** General
- **Challenge author:** Flagyard (Box: *Covid-19*).
