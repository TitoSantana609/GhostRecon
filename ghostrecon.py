#!/usr/bin/env python3
"""
GhostRecon
----------
@TitoSantana00's consolidated recon GUI (merge of recon_gui.py + SantanaScanner.py).

Pipeline:
    Subdomains -> Live Hosts (httpx) -> Ports / Vulns (nuclei) / URLs -> gf patterns
                                     -> Dir busting (dirb + ffuf, merged)

Each stage writes persistent results to:  results/<target>/<timestamp>/<tool>.txt
and can pull its input from the previous stage.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import re
import threading
import shutil
import datetime
import glob
import tempfile
import json
import queue
import random
import string
import time

try:
    import pyfiglet
    print(pyfiglet.figlet_format("GhostRecon"))
    print("           by @TitoSantana00\n")
except Exception:
    print("=== GhostRecon by @TitoSantana00 ===")


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(?:\.[A-Za-z0-9-]{1,63})+$'
)
HOST_RE = re.compile(
    # Allow leading underscore labels (CT surfaces names like _mta-sts, _dmarc)
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)'
    r'(?:\.[A-Za-z0-9_-]{1,63})*$'
)
IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
URL_RE = re.compile(r'^(https?://)?[A-Za-z0-9.-]+(:\d+)?(/\S*)?$')


def is_domain(value):
    return bool(DOMAIN_RE.match(value))


def is_host(value):
    return bool(HOST_RE.match(value) or IP_RE.match(value))


def is_url(value):
    return bool(URL_RE.match(value))


def sanitize_for_path(value):
    return re.sub(r'[^A-Za-z0-9._-]', '_', value).strip('_') or "target"


ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')
FFUF_NUM_RE = re.compile(r'^[0-9][0-9,\- ]*$')   # e.g. "404", "0-100,4242"


def strip_ansi(text):
    return ANSI_RE.sub('', text)


def parse_ranges(value):
    """'200-299,301' -> [(200, 299), (301, 301)]"""
    out = []
    for part in value.replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out


def in_ranges(value, ranges):
    return any(lo <= value <= hi for lo, hi in ranges)


FFUF_DEFAULT_MC = "200-299,301,302,307,401,403,405,500"


# --------------------------------------------------------------------------- #
# Scope parsing (bug-bounty scope files: .txt / .csv / .json)
# --------------------------------------------------------------------------- #
# Asset-type / identifier hints that aren't web targets we can scan.
NON_WEB_HINT = re.compile(
    r'(play\.google|itunes\.apple|apps\.apple|GOOGLE_PLAY|APPLE_STORE|'
    r'ANDROID|IOS|WINDOWS_APP|SOURCE_CODE|CIDR|SMART_CONTRACT|'
    r'TESTFLIGHT|OTHER_?APK|HARDWARE|EXECUTABLE)', re.I)
# App package IDs are reverse-DNS (com.example.app). Nobody names a real
# subdomain "com"/"org"/"net", so a leading one of those with 3+ labels is a
# package id, not a scannable host. (Kept deliberately narrow: "app", "io",
# "dev", "me" etc. ARE common subdomains, so they're not treated as packages.)
PACKAGE_PREFIX = {"com", "org", "net"}


def host_from_identifier(value):
    """Reduce a scope identifier to a scannable host/wildcard, or None.

    'https://app.example.com/x' -> 'app.example.com'
    '*.example.com'             -> '*.example.com'
    'com.example.app' (pkg)     -> None (not a web host)
    """
    if not value:
        return None
    v = value.strip().strip('"').strip()
    if not v or " " in v or NON_WEB_HINT.search(v):
        return None
    v = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', v)   # strip scheme
    v = v.split("/")[0].split("?")[0]                    # strip path/query
    v = v.rsplit(":", 1)[0] if re.search(r':\d+$', v) else v  # strip :port
    v = v.strip().rstrip(".").lower()
    if v.startswith("*.") and is_domain(v[2:]):
        return v
    labels = v.split(".")
    if len(labels) >= 3 and labels[0] in PACKAGE_PREFIX:
        return None   # reverse-DNS package id (com.example.app), not a host
    if is_host(v) and ("." in v):
        return v
    return None


def scope_pattern(host):
    """Compile a scope host/wildcard into a regex matching it and its subdomains."""
    base = host[2:] if host.startswith("*.") else host
    return re.compile(r'^(?:[A-Za-z0-9_-]+\.)*' + re.escape(base) + r'$', re.I)


def _rows_from_json(data):
    """Yield (identifier, eligible_bool_or_None) from assorted JSON scope shapes."""
    if isinstance(data, dict):
        # {"in_scope": [...], "out_of_scope": [...]} / include / exclude
        for inc in ("in_scope", "include", "included", "targets", "scope"):
            if isinstance(data.get(inc), list):
                for x in data[inc]:
                    yield from _rows_from_json(x) if isinstance(x, (dict, list)) \
                        else [(x, True)]
        for exc in ("out_of_scope", "exclude", "excluded", "out_scope"):
            if isinstance(data.get(exc), list):
                for x in data[exc]:
                    yield from ((i, False) for i, _ in _rows_from_json(x)) \
                        if isinstance(x, (dict, list)) else [(x, False)]
        # HackerOne structured scope: {"data":[{"attributes":{...}}]}
        if isinstance(data.get("data"), list):
            for x in data["data"]:
                yield from _rows_from_json(x)
        if "attributes" in data and isinstance(data["attributes"], dict):
            data = data["attributes"]
        ident = next((data[k] for k in (
            "asset_identifier", "identifier", "target", "url", "host",
            "domain", "asset", "name") if data.get(k)), None)
        if ident:
            elig = data.get("eligible_for_submission", data.get("in_scope",
                   data.get("eligible", True)))
            yield (ident, bool(elig) if elig is not None else True)
    elif isinstance(data, list):
        for x in data:
            yield from _rows_from_json(x)
    elif isinstance(data, str):
        yield (data, True)


def parse_scope_file(path):
    """Parse a .txt/.csv/.json scope file into a de-duplicated list of entries.

    Returns list of dicts: {"raw", "host", "scope": "in"|"out"}.
    Text rules: '#' comment; leading '!' or '-' marks out-of-scope.
    """
    ext = os.path.splitext(path)[1].lower()
    rows = []   # (raw_identifier, eligible_bool)
    if ext == ".json":
        with open(path, errors="replace") as f:
            rows = list(_rows_from_json(json.load(f)))
    elif ext == ".csv":
        import csv
        with open(path, newline="", errors="replace") as f:
            sample = f.read(2048)
            f.seek(0)
            has_header = csv.Sniffer().has_header(sample) if sample.strip() else False
            reader = csv.reader(f)
            header = [h.strip().lower() for h in next(reader, [])] if has_header else []
            id_col = next((i for i, h in enumerate(header) if h in (
                "identifier", "asset_identifier", "target", "url", "host",
                "domain", "asset", "name")), 0)
            elig_col = next((i for i, h in enumerate(header) if h in (
                "eligible_for_submission", "in_scope", "eligible", "scope")), None)
            if not has_header:
                f.seek(0)
                reader = csv.reader(f)
            for parts in reader:
                if not parts or not parts[id_col if id_col < len(parts) else 0].strip():
                    continue
                raw = parts[id_col if id_col < len(parts) else 0]
                elig = True
                if elig_col is not None and elig_col < len(parts):
                    elig = str(parts[elig_col]).strip().lower() not in (
                        "false", "no", "0", "out", "out_of_scope", "")
                rows.append((raw, elig))
    else:   # treat everything else as plain text
        with open(path, errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                out = ln[0] in "!-"
                rows.append((ln.lstrip("!- ").strip(), not out))

    entries, seen = [], set()
    for raw, elig in rows:
        host = host_from_identifier(raw)
        if not host or host in seen:
            continue
        seen.add(host)
        entries.append({"raw": raw.strip(), "host": host,
                        "scope": "in" if elig else "out"})
    return entries


# --------------------------------------------------------------------------- #
# Directory busting: wordlists + throttle presets
# --------------------------------------------------------------------------- #
# dirb's own standard list.
DIRB_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
# ffuf: first one that exists wins. raft-medium-directories is the usual
# best-balance pick (~30k entries, built from real-world crawl data).
FFUF_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    DIRB_WORDLIST,
]
# name -> (threads, max requests/sec (0 = unlimited), random jitter)
THROTTLE_PRESETS = {
    "Aggressive (no limit)": (40, 0, False),
    "Normal": (20, 50, False),
    "Polite": (5, 10, False),
    "Stealth (WAF-safe)": (1, 2, True),
}
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# --------------------------------------------------------------------------- #
# JavaScript analysis: pull endpoints + secrets out of .js source (no deps, so
# it works without jsluice; jsluice is used too when present for richer results)
# --------------------------------------------------------------------------- #
JS_URL_RE = re.compile(r'''https?://[^\s'"`<>()]{3,}''')
JS_PATH_RE = re.compile(r'''['"`](/[A-Za-z0-9_./~-][^\s'"`<>]{1,120})['"`]''')
JS_APICALL_RE = re.compile(
    r'''(?:fetch|axios|\.(?:get|post|put|delete|patch|ajax|open))\s*\(\s*'''
    r'''['"`]([^'"`]{2,160})['"`]''', re.I)
# (label, regex) -- secret-ish tokens worth a manual look.
JS_SECRET_PATTERNS = [
    ("google_api_key", re.compile(r'AIza[0-9A-Za-z_\-]{35}')),
    ("aws_access_key", re.compile(r'A(?:KIA|SIA|GPA|IDA|ROA)[0-9A-Z]{16}')),
    ("slack_token", re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,48}')),
    ("slack_webhook", re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/+]{20,}')),
    ("stripe_key", re.compile(r'[sr]k_live_[0-9A-Za-z]{20,40}')),
    ("github_token", re.compile(r'gh[pousr]_[0-9A-Za-z]{30,}')),
    ("google_oauth", re.compile(r'ya29\.[0-9A-Za-z_\-]{20,}')),
    ("jwt", re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("firebase_db", re.compile(r'[a-z0-9.-]+\.firebaseio\.com')),
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ("authorization", re.compile(r'[Aa]uthorization["\']?\s*[:=]\s*["\']?'
                                 r'(?:Bearer|Basic)\s+[A-Za-z0-9._\-+/=]{10,}')),
    ("generic_secret", re.compile(
        r'(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|'
        r'auth[_-]?token|password|passwd)["\']?\s*[:=]\s*["\']([^"\'\s]{8,64})["\']')),
]
# Things that look like secrets but aren't worth reporting.
JS_SECRET_IGNORE = re.compile(r'(?i)(example|xxxx|your[_-]?|placeholder|null|undefined|'
                              r'process\.env|import\.meta|\{\{|\}\})')


def extract_js_endpoints(text):
    found = set()
    for m in JS_URL_RE.finditer(text):
        found.add(m.group(0).rstrip('\\'))
    for m in JS_PATH_RE.finditer(text):
        p = m.group(1)
        if not re.fullmatch(r'/[\d.]+', p):          # skip bare "/1.2"
            found.add(p)
    for m in JS_APICALL_RE.finditer(text):
        found.add(m.group(1))
    # drop obvious noise: css/image data and single-segment junk
    return sorted(e for e in found
                  if not e.lower().startswith(("data:", "blob:"))
                  and len(e) <= 200)


def beautify_js(code):
    """Reformat minified JS into readable, indented multi-line code.

    Returns (text, method). Prefers the pure-Python jsbeautifier library (no
    Node needed); falls back to the js-beautify CLI; else returns code as-is.
    Note: this reflows whitespace/statements -- it does NOT rename mangled
    variables (true de-obfuscation needs heavier, Node-based tooling).
    """
    if not code or not code.strip():
        return code, "none"
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.max_preserve_newlines = 2
        return jsbeautifier.beautify(code, opts), "jsbeautifier"
    except ImportError:
        pass
    except Exception:
        return code, "error"
    exe = shutil.which("js-beautify")
    if exe:
        try:
            r = subprocess.run([exe, "-"], input=code, capture_output=True,
                               text=True, timeout=40)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout, "js-beautify cli"
        except (subprocess.SubprocessError, OSError):
            pass
    return code, "none"


def extract_js_secrets(text):
    out = []
    seen = set()
    for label, rx in JS_SECRET_PATTERNS:
        for m in rx.finditer(text):
            hit = m.group(0)
            if JS_SECRET_IGNORE.search(hit):
                continue
            key = (label, hit)
            if key in seen:
                continue
            seen.add(key)
            out.append((label, hit.strip()))
    return out


# --------------------------------------------------------------------------- #
# Global request options (proxy / headers / rate) -- how each tool spells them.
# Tools absent from a table simply don't get that option injected.
# --------------------------------------------------------------------------- #
# Proxy flag per tool (value is the proxy URL).
PROXY_FLAG = {
    "httpx": "-http-proxy", "katana": "-proxy", "nuclei": "-proxy",
    "dnsx": "-proxy", "naabu": "-proxy", "ffuf": "-x",
    "wpscan": "--proxy", "nikto": "-useproxy", "kr": "--proxy",
}
# Requests/sec cap per tool (0/unset = no cap). ffuf/dirb carry their own in the
# Dir Busting tab, so they're injected there, not globally.
RATE_FLAG = {
    "httpx": "-rate-limit", "nuclei": "-rate-limit",
    "katana": "-rate-limit", "naabu": "-rate",
}
# How a tool accepts custom headers:
#   "-H"/"-Add-header" -> repeat the flag once per "Name: Value"
#   "join"             -> one flag, headers joined by "; " (wpscan)
#   "nl"               -> one flag, headers joined by newlines (arjun)
HEADER_STYLE = {
    "httpx": ("-H", "repeat"), "katana": ("-H", "repeat"),
    "nuclei": ("-H", "repeat"), "ffuf": ("-H", "repeat"),
    "dirb": ("-H", "repeat"), "nikto": ("-Add-header", "repeat"),
    "wpscan": ("--headers", "join"), "arjun": ("--headers", "nl"),
    "kr": ("-H", "repeat"),
}
DEFAULT_SETTINGS = {
    "proxy_on": False, "proxy_url": "http://127.0.0.1:8080",
    "headers": [], "cookie": "",
    "bb_on": False, "bb_header": "X-Bug-Bounty", "bb_value": "",
    "rate": 0,            # global requests/sec cap (0 = unlimited)
    "browser_ua": False,  # send a real-browser User-Agent everywhere
    # Out-of-band / OAST testing
    "oob_server": "",     # self-hosted interactsh server (nuclei -iserver)
    "oob_token": "",      # interactsh auth token (nuclei -itoken)
    "oob_host": "",       # a callback host/payload domain for manual use / Collaborator
    "oob_disable": False, # disable OAST entirely (nuclei -ni) when a program forbids it
}


# --------------------------------------------------------------------------- #
# Themes
# --------------------------------------------------------------------------- #
THEMES = {
    "light": {
        "bg": "#ececec", "fg": "#1a1a1a", "text_bg": "#ffffff",
        "text_fg": "#111111", "entry_fg": "#111111", "accent": "#0056b3",
        "tab_bg": "#cfcfcf", "tab_fg": "#333333",
    },
    "dark": {
        "bg": "#1e1e1e", "fg": "#e6e6e6", "text_bg": "#0d1117",
        "text_fg": "#39ff6a", "entry_fg": "#e6e6e6", "accent": "#2ea043",
        "tab_bg": "#2b2b2b", "tab_fg": "#cccccc",
    },
}


class GhostReconGUI:
    def __init__(self, master):
        self.master = master
        master.title("GhostRecon — @TitoSantana00")
        master.geometry("1200x800")
        master.minsize(900, 640)

        self.theme_name = "dark"
        self.running = False
        self.run_buttons = []          # all buttons disabled during a scan
        self.active_output = None      # Text widget the current scan streams into
        self.current_proc = None       # running subprocess (for Stop)
        self.stop_requested = False    # lets multi-target loops bail out on Stop

        # shared pipeline state (results carried between tabs)
        self.state = {
            "target": None,
            "outdir": None,
            "subdomains": [],
            "live_hosts": [],
            "live_urls": [],           # httpx results with scheme (http/https)
            "urls": [],
            "dirs": [],                # merged dirb + ffuf findings
        }

        # Global request options (Burp proxy, headers, cookie, rate) shared by
        # every tool. Loaded from disk so they persist across runs.
        self.gopts = dict(DEFAULT_SETTINGS)
        self._load_settings()

        # Scope: parsed targets + compiled in/out patterns, and per-row checkboxes.
        self.scope = {"entries": [], "in_pats": [], "out_pats": [], "file": None}
        self._scope_checked = {}       # tree iid -> bool

        # Make sure go/pip user bin dirs are visible so freshly-installed tools resolve
        for p in ("~/go/bin", "~/.local/bin"):
            p = os.path.expanduser(p)
            if os.path.isdir(p) and p not in os.environ.get("PATH", ""):
                os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")

        self.style = ttk.Style()
        self._build_menu()
        self.create_welcome_screen()

    # ------------------------------------------------------------------ #
    # Welcome screen
    # ------------------------------------------------------------------ #
    def create_welcome_screen(self):
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        self.welcome_frame = ttk.Frame(self.master, padding="20")
        self.welcome_frame.grid(row=0, column=0, sticky="nsew")
        self.welcome_frame.grid_rowconfigure(0, weight=1)
        self.welcome_frame.grid_rowconfigure(3, weight=1)
        self.welcome_frame.grid_columnconfigure(0, weight=1)

        ttk.Label(self.welcome_frame, text="👻 GhostRecon",
                  font=("Helvetica", 30, "bold")).grid(row=1, column=0, pady=(0, 6))
        ttk.Label(self.welcome_frame,
                  text="Subdomains · Live Hosts · URLs · Ports · Vulns · Dir Busting",
                  font=("Helvetica", 12)).grid(row=2, column=0, pady=(0, 20))

        start = ttk.Button(self.welcome_frame, text="Start",
                           command=self.show_main_screen)
        start.grid(row=3, column=0)
        self.apply_theme()

    def show_main_screen(self):
        self.welcome_frame.destroy()
        self.create_main_widgets()
        self.apply_theme()
        self.check_dependencies(initial=True)

    # ------------------------------------------------------------------ #
    # Menu
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # Global request options: persistence + command augmentation
    # ------------------------------------------------------------------ #
    @staticmethod
    def _settings_path():
        d = os.path.expanduser("~/.config/ghostrecon")
        return os.path.join(d, "settings.json")

    def _load_settings(self):
        try:
            with open(self._settings_path()) as f:
                saved = json.load(f)
            for k in DEFAULT_SETTINGS:
                if k in saved:
                    self.gopts[k] = saved[k]
        except (OSError, ValueError):
            pass   # no/with bad settings file -> keep defaults

    def _save_settings(self):
        path = self._settings_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(self.gopts, f, indent=2)
            os.chmod(path, 0o600)   # may hold a session cookie -> keep it private
        except OSError as e:
            messagebox.showwarning("Settings", f"Could not save settings:\n{e}")

    def _all_headers(self):
        """Every header to send: user headers + Cookie + X-Bug-Bounty + UA."""
        headers = []
        for h in self.gopts["headers"]:
            if ":" in h:
                headers.append(h.strip())
        if self.gopts["cookie"].strip():
            headers.append(f"Cookie: {self.gopts['cookie'].strip()}")
        if self.gopts["bb_on"] and self.gopts["bb_value"].strip():
            headers.append(f"{self.gopts['bb_header'].strip()}: "
                           f"{self.gopts['bb_value'].strip()}")
        if self.gopts["browser_ua"]:
            headers.append(f"User-Agent: {BROWSER_UA}")
        return headers

    def _proxy_url(self):
        return self.gopts["proxy_url"].strip() if self.gopts["proxy_on"] else None

    def augment(self, cmd, tool):
        """Return cmd (a list) with the global proxy, headers and rate cap added
        in `tool`'s own flag syntax. Unknown options for a tool are skipped."""
        if not isinstance(cmd, list):
            return cmd   # shell-string commands are augmented by their builders
        cmd = list(cmd)
        proxy = self._proxy_url()
        if proxy and tool in PROXY_FLAG:
            cmd += [PROXY_FLAG[tool], proxy]
        rate = self.gopts["rate"]
        if rate and tool in RATE_FLAG:
            cmd += [RATE_FLAG[tool], str(rate)]
        headers = self._all_headers()
        if headers and tool in HEADER_STYLE:
            flag, style = HEADER_STYLE[tool]
            if style == "repeat":
                for h in headers:
                    cmd += [flag, h]
            elif style == "join":
                cmd += [flag, "; ".join(headers)]
            elif style == "nl":
                cmd += [flag, "\n".join(headers)]
        return cmd

    def nuclei_oob_args(self):
        """nuclei interactsh/OAST flags for the configured callback server."""
        if self.gopts["oob_disable"]:
            return ["-ni"]            # no-interactsh: skip OAST templates entirely
        args = []
        if self.gopts["oob_server"].strip():
            args += ["-iserver", self.gopts["oob_server"].strip()]
            if self.gopts["oob_token"].strip():
                args += ["-itoken", self.gopts["oob_token"].strip()]
        return args

    def proxy_summary(self):
        p = self._proxy_url()
        bits = []
        if p:
            bits.append(f"proxy {p}")
        if self._all_headers():
            bits.append(f"{len(self._all_headers())} header(s)")
        if self.gopts["rate"]:
            bits.append(f"{self.gopts['rate']} req/s")
        if self.gopts["oob_disable"]:
            bits.append("OAST off")
        elif self.gopts["oob_server"].strip():
            bits.append(f"OAST {self.gopts['oob_server'].strip()}")
        return " · ".join(bits) if bits else "no global options set"

    def open_global_settings(self):
        win = tk.Toplevel(self.master)
        win.title("Global request settings")
        win.geometry("660x780")
        t = THEMES[self.theme_name]
        win.configure(bg=t["bg"])
        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        g = self.gopts
        row = 0

        def section(title):
            nonlocal row
            ttk.Label(frm, text=title, font=("Helvetica", 11, "bold")
                      ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(10, 2))
            row += 1

        section("Burp / upstream proxy")
        proxy_on = tk.BooleanVar(value=g["proxy_on"])
        ttk.Checkbutton(frm, text="Route tool traffic through a proxy",
                        variable=proxy_on).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Label(frm, text="Proxy URL:").grid(row=row, column=0, sticky="w")
        proxy_url = tk.StringVar(value=g["proxy_url"])
        ttk.Entry(frm, textvariable=proxy_url).grid(row=row, column=1, columnspan=2,
                                                    sticky="ew", padx=4)
        row += 1
        ttk.Label(frm, text="Burp default is http://127.0.0.1:8080. Applies to httpx, "
                            "katana, nuclei,\nffuf, naabu, dnsx, wpscan, nikto.",
                  foreground=t["tab_fg"]).grid(row=row, column=0, columnspan=3,
                                               sticky="w", pady=(0, 4))
        row += 1

        section("Custom headers (one per line, \"Name: Value\")")
        headers_txt = tk.Text(frm, height=5, wrap=tk.NONE, font=("Courier New", 10),
                              bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["text_fg"])
        headers_txt.grid(row=row, column=0, columnspan=3, sticky="ew")
        headers_txt.insert("1.0", "\n".join(g["headers"]))
        row += 1
        ttk.Label(frm, text="Cookie:").grid(row=row, column=0, sticky="w", pady=(4, 0))
        cookie = tk.StringVar(value=g["cookie"])
        ttk.Entry(frm, textvariable=cookie).grid(row=row, column=1, columnspan=2,
                                                 sticky="ew", padx=4, pady=(4, 0))
        row += 1

        section("Bug-bounty identification header")
        bb_on = tk.BooleanVar(value=g["bb_on"])
        ttk.Checkbutton(frm, text="Send an identifying header (many programs require it)",
                        variable=bb_on).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        bbframe = ttk.Frame(frm)
        bbframe.grid(row=row, column=0, columnspan=3, sticky="ew")
        ttk.Label(bbframe, text="Header:").pack(side="left")
        bb_header = tk.StringVar(value=g["bb_header"])
        ttk.Entry(bbframe, textvariable=bb_header, width=18).pack(side="left", padx=4)
        ttk.Label(bbframe, text="Value (e.g. your H1/username):").pack(side="left")
        bb_value = tk.StringVar(value=g["bb_value"])
        ttk.Entry(bbframe, textvariable=bb_value).pack(side="left", fill="x",
                                                       expand=True, padx=4)
        row += 1

        section("Throttle / fingerprint")
        uaframe = ttk.Frame(frm)
        uaframe.grid(row=row, column=0, columnspan=3, sticky="ew")
        browser_ua = tk.BooleanVar(value=g["browser_ua"])
        ttk.Checkbutton(uaframe, text="Send a real-browser User-Agent",
                        variable=browser_ua).pack(side="left")
        ttk.Label(uaframe, text="   Global max req/s (0 = unlimited):").pack(side="left")
        rate = tk.IntVar(value=g["rate"])
        ttk.Spinbox(uaframe, from_=0, to=1000, width=6, textvariable=rate
                    ).pack(side="left", padx=4)
        row += 1
        ttk.Label(frm, text="Rate cap applies to httpx, nuclei, katana, naabu. Dir Busting\n"
                            "keeps its own per-scan throttle.", foreground=t["tab_fg"]
                  ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))
        row += 1

        section("Out-of-band / OAST (interactsh · Collaborator)")
        ttk.Label(frm, text="interactsh server:").grid(row=row, column=0, sticky="w")
        oob_server = tk.StringVar(value=g["oob_server"])
        ttk.Entry(frm, textvariable=oob_server).grid(row=row, column=1, columnspan=2,
                                                     sticky="ew", padx=4)
        row += 1
        ttk.Label(frm, text="interactsh token:").grid(row=row, column=0, sticky="w")
        oob_token = tk.StringVar(value=g["oob_token"])
        ttk.Entry(frm, textvariable=oob_token, show="*").grid(row=row, column=1,
                                                             columnspan=2, sticky="ew", padx=4)
        row += 1
        ttk.Label(frm, text="Callback host:").grid(row=row, column=0, sticky="w")
        hostframe = ttk.Frame(frm)
        hostframe.grid(row=row, column=1, columnspan=2, sticky="ew", padx=4)
        hostframe.columnconfigure(0, weight=1)
        oob_host = tk.StringVar(value=g["oob_host"])
        ttk.Entry(hostframe, textvariable=oob_host).grid(row=0, column=0, sticky="ew")

        def copy_host():
            h = oob_host.get().strip()
            if h:
                self.master.clipboard_clear()
                self.master.clipboard_append(h)
                self.update_status(f"Copied callback host: {h}")
        ttk.Button(hostframe, text="Copy", command=copy_host).grid(row=0, column=1, padx=(4, 0))
        row += 1
        oob_disable = tk.BooleanVar(value=g["oob_disable"])
        ttk.Checkbutton(frm, text="Disable OAST entirely (nuclei -ni) — for programs that "
                                 "forbid out-of-band testing", variable=oob_disable
                        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Label(frm, text="Server + token drive nuclei's interactsh (-iserver/-itoken). "
                            "The callback host is\nyours to paste into manual payloads / "
                            "Burp Collaborator (use Copy).", foreground=t["tab_fg"]
                  ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))
        row += 1

        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="e", pady=(8, 0))

        def save():
            rate_val = rate.get() if str(rate.get()).isdigit() else 0
            px = proxy_url.get().strip()
            if proxy_on.get() and not re.match(r'^(https?|socks5h?)://', px, re.I):
                messagebox.showwarning("Proxy", "Proxy URL must start with http://, "
                                               "https:// or socks5://.", parent=win)
                return
            self.gopts.update({
                "proxy_on": proxy_on.get(), "proxy_url": px or DEFAULT_SETTINGS["proxy_url"],
                "headers": [ln.strip() for ln in
                            headers_txt.get("1.0", tk.END).splitlines() if ln.strip()],
                "cookie": cookie.get().strip(),
                "bb_on": bb_on.get(), "bb_header": bb_header.get().strip() or "X-Bug-Bounty",
                "bb_value": bb_value.get().strip(),
                "rate": max(0, rate_val), "browser_ua": browser_ua.get(),
                "oob_server": oob_server.get().strip(), "oob_token": oob_token.get().strip(),
                "oob_host": oob_host.get().strip(), "oob_disable": oob_disable.get(),
            })
            self._save_settings()
            self.update_status(f"Global settings saved — {self.proxy_summary()}")
            win.destroy()

        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="Save", command=save).pack(side="right")

    def _build_menu(self):
        menubar = tk.Menu(self.master)
        view = tk.Menu(menubar, tearoff=0)
        view.add_command(label="Toggle dark/light", command=self.toggle_theme)
        menubar.add_cascade(label="View", menu=view)

        tools = tk.Menu(menubar, tearoff=0)
        tools.add_command(label="Check dependencies", command=self.check_dependencies)
        menubar.add_cascade(label="Tools", menu=tools)

        settings = tk.Menu(menubar, tearoff=0)
        settings.add_command(label="Global request settings (proxy / headers)…",
                             command=self.open_global_settings)
        settings.add_separator()
        settings.add_command(label="Install missing tools…",
                             command=self.open_install_dialog)
        settings.add_separator()
        settings.add_command(label="Update nuclei engine…",
                             command=self.update_nuclei_engine)
        settings.add_command(label="Update nuclei templates…",
                             command=self.update_nuclei_templates)
        menubar.add_cascade(label="Settings", menu=settings)
        self.master.config(menu=menubar)

    # ------------------------------------------------------------------ #
    # Main layout: Notebook with one tab per pipeline stage
    # ------------------------------------------------------------------ #
    def create_main_widgets(self):
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_rowconfigure(1, weight=0)
        self.master.grid_columnconfigure(0, weight=1)

        self.notebook = ttk.Notebook(self.master)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        self.outputs = {}  # tab name -> Text widget (order must match tab order)
        self._build_scope_tab()
        self._build_subdomain_tab()
        self._build_livehost_tab()
        self._build_url_tab()
        self._build_port_tab()
        self._build_vuln_tab()
        self._build_dirbust_tab()
        self._build_reconplus_tab()
        self._build_webscan_tab()

        # Bottom control/status bar
        bottom = ttk.Frame(self.master, padding=(8, 4))
        bottom.grid(row=1, column=0, sticky="ew")
        bottom.columnconfigure(1, weight=1)

        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=160)
        self.progress.grid(row=0, column=0, padx=(0, 8))

        self.status_label = ttk.Label(bottom, text="Ready", anchor="w")
        self.status_label.grid(row=0, column=1, sticky="ew")

        self.stop_button = ttk.Button(bottom, text="Stop", command=self.stop_scan,
                                       state=tk.DISABLED)
        self.stop_button.grid(row=0, column=2, padx=4)
        ttk.Button(bottom, text="Save Active Tab",
                   command=self.save_active_output).grid(row=0, column=3, padx=4)
        ttk.Button(bottom, text="Clear Active Tab",
                   command=self.clear_active_output).grid(row=0, column=4, padx=4)

    def _make_output(self, parent):
        frame = ttk.Frame(parent)
        frame.grid(row=10, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
        parent.grid_rowconfigure(10, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        text = tk.Text(frame, wrap=tk.WORD, state="disabled",
                       font=("Courier New", 10), relief=tk.FLAT, bd=0)
        text.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(frame, command=text.yview)
        sb.grid(row=0, column=1, sticky="ns")
        text["yscrollcommand"] = sb.set
        text._gr_output = True   # marks the Save/Clear "active tab" target
        return text

    # --- Tab: Scope ------------------------------------------------------- #
    STAGE_TARGETS = ["1. Subdomains", "2. Live Hosts", "3. URLs",
                     "4. Ports", "5. Vulnerabilities", "6. Dir Busting"]

    def _build_scope_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Scope")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        top = ttk.Frame(tab)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(2, weight=1)
        btn = ttk.Button(top, text="Load scope file (.txt / .csv / .json)…",
                         command=self._scope_load_file)
        btn.grid(row=0, column=0, padx=(0, 8))
        self.run_buttons.append(btn)
        self.scope_enforce = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Enforce scope (block out-of-scope targets everywhere)",
                        variable=self.scope_enforce).grid(row=0, column=1, padx=4)
        self.scope_label = ttk.Label(top, text="No scope loaded.", anchor="e")
        self.scope_label.grid(row=0, column=2, sticky="e")

        ctl = ttk.Frame(tab)
        ctl.grid(row=1, column=0, sticky="ew", pady=(8, 2))
        ttk.Button(ctl, text="Check all in-scope",
                   command=lambda: self._scope_check_all(True)).pack(side="left")
        ttk.Button(ctl, text="Uncheck all",
                   command=lambda: self._scope_check_all(False)).pack(side="left", padx=4)
        ttk.Button(ctl, text="Invert", command=self._scope_invert).pack(side="left")
        ttk.Label(ctl, text="   Filter:").pack(side="left")
        self.scope_search = tk.StringVar()
        self.scope_search.trace_add("write", lambda *a: self._scope_populate())
        ttk.Entry(ctl, textvariable=self.scope_search, width=22).pack(side="left", padx=4)

        ttk.Label(tab, text="Tick the targets you want to test (out-of-scope rows are "
                            "locked). Click the ✓ column to toggle.", foreground="#888"
                  ).grid(row=2, column=0, sticky="w")

        wrap = ttk.Frame(tab)
        wrap.grid(row=3, column=0, sticky="nsew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        cols = ("sel", "scope", "host", "raw")
        self.scope_tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                       selectmode="none")
        for col, label, width, stretch in (("sel", "✓", 34, False),
                                           ("scope", "Scope", 70, False),
                                           ("host", "Host / target", 300, True),
                                           ("raw", "Raw identifier", 320, True)):
            self.scope_tree.heading(col, text=label)
            self.scope_tree.column(col, width=width, stretch=stretch,
                                   anchor="center" if col in ("sel", "scope") else "w")
        self.scope_tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(wrap, command=self.scope_tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.scope_tree["yscrollcommand"] = sb.set
        self.scope_tree.tag_configure("out", foreground="#c0392b")
        self.scope_tree.bind("<Button-1>", self._scope_click)

        send = ttk.Frame(tab)
        send.grid(row=4, column=0, sticky="ew", pady=(6, 2))
        ttk.Label(send, text="Send checked targets to:").pack(side="left")
        self.scope_dest = ttk.Combobox(send, state="readonly", width=20,
                                       values=self.STAGE_TARGETS)
        self.scope_dest.set(self.STAGE_TARGETS[1])
        self.scope_dest.pack(side="left", padx=4)
        ttk.Button(send, text="Send", command=self._scope_send).pack(side="left")
        self.scope_count = ttk.Label(send, text="")
        self.scope_count.pack(side="left", padx=8)

        log = ttk.Frame(tab)
        log.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        log.columnconfigure(0, weight=1)
        text = tk.Text(log, wrap=tk.WORD, state="disabled", height=4,
                       font=("Courier New", 10), relief=tk.FLAT, bd=0)
        text.grid(row=0, column=0, sticky="ew")
        text._gr_output = True
        self.outputs["scope"] = text   # keep aligned with tab order (first tab)

    def _scope_load_file(self):
        path = filedialog.askopenfilename(
            title="Load scope file",
            filetypes=[("Scope files", "*.txt *.csv *.json *.lst"),
                       ("All files", "*.*")])
        if not path:
            return
        try:
            entries = parse_scope_file(path)
        except Exception as e:
            messagebox.showerror("Scope", f"Could not parse {os.path.basename(path)}:\n{e}")
            return
        self.scope["entries"] = entries
        self.scope["file"] = path
        self.scope["in_pats"] = [scope_pattern(e["host"]) for e in entries
                                 if e["scope"] == "in"]
        self.scope["out_pats"] = [scope_pattern(e["host"]) for e in entries
                                  if e["scope"] == "out"]
        self._scope_checked = {}
        n_in = sum(1 for e in entries if e["scope"] == "in")
        self.scope_label.config(text=f"{os.path.basename(path)} — {len(entries)} targets, "
                                     f"{n_in} in-scope")
        self.append(self.outputs["scope"],
                    f"[+] Loaded {len(entries)} targets ({n_in} in-scope, "
                    f"{len(entries) - n_in} out) from {path}\n")
        self._scope_populate()
        self.update_status(f"Scope loaded: {n_in} in-scope targets")

    def _scope_populate(self):
        tree = self.scope_tree
        tree.delete(*tree.get_children())
        needle = self.scope_search.get().strip().lower()
        for i, e in enumerate(self.scope["entries"]):
            if needle and needle not in e["host"].lower() and needle not in e["raw"].lower():
                continue
            iid = f"e{i}"
            checked = self._scope_checked.get(iid, False)
            mark = "☑" if checked else ("☐" if e["scope"] == "in" else "🔒")
            tree.insert("", tk.END, iid=iid,
                        values=(mark, e["scope"], e["host"], e["raw"]),
                        tags=("out",) if e["scope"] == "out" else ())
        self._scope_update_count()

    def _scope_click(self, event):
        if self.scope_tree.identify("region", event.x, event.y) != "cell":
            return
        iid = self.scope_tree.identify_row(event.y)
        if not iid:
            return
        idx = int(iid[1:])
        if self.scope["entries"][idx]["scope"] != "in":
            return   # out-of-scope rows are locked
        self._scope_checked[iid] = not self._scope_checked.get(iid, False)
        self.scope_tree.set(iid, "sel", "☑" if self._scope_checked[iid] else "☐")
        self._scope_update_count()

    def _scope_check_all(self, value):
        for i, e in enumerate(self.scope["entries"]):
            if e["scope"] == "in":
                self._scope_checked[f"e{i}"] = value
        self._scope_populate()

    def _scope_invert(self):
        for i, e in enumerate(self.scope["entries"]):
            if e["scope"] == "in":
                iid = f"e{i}"
                self._scope_checked[iid] = not self._scope_checked.get(iid, False)
        self._scope_populate()

    def _scope_update_count(self):
        n = sum(1 for v in self._scope_checked.values() if v)
        self.scope_count.config(text=f"{n} checked")

    def scope_checked_hosts(self):
        return [self.scope["entries"][int(iid[1:])]["host"]
                for iid, on in self._scope_checked.items() if on]

    def _scope_send(self):
        hosts = self.scope_checked_hosts()
        if not hosts:
            messagebox.showinfo("Scope", "No targets checked.")
            return
        # strip wildcards for stages that want a concrete host/domain
        plain = [h[2:] if h.startswith("*.") else h for h in hosts]
        dest = self.scope_dest.get()
        widget_map = {
            "1. Subdomains": ("entry", "domain_entry"),
            "2. Live Hosts": ("text", "hosts_input"),
            "3. URLs": ("entry", "url_entry"),
            "4. Ports": ("entry", "port_entry"),
            "5. Vulnerabilities": ("text", "vuln_input"),
            "6. Dir Busting": ("text", "dirbust_input"),
        }
        kind, attr = widget_map[dest]
        widget = getattr(self, attr)
        if kind == "text":
            widget.delete("1.0", tk.END)
            widget.insert("1.0", "\n".join(plain))
            msg = f"{len(plain)} target(s)"
        else:
            widget.delete(0, tk.END)
            widget.insert(0, plain[0])
            msg = f"'{plain[0]}'" + (f" (+{len(plain) - 1} more ignored; "
                                     "this stage takes one)" if len(plain) > 1 else "")
        self.notebook.select(self.STAGE_TARGETS.index(dest) + 1)  # +1 past Scope tab
        self.update_status(f"Sent {msg} to {dest}")

    # Scope enforcement used by the active stages --------------------------- #
    def in_scope(self, host):
        """True if host is allowed: matches an in-scope pattern and no out pattern.
        With no in-scope patterns loaded, everything is allowed."""
        host = host.lower()
        if not self.scope["in_pats"]:
            return True
        if any(p.match(host) for p in self.scope["out_pats"]):
            return False
        return any(p.match(host) for p in self.scope["in_pats"])

    def scope_filter(self, hosts, widget):
        """Drop out-of-scope hosts when enforcement is on; log what was blocked."""
        if not (getattr(self, "scope_enforce", None) and self.scope_enforce.get()
                and self.scope["in_pats"]):
            return list(hosts)
        kept, blocked = [], []
        for h in hosts:
            bare = re.sub(r'^https?://', '', h, flags=re.I).split("/")[0].split(":")[0]
            (kept if self.in_scope(bare) else blocked).append(h)
        if blocked:
            self.append(widget, f"[scope] Blocked {len(blocked)} out-of-scope target(s): "
                                f"{', '.join(blocked[:8])}{' …' if len(blocked) > 8 else ''}\n")
        return kept

    # --- Tab: Subdomains -------------------------------------------------- #
    def _build_subdomain_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="1. Subdomains")

        ttk.Label(tab, text="Domain:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.domain_entry = ttk.Entry(tab, width=45)
        self.domain_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.domain_entry.bind("<Return>", lambda e: self.start_subdomain_recon())
        tab.columnconfigure(1, weight=1)

        btn = ttk.Button(tab, text="Enumerate (amass, subfinder, crt.sh, crt.name)",
                         command=self.start_subdomain_recon)
        btn.grid(row=0, column=2, padx=5, pady=5)
        self.run_buttons.append(btn)

        self.outputs["sub"] = self._make_output(tab)

    # --- Tab: Live Hosts -------------------------------------------------- #
    def _build_livehost_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="2. Live Hosts")

        ttk.Label(tab, text="Hosts (one per line, or use previous stage):"
                  ).grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=(5, 0))
        self.hosts_input = tk.Text(tab, height=5, wrap=tk.NONE, font=("Courier New", 10))
        self.hosts_input.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        tab.columnconfigure(0, weight=1)

        ttk.Button(tab, text="Load subdomains from stage 1",
                   command=lambda: self._load_into(self.hosts_input, "subdomains")
                   ).grid(row=2, column=0, sticky="w", padx=5)
        btn = ttk.Button(tab, text="Probe with httpx",
                         command=self.start_httpx)
        btn.grid(row=2, column=2, sticky="e", padx=5)
        self.run_buttons.append(btn)

        self.outputs["live"] = self._make_output(tab)

    # --- Tab: URLs -------------------------------------------------------- #
    def _build_url_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="3. URLs & Patterns")

        ttk.Label(tab, text="Domain/URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = ttk.Entry(tab, width=40)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.url_entry.bind("<Return>", lambda e: self.start_url_recon())
        tab.columnconfigure(1, weight=1)

        ttk.Label(tab, text="gf pattern:").grid(row=1, column=0, sticky="w", padx=5)
        self.gf_pattern = ttk.Combobox(
            tab, width=15, state="readonly",
            values=["xss", "ssrf", "lfi", "sqli", "redirect", "rce", "idor", "ssti"])
        self.gf_pattern.set("xss")
        self.gf_pattern.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        self.src_gau = tk.BooleanVar(value=True)
        self.src_wayback = tk.BooleanVar(value=True)
        self.src_katana = tk.BooleanVar(value=True)
        srcframe = ttk.Frame(tab)
        srcframe.grid(row=2, column=0, columnspan=2, sticky="w", padx=5)
        ttk.Checkbutton(srcframe, text="gau", variable=self.src_gau).pack(side="left")
        ttk.Checkbutton(srcframe, text="waybackurls", variable=self.src_wayback).pack(side="left")
        ttk.Checkbutton(srcframe, text="katana", variable=self.src_katana).pack(side="left")

        btn = ttk.Button(tab, text="Discover URLs + filter",
                         command=self.start_url_recon)
        btn.grid(row=0, column=2, padx=5, pady=5)
        self.run_buttons.append(btn)

        self.outputs["url"] = self._make_output(tab)

    # --- Tab: Ports ------------------------------------------------------- #
    def _build_port_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="4. Ports")

        ttk.Label(tab, text="Host/IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.port_entry = ttk.Entry(tab, width=40)
        self.port_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        tab.columnconfigure(1, weight=1)

        self.scanner_choice = tk.StringVar(value="naabu")
        ttk.Radiobutton(tab, text="naabu (fast)", variable=self.scanner_choice,
                        value="naabu").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Radiobutton(tab, text="nmap (-sV)", variable=self.scanner_choice,
                        value="nmap").grid(row=1, column=1, sticky="w", padx=5)

        btn = ttk.Button(tab, text="Scan ports", command=self.start_port_scan)
        btn.grid(row=0, column=2, padx=5, pady=5)
        self.run_buttons.append(btn)

        self.outputs["port"] = self._make_output(tab)

    # --- Tab: Vulnerabilities (nuclei) ----------------------------------- #
    def _build_vuln_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="5. Vulnerabilities")

        ttk.Label(tab, text="Targets (one per line, or use live hosts):"
                  ).grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=(5, 0))
        self.vuln_input = tk.Text(tab, height=5, wrap=tk.NONE, font=("Courier New", 10))
        self.vuln_input.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        tab.columnconfigure(0, weight=1)

        ttk.Button(tab, text="Load live hosts from stage 2",
                   command=lambda: self._load_into(self.vuln_input, "live_hosts")
                   ).grid(row=2, column=0, sticky="w", padx=5)

        ttk.Label(tab, text="Severity:").grid(row=2, column=1, sticky="e")
        self.severity = ttk.Combobox(
            tab, width=22, state="readonly",
            values=["", "low,medium,high,critical", "medium,high,critical",
                    "high,critical", "critical"])
        self.severity.set("medium,high,critical")
        self.severity.grid(row=2, column=2, sticky="w", padx=5)

        btn = ttk.Button(tab, text="Scan with nuclei", command=self.start_nuclei)
        btn.grid(row=3, column=2, sticky="e", padx=5, pady=5)
        self.run_buttons.append(btn)

        self.outputs["vuln"] = self._make_output(tab)

    # --- Tab: Directory busting (dirb + ffuf) ---------------------------- #
    def _build_dirbust_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="6. Dir Busting")
        tab.columnconfigure(0, weight=1)

        ttk.Label(tab, text="Target URLs (one per line, or use live hosts):"
                  ).grid(row=0, column=0, columnspan=4, sticky="w", padx=5, pady=(5, 0))
        self.dirbust_input = tk.Text(tab, height=3, wrap=tk.NONE, font=("Courier New", 10))
        self.dirbust_input.grid(row=1, column=0, columnspan=4, sticky="ew", padx=5, pady=5)

        row2 = ttk.Frame(tab)
        row2.grid(row=2, column=0, columnspan=4, sticky="ew", padx=5)
        ttk.Button(row2, text="Load live hosts from stage 2",
                   command=self._load_live_urls).pack(side="left")
        self.db_use_dirb = tk.BooleanVar(value=True)
        self.db_use_ffuf = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="dirb", variable=self.db_use_dirb).pack(side="left", padx=(16, 4))
        ttk.Checkbutton(row2, text="ffuf", variable=self.db_use_ffuf).pack(side="left", padx=4)
        btn = ttk.Button(row2, text="Bust directories", command=self.start_dirbust)
        btn.pack(side="right")
        self.run_buttons.append(btn)

        # Wordlists
        wl = ttk.LabelFrame(tab, text="Wordlists", padding=6)
        wl.grid(row=3, column=0, columnspan=4, sticky="ew", padx=5, pady=(6, 0))
        wl.columnconfigure(1, weight=1)
        self.dirb_wordlist = tk.StringVar(value=DIRB_WORDLIST)
        self.ffuf_wordlist = tk.StringVar(value=self.best_ffuf_wordlist() or "")
        for r, (label, var) in enumerate((("dirb:", self.dirb_wordlist),
                                          ("ffuf:", self.ffuf_wordlist))):
            ttk.Label(wl, text=label).grid(row=r, column=0, sticky="w")
            ttk.Entry(wl, textvariable=var).grid(row=r, column=1, sticky="ew", padx=4, pady=1)
            ttk.Button(wl, text="Browse…",
                       command=lambda v=var: self._browse_wordlist(v)
                       ).grid(row=r, column=2, pady=1)

        opts = ttk.Frame(tab)
        opts.grid(row=4, column=0, columnspan=4, sticky="ew", padx=5, pady=(6, 0))
        opts.columnconfigure(0, weight=1)
        opts.columnconfigure(1, weight=1)

        # ffuf filters: checkbox enables the flag, entry holds its value
        flt = ttk.LabelFrame(opts, text="ffuf filters", padding=6)
        flt.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.ffuf_filters = {}
        specs = [
            ("-ac", "Auto-calibrate (-ac)", None, True),
            ("-mc", "Match codes (-mc)", "200-299,301,302,307,401,403,405,500", True),
            ("-fc", "Filter codes (-fc)", "404", False),
            ("-fs", "Filter size (-fs)", "", False),
            ("-fw", "Filter words (-fw)", "", False),
            ("-fl", "Filter lines (-fl)", "", False),
            ("-fr", "Filter regex (-fr)", "", False),
        ]
        for i, (flag, label, default, on) in enumerate(specs):
            # -ac alone on the first row, then the value filters two per row
            r, c = (0, 0) if i == 0 else (1 + (i - 1) // 2, (i - 1) % 2)
            cell = ttk.Frame(flt)
            cell.grid(row=r, column=c, sticky="w", padx=(0, 10), pady=1)
            var = tk.BooleanVar(value=on)
            ttk.Checkbutton(cell, text=label, variable=var).pack(side="left")
            val = None
            if default is not None:
                val = tk.StringVar(value=default)
                ttk.Entry(cell, textvariable=val, width=14 if flag != "-mc" else 22
                          ).pack(side="left", padx=(4, 0))
            self.ffuf_filters[flag] = (var, val)

        # Throttle / evasion
        thr = ttk.LabelFrame(opts, text="Throttle", padding=6)
        thr.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        ttk.Label(thr, text="Preset:").grid(row=0, column=0, sticky="w")
        self.throttle_preset = ttk.Combobox(thr, state="readonly", width=20,
                                            values=list(THROTTLE_PRESETS) + ["Custom"])
        self.throttle_preset.grid(row=0, column=1, columnspan=3, sticky="w", padx=4, pady=1)
        self.throttle_preset.bind("<<ComboboxSelected>>", self._apply_throttle_preset)

        self.db_threads = tk.IntVar()
        self.db_rate = tk.IntVar()
        self.db_jitter = tk.BooleanVar()
        ttk.Label(thr, text="Threads:").grid(row=1, column=0, sticky="w")
        ttk.Spinbox(thr, from_=1, to=200, width=5, textvariable=self.db_threads,
                    command=self._throttle_custom).grid(row=1, column=1, sticky="w", padx=4, pady=1)
        ttk.Label(thr, text="Max req/s (0 = no limit):").grid(row=1, column=2, sticky="w")
        ttk.Spinbox(thr, from_=0, to=1000, width=5, textvariable=self.db_rate,
                    command=self._throttle_custom).grid(row=1, column=3, sticky="w", padx=4, pady=1)
        ttk.Checkbutton(thr, text="Random delay jitter (ffuf -p 0.1-1.0)",
                        variable=self.db_jitter, command=self._throttle_custom
                        ).grid(row=2, column=0, columnspan=4, sticky="w")
        self.db_browser_ua = tk.BooleanVar(value=True)
        ttk.Checkbutton(thr, text="Browser User-Agent (tool UAs are often WAF-blocked)",
                        variable=self.db_browser_ua).grid(row=3, column=0, columnspan=4, sticky="w")
        self.db_recursive = tk.BooleanVar(value=False)
        ttk.Checkbutton(thr, text="Recurse into found dirs (multiplies requests)",
                        variable=self.db_recursive).grid(row=4, column=0, columnspan=4, sticky="w")
        self.throttle_preset.set("Polite")
        self._apply_throttle_preset()

        # Results (merged dirb + ffuf) above the live log, resizable split
        paned = ttk.PanedWindow(tab, orient=tk.VERTICAL)
        paned.grid(row=10, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
        tab.grid_rowconfigure(10, weight=1)

        res = ttk.Frame(paned)
        res.columnconfigure(0, weight=1)
        res.rowconfigure(1, weight=1)
        self.dirbust_summary = ttk.Label(res, text="Combined results (dirb + ffuf) — "
                                                   "double-click a row to copy its URL")
        self.dirbust_summary.grid(row=0, column=0, columnspan=2, sticky="w")
        cols = ("url", "status", "size", "found_by")
        self.dirbust_tree = ttk.Treeview(res, columns=cols, show="headings", height=8)
        for col, label, width, stretch in (("url", "URL", 460, True),
                                           ("status", "Status", 70, False),
                                           ("size", "Size", 80, False),
                                           ("found_by", "Found by", 110, False)):
            self.dirbust_tree.heading(col, text=label,
                                      command=lambda c=col: self._sort_dirbust(c, False))
            self.dirbust_tree.column(col, width=width, stretch=stretch,
                                     anchor="w" if col == "url" else "center")
        self.dirbust_tree.grid(row=1, column=0, sticky="nsew")
        tsb = ttk.Scrollbar(res, command=self.dirbust_tree.yview)
        tsb.grid(row=1, column=1, sticky="ns")
        self.dirbust_tree["yscrollcommand"] = tsb.set
        self.dirbust_tree.bind("<Double-1>", self._copy_dirbust_url)
        paned.add(res, weight=1)

        # Live feed: every word tested, with its response code + size
        live = ttk.Frame(paned)
        live.rowconfigure(1, weight=1)
        live.columnconfigure(0, weight=1)
        self.live_status = ttk.Label(live, text="Live requests — idle")
        self.live_status.grid(row=0, column=0, columnspan=2, sticky="w")
        self.live_feed = tk.Text(live, wrap=tk.NONE, state="disabled", height=7,
                                 font=("Courier New", 10), relief=tk.FLAT, bd=0)
        self.live_feed.grid(row=1, column=0, sticky="nsew")
        fsb = ttk.Scrollbar(live, command=self.live_feed.yview)
        fsb.grid(row=1, column=1, sticky="ns")
        self.live_feed["yscrollcommand"] = fsb.set
        for tag, color in (("2xx", "#3fb950"), ("3xx", "#58a6ff"), ("4xx", "#8b949e"),
                           ("5xx", "#f85149"), ("err", "#d29922")):
            self.live_feed.tag_configure(tag, foreground=color)
        self.live_feed.tag_configure("hit", font=("Courier New", 10, "bold"))
        paned.add(live, weight=1)
        self._feed_q = queue.Queue()
        self._feed = {"tool": None}
        self.master.after(150, self._drain_feed)

        log = ttk.Frame(paned)
        log.rowconfigure(0, weight=1)
        log.columnconfigure(0, weight=1)
        text = tk.Text(log, wrap=tk.WORD, state="disabled", height=6,
                       font=("Courier New", 10), relief=tk.FLAT, bd=0)
        text.grid(row=0, column=0, sticky="nsew")
        lsb = ttk.Scrollbar(log, command=text.yview)
        lsb.grid(row=0, column=1, sticky="ns")
        text["yscrollcommand"] = lsb.set
        paned.add(log, weight=1)
        text._gr_output = True
        self.outputs["dir"] = text

    # Live feed plumbing: workers push into a queue, the Tk loop drains it in
    # batches (a fast scan can do hundreds of req/s -- one Tk call per line
    # would freeze the window).
    FEED_MAX_LINES = 500

    def _feed_begin(self, tool, target, total):
        self._feed = {"tool": tool, "target": target, "total": total, "tested": 0,
                      "hits": 0, "last": "", "t0": time.time(), "rate": 0.0,
                      "rt": time.time(), "rn": 0}

    def _feed_push(self, path, code, size, hit):
        f = self._feed
        f["tested"] += 1
        f["hits"] += hit
        f["last"] = f"{path} [{code}] {size}B"
        self._feed_q.put((path, code, size, hit))

    def _drain_feed(self):
        try:
            items = []
            while len(items) < 5000:
                items.append(self._feed_q.get_nowait())
        except queue.Empty:
            pass
        if items:
            fw = self.live_feed
            fw.config(state="normal")
            for path, code, size, hit in items[-self.FEED_MAX_LINES:]:
                c = str(code)
                tag = f"{c[0]}xx" if c[:1] in "2345" and c.isdigit() else "err"
                line = f"{path[:70]:<70} [{c:>3}] {str(size):>9} B"
                fw.insert(tk.END, line + ("   <-- HIT\n" if hit else "\n"),
                          (tag, "hit") if hit else (tag,))
            excess = int(fw.index("end-1c").split(".")[0]) - self.FEED_MAX_LINES
            if excess > 0:
                fw.delete("1.0", f"{excess + 1}.0")
            fw.see(tk.END)
            fw.config(state="disabled")
        f = self._feed
        if f.get("tool"):
            now = f.get("t_end") or time.time()
            if f.get("done") and not f.get("t_end"):
                f["t_end"] = now   # final figure = average over the whole run
                f["rate"] = f["tested"] / max(now - f["t0"], 0.001)
            if not f.get("done") and now - f["rt"] >= 1.0:   # req/s over the last ~second
                f["rate"] = (f["tested"] - f["rn"]) / (now - f["rt"])
                f["rt"], f["rn"] = now, f["tested"]
            total = f["total"]
            pct = f" ({100 * f['tested'] // total}%)" if total else ""
            el = int(now - f["t0"])
            self.live_status.config(text=(
                f"{'FINISHED  ' if f.get('done') else ''}{f['tool']} -> {f['target']}   tested {f['tested']}/{total or '?'}{pct}"
                f"   {f['rate']:.1f} req/s   hits {f['hits']}   {el // 60}:{el % 60:02d}"
                f"   last: {f['last']}"))
        self.master.after(150, self._drain_feed)

    @staticmethod
    def _count_words(path):
        try:
            with open(path, errors="replace") as fh:
                return sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
        except OSError:
            return 0

    def _load_live_urls(self):
        # Prefer httpx URLs (keep the real scheme); fall back to bare hosts.
        items = self.state.get("live_urls") or self.state.get("live_hosts")
        if not items:
            messagebox.showinfo("No data", "No live hosts available yet. Run stage 2 first.")
            return
        self.dirbust_input.delete("1.0", tk.END)
        self.dirbust_input.insert("1.0", "\n".join(items))

    def _browse_wordlist(self, var):
        start = os.path.dirname(var.get()) if var.get() else "/usr/share"
        path = filedialog.askopenfilename(initialdir=start, title="Choose wordlist",
                                          filetypes=[("Text files", "*.txt"), ("All files", "*")])
        if path:
            var.set(path)

    @staticmethod
    def best_ffuf_wordlist():
        return next((p for p in FFUF_WORDLISTS if os.path.isfile(p)), None)

    def _apply_throttle_preset(self, _event=None):
        preset = THROTTLE_PRESETS.get(self.throttle_preset.get())
        if preset:
            threads, rate, jitter = preset
            self.db_threads.set(threads)
            self.db_rate.set(rate)
            self.db_jitter.set(jitter)

    def _throttle_custom(self):
        self.throttle_preset.set("Custom")

    def _sort_dirbust(self, col, reverse):
        tree = self.dirbust_tree
        rows = [(tree.set(k, col), k) for k in tree.get_children("")]

        def key(item):
            v = item[0]
            return (0, int(v), "") if v.isdigit() else (1, 0, v.lower())
        rows.sort(key=key, reverse=reverse)
        for i, (_, k) in enumerate(rows):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: self._sort_dirbust(col, not reverse))

    def _copy_dirbust_url(self, _event):
        sel = self.dirbust_tree.selection()
        if sel:
            url = self.dirbust_tree.set(sel[0], "url")
            self.master.clipboard_clear()
            self.master.clipboard_append(url)
            self.update_status(f"Copied {url}")

    def _load_into(self, widget, state_key):
        items = self.state.get(state_key, [])
        if not items:
            messagebox.showinfo("No data", f"No {state_key} available yet. Run the earlier stage first.")
            return
        widget.delete("1.0", tk.END)
        widget.insert("1.0", "\n".join(items))

    # ------------------------------------------------------------------ #
    # Theming
    # ------------------------------------------------------------------ #
    def toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.apply_theme()

    def apply_theme(self):
        t = THEMES[self.theme_name]
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.master.configure(bg=t["bg"])
        self.style.configure(".", background=t["bg"], foreground=t["fg"])
        self.style.configure("TFrame", background=t["bg"])
        self.style.configure("TLabel", background=t["bg"], foreground=t["fg"])
        self.style.configure("TLabelframe", background=t["bg"], foreground=t["fg"])
        self.style.configure("TLabelframe.Label", background=t["bg"], foreground=t["fg"])
        self.style.configure("TButton", background=t["accent"], foreground="#ffffff")
        self.style.map("TButton", background=[("active", t["accent"]), ("disabled", t["tab_bg"])])

        # Entry / Combobox: make field + typed text readable in both themes
        self.style.configure("TEntry", fieldbackground=t["text_bg"],
                             foreground=t["entry_fg"], insertcolor=t["entry_fg"])
        self.style.map("TEntry", fieldbackground=[("readonly", t["text_bg"])],
                       foreground=[("readonly", t["entry_fg"])])
        self.style.configure("TCombobox", fieldbackground=t["text_bg"],
                             background=t["text_bg"], foreground=t["entry_fg"],
                             arrowcolor=t["fg"])
        self.style.map("TCombobox",
                       fieldbackground=[("readonly", t["text_bg"])],
                       foreground=[("readonly", t["entry_fg"])],
                       selectbackground=[("readonly", t["text_bg"])],
                       selectforeground=[("readonly", t["entry_fg"])])
        self.master.option_add("*TCombobox*Listbox.background", t["text_bg"])
        self.master.option_add("*TCombobox*Listbox.foreground", t["entry_fg"])
        self.master.option_add("*TCombobox*Listbox.selectBackground", t["accent"])

        # Notebook tabs: clear selected vs unselected contrast
        self.style.configure("TNotebook", background=t["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", background=t["tab_bg"],
                             foreground=t["tab_fg"], padding=[14, 7], borderwidth=1)
        self.style.map("TNotebook.Tab",
                       background=[("selected", t["accent"]), ("active", t["bg"])],
                       foreground=[("selected", "#ffffff"), ("active", t["fg"])])
        self.style.configure("TCheckbutton", background=t["bg"], foreground=t["fg"])
        self.style.map("TCheckbutton", background=[("active", t["bg"])])
        self.style.configure("TRadiobutton", background=t["bg"], foreground=t["fg"])
        self.style.map("TRadiobutton", background=[("active", t["bg"])])
        self.style.configure("TSpinbox", fieldbackground=t["text_bg"],
                             foreground=t["entry_fg"], arrowcolor=t["fg"])
        self.style.configure("Treeview", background=t["text_bg"], foreground=t["text_fg"],
                             fieldbackground=t["text_bg"], rowheight=20)
        self.style.map("Treeview", background=[("selected", t["accent"])],
                       foreground=[("selected", "#ffffff")])
        self.style.configure("Treeview.Heading", background=t["tab_bg"], foreground=t["tab_fg"])
        self.style.map("Treeview.Heading", background=[("active", t["bg"])])
        extra_inputs = [getattr(self, a, None) for a in (
            "hosts_input", "vuln_input", "dirbust_input", "live_feed",
            "js_input", "takeover_input", "params_input", "bypass_input",
            "nikto_input", "api_input")]
        for widget in list(getattr(self, "outputs", {}).values()) + extra_inputs:
            if widget is not None:
                widget.configure(bg=t["text_bg"], fg=t["text_fg"],
                                 insertbackground=t["text_fg"])

    # ------------------------------------------------------------------ #
    # Thread-safe UI updates
    # ------------------------------------------------------------------ #
    def update_status(self, message):
        self.master.after(0, lambda: self.status_label.config(text=message))

    def append(self, widget, text):
        def _do():
            widget.config(state="normal")
            widget.insert(tk.END, text)
            widget.see(tk.END)
            widget.config(state="disabled")
        self.master.after(0, _do)

    def clear_active_output(self):
        w = self._active_widget()
        if w:
            w.config(state="normal")
            w.delete("1.0", tk.END)
            w.config(state="disabled")

    def _active_widget(self):
        """The output Text of the currently visible tab, descending through any
        nested notebook to its selected sub-tab. Robust to tab add/reorder."""
        try:
            frame = self.master.nametowidget(self.notebook.select())
        except (KeyError, tk.TclError):
            return next(iter(self.outputs.values()), None)
        return self._find_output(frame) or next(iter(self.outputs.values()), None)

    def _find_output(self, widget):
        # Prefer a nested notebook's currently-selected sub-tab.
        for child in widget.winfo_children():
            if isinstance(child, ttk.Notebook):
                try:
                    sub = self.master.nametowidget(child.select())
                except (KeyError, tk.TclError):
                    continue
                found = self._find_output(sub)
                if found:
                    return found
        for child in widget.winfo_children():
            if isinstance(child, tk.Text) and getattr(child, "_gr_output", False):
                return child
            found = self._find_output(child)
            if found:
                return found
        return None

    def save_active_output(self):
        w = self._active_widget()
        content = w.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Save", "No output to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, "w") as f:
                f.write(content)
            self.update_status(f"Saved to {path}")

    # ------------------------------------------------------------------ #
    # Run lifecycle
    # ------------------------------------------------------------------ #
    def _begin_run(self, output_widget):
        self.running = True
        self.stop_requested = False
        self.active_output = output_widget
        for b in self.run_buttons:
            b.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start(12)

    def _end_run(self):
        def _do():
            self.running = False
            self.current_proc = None
            for b in self.run_buttons:
                b.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress.stop()
        self.master.after(0, _do)

    def stop_scan(self):
        self.stop_requested = True
        if self.current_proc and self.current_proc.poll() is None:
            try:
                self.current_proc.terminate()
                self.update_status("Scan stopped by user.")
            except Exception:
                pass

    def _launch(self, target_fn, output_widget, args=()):
        if self.running:
            messagebox.showinfo("Busy", "A scan is already running. Stop it first.")
            return
        self._begin_run(output_widget)
        t = threading.Thread(target=self._wrap, args=(target_fn, args), daemon=True)
        t.start()

    def _wrap(self, fn, args):
        try:
            fn(*args)
        except Exception as e:
            self.append(self.active_output, f"\n[!] Error: {e}\n")
            self.update_status(f"Error: {e}")
        finally:
            self._end_run()

    # ------------------------------------------------------------------ #
    # Output directory + streaming command runner
    # ------------------------------------------------------------------ #
    def _new_outdir(self, target):
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = os.path.join(base, sanitize_for_path(target), stamp)
        os.makedirs(outdir, exist_ok=True)
        self.state["target"] = target
        self.state["outdir"] = outdir
        return outdir

    def run_stream(self, command, widget, shell=False, outfile=None, merge_stderr=True,
                   skip_blank=False, on_line=None, echo=True):
        """Run a command, stream output live into `widget`, return list of stdout lines.

        merge_stderr=False routes stderr to /dev/null so a tool's progress bars or
        logs (amass writes these to stderr) don't pollute the captured names.
        """
        shown = command if isinstance(command, str) else " ".join(command)
        if echo:
            self.append(widget, f"$ {shown}\n")
        lines = []
        try:
            self.current_proc = subprocess.Popen(
                command, shell=shell, stdout=subprocess.PIPE,
                stderr=(subprocess.STDOUT if merge_stderr else subprocess.DEVNULL),
                text=True, bufsize=1)
        except FileNotFoundError:
            self.append(widget, f"[!] Command not found: {shown}\n")
            return lines
        for line in self.current_proc.stdout:
            line = strip_ansi(line)
            if skip_blank and not line.strip():
                continue   # e.g. ffuf's leading \r becomes an empty line
            if on_line:    # caller handles display itself (live feed)
                on_line(line.rstrip("\n"))
                continue
            lines.append(line.rstrip("\n"))
            self.append(widget, line)
        self.current_proc.wait()
        if outfile and lines:
            try:
                with open(outfile, "w") as f:
                    f.write("\n".join(lines) + "\n")
            except Exception as e:
                self.append(widget, f"[!] Could not write {outfile}: {e}\n")
        return lines

    # ------------------------------------------------------------------ #
    # Dependencies
    # ------------------------------------------------------------------ #
    TOOLS = {
        "amass": "https://github.com/owasp-amass/amass",
        "subfinder": "https://github.com/projectdiscovery/subfinder",
        "subfaster": "https://github.com/melvinsh/subfaster",
        "curl": "https://curl.se",
        "httpx": "https://github.com/projectdiscovery/httpx",
        "gau": "https://github.com/lc/gau",
        "waybackurls": "https://github.com/tomnomnom/waybackurls",
        "katana": "https://github.com/projectdiscovery/katana",
        "gf": "https://github.com/tomnomnom/gf",
        "uro": "https://github.com/s0md3v/uro",
        "naabu": "https://github.com/projectdiscovery/naabu",
        "nmap": "https://nmap.org",
        "nuclei": "https://github.com/projectdiscovery/nuclei",
        "dirb": "https://dirb.sourceforge.net",
        "ffuf": "https://github.com/ffuf/ffuf",
        "dnsx": "https://github.com/projectdiscovery/dnsx",
        "subzy": "https://github.com/PentestPad/subzy",
        "arjun": "https://github.com/s0md3v/Arjun",
        "jsluice": "https://github.com/BishopFox/jsluice",
        "wpscan": "https://github.com/wpscanteam/wpscan",
        "nikto": "https://github.com/sullo/nikto",
        "js-beautify": "https://github.com/beautifier/js-beautify",
        "kr": "https://github.com/assetnote/kiterunner",
    }

    # How to install each tool. "go"/"pip" entries run without sudo; "apt" needs sudo.
    INSTALL = {
        "subfinder": ("go", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        "subfaster": ("go", "go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest"),
        "httpx":     ("go", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        "gau":       ("go", "go install github.com/lc/gau/v2/cmd/gau@latest"),
        "waybackurls": ("go", "go install github.com/tomnomnom/waybackurls@latest"),
        "katana":    ("go", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
        "gf":        ("go", "go install github.com/tomnomnom/gf@latest"),
        "naabu":     ("go", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        "nuclei":    ("go", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        "uro":       ("pip", "pipx install uro 2>/dev/null || pip3 install --user uro"),
        "amass":     ("apt", "sudo apt-get install -y amass"),
        "nmap":      ("apt", "sudo apt-get install -y nmap"),
        "curl":      ("apt", "sudo apt-get install -y curl"),
        "ffuf":      ("go", "go install github.com/ffuf/ffuf/v2@latest"),
        "dirb":      ("apt", "sudo apt-get install -y dirb"),
        "dnsx":      ("go", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        "subzy":     ("go", "go install -v github.com/PentestPad/subzy@latest"),
        "jsluice":   ("go", "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"),
        "arjun":     ("pip", "pipx install arjun 2>/dev/null || pip3 install --user arjun"),
        "wpscan":    ("apt", "sudo apt-get install -y wpscan"),
        "nikto":     ("apt", "sudo apt-get install -y nikto"),
        "js-beautify": ("pip", "pip3 install --user jsbeautifier"),
        "kr":        ("go", "go install github.com/assetnote/kiterunner/cmd/kr@latest"),
    }
    # Tools that are optional enhancers: never block a stage, just improve it.
    OPTIONAL_TOOLS = {"jsluice", "subzy", "x8", "js-beautify", "kr"}

    def has_tool(self, name):
        # httpx is special: the name collides with the Python httpx HTTP client.
        # Only count ProjectDiscovery's httpx (the recon tool) as present.
        if name == "httpx":
            return self.pd_httpx_path() is not None
        return shutil.which(name) is not None

    _pd_httpx_cache = None  # None = unchecked, False = none found, str = path

    def pd_httpx_path(self):
        """Resolve ProjectDiscovery's httpx, skipping the Python httpx CLI shadow."""
        if self._pd_httpx_cache is not None:
            return self._pd_httpx_cache or None
        candidates = [
            os.path.expanduser("~/go/bin/httpx"),
            os.path.expanduser("~/.local/bin/httpx"),
            "/usr/local/bin/httpx",
            shutil.which("httpx"),
        ]
        for path in candidates:
            if not path or not os.path.exists(path):
                continue
            try:
                r = subprocess.run([path, "-version"], capture_output=True,
                                   text=True, timeout=5)
                blob = (r.stdout + r.stderr).lower()
            except Exception:
                continue
            # Python httpx rejects -version ("no such option"); PD httpx prints a version.
            if "no such option" not in blob and "usage: httpx [options]" not in blob:
                self._pd_httpx_cache = path
                return path
        self._pd_httpx_cache = False
        return None

    GF_PATTERNS_REPO = "https://github.com/1ndianl33t/Gf-Patterns.git"

    def gf_pattern_dir(self):
        # Mirrors gf's own lookup (main.go: getPatternDir) so we check the
        # exact directory it will read from, not just "~/.gf".
        cfg = os.path.expanduser("~/.config/gf")
        return cfg if os.path.isdir(cfg) else os.path.expanduser("~/.gf")

    def ensure_gf_patterns(self, widget):
        """gf installs with no patterns at all -- xss.json etc. must be fetched
        separately, or every `gf <pattern>` call matches nothing and the
        pipeline writes an empty (but valid) output file. Fetch them once."""
        patdir = self.gf_pattern_dir()
        if glob.glob(os.path.join(patdir, "*.json")):
            return True
        self.append(widget, f"[*] No gf patterns in {patdir} -- fetching a pattern set ...\n")
        os.makedirs(patdir, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix="gf-patterns-")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", self.GF_PATTERNS_REPO, tmp],
                check=True, capture_output=True, text=True, timeout=60)
            for f in glob.glob(os.path.join(tmp, "*.json")):
                shutil.copy(f, patdir)
        except Exception as e:
            self.append(widget,
                f"[!] Could not fetch gf patterns automatically ({e}).\n"
                f"    Install manually: git clone {self.GF_PATTERNS_REPO} {patdir}\n")
            return False
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if glob.glob(os.path.join(patdir, "*.json")):
            self.append(widget, f"[+] gf patterns installed to {patdir}\n")
            return True
        self.append(widget, f"[!] Pattern fetch ran but {patdir} is still empty.\n")
        return False

    def require(self, widget, *tools):
        missing = [t for t in tools if not self.has_tool(t)]
        if missing:
            self.append(widget, f"[!] Missing tools: {', '.join(missing)} — skipping.\n")
            self.update_status(f"Missing: {', '.join(missing)}")
        return not missing

    def check_dependencies(self, initial=False):
        missing = {t: u for t, u in self.TOOLS.items() if not self.has_tool(t)}
        if not missing:
            if not initial:
                messagebox.showinfo("Dependencies", "All tools found in PATH.")
            self.update_status("All dependencies present.")
            return
        msg = "Tools not found in PATH (modules needing them will be skipped):\n\n" + \
            "\n".join(f"• {t}  ({u})" for t, u in missing.items())
        messagebox.showwarning("Missing Dependencies", msg)
        self.update_status(f"{len(missing)} tool(s) missing.")

    # ------------------------------------------------------------------ #
    # Settings: auto-install missing tools
    # ------------------------------------------------------------------ #
    def open_install_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Install Missing Tools")
        win.geometry("720x560")
        t = THEMES[self.theme_name]
        win.configure(bg=t["bg"])

        ttk.Label(win, text="Select tools to install",
                  font=("Helvetica", 14, "bold")).pack(anchor="w", padx=12, pady=(12, 2))

        have_go = self.has_tool("go")
        note = "Go toolchain detected." if have_go else \
            "⚠ 'go' not found — Go-based tools can't be installed until you install Go."
        ttk.Label(win, text=note).pack(anchor="w", padx=12, pady=(0, 8))

        list_frame = ttk.Frame(win)
        list_frame.pack(fill="x", padx=12)

        self._install_vars = {}
        missing = [name for name in self.TOOLS if not self.has_tool(name)]
        if not missing:
            ttk.Label(list_frame, text="✅ All tools are already installed.").pack(anchor="w")
        for name in missing:
            method, cmd = self.INSTALL.get(name, (None, None))
            row = ttk.Frame(list_frame)
            row.pack(fill="x", pady=1)
            installable = method in ("go", "pip") and (have_go or method == "pip")
            var = tk.BooleanVar(value=installable)
            self._install_vars[name] = (var, method, cmd)
            cb = ttk.Checkbutton(row, variable=var, text=f"{name}")
            cb.pack(side="left")
            if method == "apt":
                hint = "needs sudo — run in a terminal"
            elif method == "go" and not have_go:
                hint = "needs Go"
            elif cmd is None:
                hint = "no known installer"
            else:
                hint = cmd
            if not installable:
                cb.state(["disabled"])
            ttk.Label(row, text=f"   {hint}", foreground=t["tab_fg"]).pack(side="left")

        out = tk.Text(win, height=14, wrap=tk.WORD, state="disabled",
                      font=("Courier New", 9), bg=t["text_bg"], fg=t["text_fg"],
                      insertbackground=t["text_fg"], relief=tk.FLAT)
        out.pack(fill="both", expand=True, padx=12, pady=10)

        btnrow = ttk.Frame(win)
        btnrow.pack(fill="x", padx=12, pady=(0, 12))
        install_btn = ttk.Button(btnrow, text="Install Selected")
        install_btn.pack(side="right")
        ttk.Button(btnrow, text="Close", command=win.destroy).pack(side="right", padx=6)

        def append(text):
            win.after(0, lambda: (out.config(state="normal"), out.insert(tk.END, text),
                                  out.see(tk.END), out.config(state="disabled")))

        def do_install():
            chosen = [(n, c) for n, (v, m, c) in self._install_vars.items()
                      if v.get() and c]
            if not chosen:
                append("Nothing selected.\n")
                return
            install_btn.config(state=tk.DISABLED)

            def worker():
                for name, cmd in chosen:
                    append(f"\n=== Installing {name} ===\n$ {cmd}\n")
                    try:
                        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT, text=True, bufsize=1)
                        for line in proc.stdout:
                            append(line)
                        proc.wait()
                        ok = self.has_tool(name)
                        append(f"[{'OK' if ok else 'FAILED'}] {name} "
                               f"{'installed' if ok else 'not found after install'}\n")
                    except Exception as e:
                        append(f"[ERROR] {name}: {e}\n")
                append("\nDone. Re-open this dialog to refresh the list.\n")
                win.after(0, lambda: install_btn.config(state=tk.NORMAL))
                self.update_status("Tool installation finished.")

            threading.Thread(target=worker, daemon=True).start()

        install_btn.config(command=do_install)

    # ------------------------------------------------------------------ #
    # Settings: nuclei engine / template updates
    # ------------------------------------------------------------------ #
    NUCLEI_GO_PKG = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    def _nuclei_install_source(self, path):
        """How this nuclei binary was installed -> how it must be updated.
        Distro builds (Kali's apt package) strip nuclei's self-updater (-up),
        and overwriting an apt-owned binary would fight the package manager."""
        real = os.path.realpath(path)
        if real.startswith(os.path.expanduser("~/go/bin")):
            return "go"
        try:
            if subprocess.run(["dpkg", "-S", real], capture_output=True,
                              timeout=10).returncode == 0:
                return "apt"
        except (OSError, subprocess.TimeoutExpired):
            pass
        return "self"   # official release binary: has -up

    def update_nuclei_engine(self):
        path = shutil.which("nuclei")
        if not path:
            messagebox.showwarning("nuclei", "nuclei is not installed. Use Settings → "
                                             "Install missing tools first.")
            return
        source = self._nuclei_install_source(path)
        steps = [("Current version", [path, "-version"])]
        if source == "apt":
            if not (shutil.which("pkexec") and os.environ.get("DISPLAY")):
                messagebox.showinfo(
                    "nuclei (apt package)",
                    f"{path} is managed by apt, which needs root. Run in a terminal:\n\n"
                    "sudo apt update && sudo apt install --only-upgrade nuclei")
                return
            # pkexec pops the desktop's graphical password prompt
            steps.append(("Upgrading apt package (you'll be asked for your password)",
                          ["pkexec", "sh", "-c",
                           "apt-get update && apt-get install -y --only-upgrade nuclei"]))
        elif source == "go":
            if not self.has_tool("go"):
                messagebox.showwarning("nuclei", "nuclei was installed with Go, but 'go' "
                                                 "is not on PATH.")
                return
            steps.append(("Rebuilding with go install", ["go", "install", "-v",
                                                         self.NUCLEI_GO_PKG]))
        else:
            steps.append(("Self-updating", [path, "-up"]))
        steps.append(("New version", [path, "-version"]))
        self._run_steps_dialog(f"Update nuclei engine ({source} install)", steps)

    def update_nuclei_templates(self):
        path = shutil.which("nuclei")
        if not path:
            messagebox.showwarning("nuclei", "nuclei is not installed. Use Settings → "
                                             "Install missing tools first.")
            return
        # Templates live in the user's home -- no root needed, any install type.
        self._run_steps_dialog("Update nuclei templates", [
            ("Installed templates", [path, "-tv"]),
            ("Downloading latest templates", [path, "-ut"]),
            ("Templates now", [path, "-tv"]),
        ])

    def _run_steps_dialog(self, title, steps):
        """Run commands one after another in a log window, streaming output."""
        win = tk.Toplevel(self.master)
        win.title(title)
        win.geometry("760x420")
        t = THEMES[self.theme_name]
        win.configure(bg=t["bg"])
        ttk.Label(win, text=title, font=("Helvetica", 13, "bold")
                  ).pack(anchor="w", padx=12, pady=(12, 4))
        out = tk.Text(win, wrap=tk.WORD, state="disabled", font=("Courier New", 9),
                      bg=t["text_bg"], fg=t["text_fg"], relief=tk.FLAT)
        out.pack(fill="both", expand=True, padx=12, pady=6)
        close = ttk.Button(win, text="Close", command=win.destroy, state=tk.DISABLED)
        close.pack(anchor="e", padx=12, pady=(0, 12))

        def append(text):
            def _do():
                if out.winfo_exists():
                    out.config(state="normal")
                    out.insert(tk.END, text)
                    out.see(tk.END)
                    out.config(state="disabled")
            win.after(0, _do)

        def worker():
            ok = True
            for label, cmd in steps:
                append(f"\n=== {label} ===\n$ {' '.join(cmd)}\n")
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True, bufsize=1)
                    for line in proc.stdout:
                        append(strip_ansi(line))
                    proc.wait()
                except OSError as e:
                    append(f"[!] {e}\n")
                    ok = False
                    break
                if proc.returncode != 0:
                    # pkexec: 126 = password dialog dismissed, 127 = not authorized
                    hint = " (authentication cancelled or denied)" \
                        if cmd[0] == "pkexec" and proc.returncode in (126, 127) else ""
                    append(f"[!] Exited with code {proc.returncode}{hint}\n")
                    if label not in ("Current version", "Installed templates"):
                        ok = False
                        break
            append(f"\n{'[+] Done.' if ok else '[!] Update did not complete.'}\n")
            self.update_status(f"{title}: {'done' if ok else 'failed'}")
            win.after(0, lambda: close.config(state=tk.NORMAL) if close.winfo_exists() else None)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ #
    # Stage 1: Subdomains
    # ------------------------------------------------------------------ #
    def start_subdomain_recon(self):
        domain = self.domain_entry.get().strip().lower()
        if not is_domain(domain):
            messagebox.showwarning("Input", "Enter a valid domain, e.g. example.com")
            return
        if not self.scope_filter([domain], self.outputs["sub"]):
            messagebox.showwarning("Scope", f"{domain} is out of scope.")
            return
        self._launch(self.run_subdomains, self.outputs["sub"], (domain,))

    def run_subdomains(self, domain):
        w = self.outputs["sub"]
        outdir = self._new_outdir(domain)
        self.update_status(f"Enumerating subdomains for {domain} ...")
        self.append(w, f"--- Subdomain enumeration: {domain} ---\n")
        found = set()

        if self.has_tool("amass"):
            self.update_status("Running amass (passive) ...")
            out = os.path.join(outdir, "amass.txt")
            # amass v4+/v5: no -o flag. Names print to stdout; progress goes to
            # stderr (dropped via merge_stderr=False); -dir holds its DB.
            lines = self.run_stream(
                ["amass", "enum", "-passive", "-d", domain,
                 "-dir", outdir, "-timeout", "10"], w, merge_stderr=False)
            names = {ln.strip().lower() for ln in lines
                     if ln.strip() and ln.strip().endswith(domain)}
            with open(out, "w") as f:
                f.write("\n".join(sorted(names)) + ("\n" if names else ""))
            self.append(w, f"[+] amass: {len(names)} names -> {out}\n")
            found |= names
        else:
            self.append(w, "[!] amass missing — skipping.\n")

        if self.has_tool("subfinder"):
            self.update_status("Running subfinder ...")
            out = os.path.join(outdir, "subfinder.txt")
            self.run_stream(["subfinder", "-d", domain, "-o", out, "-silent"], w)
            found |= self._read_lines(out)
        else:
            self.append(w, "[!] subfinder missing — skipping.\n")

        # subfaster: fast passive aggregator (8 keyless sources incl. crt.name's 'crt')
        if self.has_tool("subfaster"):
            self.update_status("Running subfaster (fast passive sources incl. crt.name) ...")
            out = os.path.join(outdir, "subfaster.txt")
            self.run_stream(["subfaster", "-d", domain, "-silent", "-o", out], w)
            found |= self._read_lines(out)
        else:
            self.append(w, "[!] subfaster missing — using crt.name fallback instead.\n")

        # crt.sh via JSON API (robust, no HTML scraping)
        if self.has_tool("curl"):
            self.update_status("Querying crt.sh ...")
            raw = os.path.join(outdir, "crtsh.json")
            self.run_stream(
                ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json", "-o", raw], w)
            found |= self._parse_crtsh(raw, domain)

            # crt.name passive CT index — fallback for when subfaster isn't installed
            # (free endpoint: one subdomain per line, 100 req/IP/day, no token)
            if not self.has_tool("subfaster"):
                self.update_status("Querying crt.name ...")
                out = os.path.join(outdir, "crtname.txt")
                self.run_stream(
                    ["curl", "-s", "--max-time", "30",
                     f"https://crt.name/v1/search?apex={domain}", "-o", out], w)
                found |= {s for s in self._read_lines(out) if "." in s and " " not in s}

        subs = sorted(s for s in found if s.endswith(domain))
        combined = os.path.join(outdir, "subdomains.txt")
        with open(combined, "w") as f:
            f.write("\n".join(subs) + ("\n" if subs else ""))
        self.state["subdomains"] = subs

        self.append(w, f"\n--- {len(subs)} unique subdomains ---\n")
        self.append(w, "\n".join(subs) + "\n")
        self.append(w, f"\n[+] Saved to {combined}\n")
        self.update_status(f"Done. {len(subs)} subdomains. Saved in {outdir}")

    def _parse_crtsh(self, json_path, domain):
        import json
        results = set()
        if not os.path.exists(json_path):
            return results
        try:
            with open(json_path) as f:
                data = json.load(f)
            for entry in data:
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        results.add(name)
        except Exception:
            pass
        return results

    @staticmethod
    def _read_lines(path):
        if not os.path.exists(path):
            return set()
        with open(path) as f:
            return {ln.strip().lower() for ln in f if ln.strip()}

    # ------------------------------------------------------------------ #
    # Stage 2: Live hosts (httpx)
    # ------------------------------------------------------------------ #
    def start_httpx(self):
        hosts = [h.strip() for h in self.hosts_input.get("1.0", tk.END).splitlines() if h.strip()]
        hosts = [h for h in hosts if is_host(h)]
        hosts = self.scope_filter(hosts, self.outputs["live"])
        if not hosts:
            messagebox.showwarning("Input", "No valid in-scope hosts to probe.")
            return
        self._launch(self.run_httpx, self.outputs["live"], (hosts,))

    def run_httpx(self, hosts):
        w = self.outputs["live"]
        httpx_bin = self.pd_httpx_path()
        if not httpx_bin:
            if shutil.which("httpx"):
                self.append(w, "[!] The 'httpx' on PATH is the Python HTTP client, "
                               "not ProjectDiscovery's recon tool.\n"
                               "    Install the real one (goes to ~/go/bin, which "
                               "GhostRecon checks first):\n"
                               "    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                               "    or use Settings → Install missing tools.\n")
            else:
                self.append(w, "[!] httpx not found. Install it via Settings → "
                               "Install missing tools.\n")
            self.update_status("ProjectDiscovery httpx not found.")
            return
        outdir = self.state["outdir"] or self._new_outdir(hosts[0])
        infile = os.path.join(outdir, "httpx_input.txt")
        with open(infile, "w") as f:
            f.write("\n".join(hosts) + "\n")
        out = os.path.join(outdir, "live_hosts.txt")
        self.update_status(f"Probing {len(hosts)} hosts with httpx ...")
        self.run_stream(self.augment([httpx_bin, "-l", infile, "-silent", "-status-code",
                         "-title", "-tech-detect", "-o", out], "httpx"), w)
        live = sorted(self._read_lines(out))
        # store bare hosts (strip http scheme + metadata) for downstream stages
        bare = sorted({re.sub(r'^https?://', '', ln.split(" ")[0]).split("/")[0]
                       for ln in live})
        self.state["live_hosts"] = bare
        self.state["live_urls"] = sorted({ln.split(" ")[0] for ln in live
                                          if ln.startswith("http")})
        self.append(w, f"\n[+] {len(bare)} live hosts saved to {out}\n")
        self.update_status(f"httpx done. {len(bare)} live hosts.")

    # ------------------------------------------------------------------ #
    # Stage 3: URLs (gau / waybackurls / katana) -> gf pattern -> uro
    # ------------------------------------------------------------------ #
    def start_url_recon(self):
        target = self.url_entry.get().strip().lower()
        bare = re.sub(r'^https?://', '', target).split("/")[0]
        if not (is_url(target) and is_host(bare)):
            messagebox.showwarning("Input", "Enter a valid domain or URL.")
            return
        if not self.scope_filter([bare], self.outputs["url"]):
            messagebox.showwarning("Scope", f"{bare} is out of scope.")
            return
        self._launch(self.run_url_recon, self.outputs["url"], (target, bare))

    def run_url_recon(self, target, bare):
        w = self.outputs["url"]
        outdir = self.state["outdir"] or self._new_outdir(bare)
        all_urls = set()

        if self.src_gau.get() and self.require(w, "gau"):
            self.update_status("Running gau ...")
            out = os.path.join(outdir, "gau.txt")
            self.run_stream(f"echo {bare} | gau", w, shell=True, outfile=out)
            all_urls |= self._read_lines(out)

        if self.src_wayback.get() and self.require(w, "waybackurls"):
            self.update_status("Running waybackurls ...")
            out = os.path.join(outdir, "waybackurls.txt")
            self.run_stream(f"echo {bare} | waybackurls", w, shell=True, outfile=out)
            all_urls |= self._read_lines(out)

        if self.src_katana.get() and self.require(w, "katana"):
            self.update_status("Running katana ...")
            out = os.path.join(outdir, "katana.txt")
            url = target if target.startswith("http") else f"https://{bare}"
            self.run_stream(self.augment(["katana", "-u", url, "-silent", "-jc"],
                                         "katana"), w, outfile=out)
            all_urls |= self._read_lines(out)

        combined = os.path.join(outdir, "all_urls.txt")
        with open(combined, "w") as f:
            f.write("\n".join(sorted(all_urls)) + ("\n" if all_urls else ""))
        self.state["urls"] = sorted(all_urls)
        self.append(w, f"\n[+] {len(all_urls)} unique URLs -> {combined}\n")

        pattern = self.gf_pattern.get()
        if self.require(w, "gf", "uro") and self.ensure_gf_patterns(w):
            patfile = os.path.join(self.gf_pattern_dir(), f"{pattern}.json")
            if not os.path.isfile(patfile):
                self.append(w, f"[!] gf pattern '{pattern}' not found at {patfile} -- skipping.\n")
            else:
                self.update_status(f"Filtering for {pattern} ...")
                out = os.path.join(outdir, f"{pattern}.txt")
                cmd = f"cat {combined} | gf {pattern} | uro | tee {out}"
                self.append(w, f"\n--- gf {pattern} results ---\n")
                self.run_stream(cmd, w, shell=True)
                if os.path.getsize(out) == 0:
                    self.append(w, f"\n[*] 0 matches for '{pattern}' in this URL set (file saved, but empty).\n")
                else:
                    self.append(w, f"\n[+] Saved to {out}\n")
        self.update_status(f"URL recon done. Results in {outdir}")

    # ------------------------------------------------------------------ #
    # Stage 4: Ports (naabu / nmap)
    # ------------------------------------------------------------------ #
    def start_port_scan(self):
        host = self.port_entry.get().strip().lower()
        host = re.sub(r'^https?://', '', host).split("/")[0]
        if not is_host(host):
            messagebox.showwarning("Input", "Enter a valid host or IP.")
            return
        if not self.scope_filter([host], self.outputs["port"]):
            messagebox.showwarning("Scope", f"{host} is out of scope.")
            return
        self._launch(self.run_port_scan, self.outputs["port"], (host,))

    def run_port_scan(self, host):
        w = self.outputs["port"]
        scanner = self.scanner_choice.get()
        if not self.require(w, scanner):
            return
        outdir = self.state["outdir"] or self._new_outdir(host)
        out = os.path.join(outdir, f"ports_{scanner}_{sanitize_for_path(host)}.txt")
        self.update_status(f"Port scanning {host} with {scanner} ...")
        if scanner == "naabu":
            self.run_stream(self.augment(["naabu", "-host", host, "-silent", "-o", out],
                                         "naabu"), w)
        else:
            self.run_stream(["nmap", "-sV", "-T4", "-oN", out, host], w)
        self.append(w, f"\n[+] Saved to {out}\n")
        self.update_status(f"Port scan done -> {out}")

    # ------------------------------------------------------------------ #
    # Stage 5: Vulnerabilities (nuclei)
    # ------------------------------------------------------------------ #
    def start_nuclei(self):
        targets = [t.strip() for t in self.vuln_input.get("1.0", tk.END).splitlines() if t.strip()]
        targets = [t for t in targets if is_host(re.sub(r'^https?://', '', t).split("/")[0])]
        targets = self.scope_filter(targets, self.outputs["vuln"])
        if not targets:
            messagebox.showwarning("Input", "No valid in-scope targets.")
            return
        self._launch(self.run_nuclei, self.outputs["vuln"], (targets,))

    def run_nuclei(self, targets):
        w = self.outputs["vuln"]
        if not self.require(w, "nuclei"):
            return
        outdir = self.state["outdir"] or self._new_outdir(targets[0])
        infile = os.path.join(outdir, "nuclei_targets.txt")
        with open(infile, "w") as f:
            f.write("\n".join(targets) + "\n")
        out = os.path.join(outdir, "nuclei.txt")
        cmd = ["nuclei", "-l", infile, "-o", out]
        sev = self.severity.get().strip()
        if sev:
            cmd += ["-severity", sev]
        oob = self.nuclei_oob_args()
        if oob:
            cmd += oob
            self.append(w, f"[*] OAST: {' '.join(oob)}\n")
        self.update_status(f"Running nuclei on {len(targets)} targets ...")
        self.run_stream(self.augment(cmd, "nuclei"), w)
        self.append(w, f"\n[+] Saved to {out}\n")
        self.update_status(f"nuclei done -> {out}")


    # ------------------------------------------------------------------ #
    # Stage 6: Directory busting (dirb + ffuf, merged results)
    # ------------------------------------------------------------------ #
    def start_dirbust(self):
        lines = [ln.strip() for ln in self.dirbust_input.get("1.0", tk.END).splitlines()
                 if ln.strip()]
        targets = []
        for ln in lines:
            url = ln if re.match(r'^https?://', ln, re.I) else f"https://{ln}"
            host = re.sub(r'^https?://', '', url, flags=re.I).split("/")[0].split(":")[0]
            if is_url(url) and is_host(host):
                targets.append(url.rstrip("/"))
        targets = self.scope_filter(targets, self.outputs["dir"])
        if not targets:
            messagebox.showwarning("Input", "No valid in-scope URL/host to bust.")
            return
        use_dirb, use_ffuf = self.db_use_dirb.get(), self.db_use_ffuf.get()
        if not (use_dirb or use_ffuf):
            messagebox.showwarning("Input", "Select dirb, ffuf, or both.")
            return

        cfg = {"dirb": use_dirb, "ffuf": use_ffuf,
               "dirb_wl": self.dirb_wordlist.get().strip(),
               "ffuf_wl": self.ffuf_wordlist.get().strip()}
        for tool in ("dirb", "ffuf"):
            if cfg[tool] and not os.path.isfile(cfg[f"{tool}_wl"]):
                messagebox.showwarning("Wordlist", f"{tool} wordlist not found:\n{cfg[f'{tool}_wl']}")
                return
        try:
            cfg["threads"] = max(1, int(self.db_threads.get()))
            cfg["rate"] = max(0, int(self.db_rate.get()))
        except (tk.TclError, ValueError):
            messagebox.showwarning("Throttle", "Threads and req/s must be whole numbers.")
            return
        cfg["jitter"] = self.db_jitter.get()
        cfg["ua"] = BROWSER_UA if self.db_browser_ua.get() else None
        cfg["recursive"] = self.db_recursive.get()

        # ffuf runs with -mc all so every response reaches the live feed;
        # GhostRecon applies these matchers/filters itself to decide hits.
        fspec = {"mc": parse_ranges(FFUF_DEFAULT_MC), "fc": [], "fs": [], "fw": [],
                 "fl": [], "fr": None, "ac": False}
        for flag, (on, val) in self.ffuf_filters.items():
            if not on.get():
                continue
            key = flag.lstrip("-")
            if val is None:
                fspec[key] = True
                continue
            v = val.get().strip()
            if not v:
                messagebox.showwarning("ffuf filters", f"{flag} is checked but has no value.")
                return
            if flag == "-fr":
                try:
                    re.compile(v)
                except re.error as e:
                    messagebox.showwarning("ffuf filters", f"Invalid regex for -fr: {e}")
                    return
                fspec["fr"] = v
            elif flag == "-mc" and v.lower() == "all":
                fspec["mc"] = "all"
            elif FFUF_NUM_RE.match(v):
                try:
                    fspec[key] = parse_ranges(v)
                except ValueError:
                    messagebox.showwarning("ffuf filters", f"Bad value for {flag}: {v}")
                    return
            else:
                messagebox.showwarning("ffuf filters",
                                       f"{flag} expects numbers/ranges like 404 or 100-200,4242.")
                return
        cfg["fspec"] = fspec

        self.dirbust_tree.delete(*self.dirbust_tree.get_children())
        self._launch(self.run_dirbust, self.outputs["dir"], (targets, cfg))

    def run_dirbust(self, targets, cfg):
        w = self.outputs["dir"]
        tools = [t for t in ("dirb", "ffuf") if cfg[t] and self.require(w, t)]
        if not tools:
            return
        first_host = re.sub(r'^https?://', '', targets[0], flags=re.I).split("/")[0]
        outdir = self.state["outdir"] or self._new_outdir(first_host)
        rate, threads = cfg["rate"], cfg["threads"]
        self.append(w, f"[*] Throttle: {threads} thread(s), "
                       f"{'unlimited' if not rate else f'max {rate} req/s'}"
                       f"{', jitter on' if cfg['jitter'] else ''}\n")

        fspec = cfg["fspec"]
        merged = {}   # normalized url -> {url, status, size, sources}

        def add(url, status, size, source):
            key = url.rstrip("/").lower()
            entry = merged.setdefault(key, {"url": url.rstrip("/") or url, "status": "",
                                            "size": "", "sources": set()})
            entry["sources"].add(source)
            # Prefer a real status/size over dirb's bare "DIR" marker.
            if status and (not entry["status"] or entry["status"] == "DIR"):
                entry["status"] = str(status)
            if size != "" and entry["size"] == "":
                entry["size"] = str(size)

        for i, base in enumerate(targets, 1):
            if self.stop_requested:
                self.append(w, "\n[!] Stopped — skipping remaining targets.\n")
                break
            tag = sanitize_for_path(re.sub(r'^https?://', '', base, flags=re.I))
            self.append(w, f"\n=== [{i}/{len(targets)}] {base} ===\n")

            if "dirb" in tools and not self.stop_requested:
                self.update_status(f"dirb -> {base} ({i}/{len(targets)})")
                out = os.path.join(outdir, f"dirb_{tag}.txt")
                # -v prints every word (404s too) so the live feed sees each test
                cmd = ["dirb", base + "/", cfg["dirb_wl"], "-S", "-v", "-o", out]
                if not cfg["recursive"]:
                    cmd.append("-r")
                if rate:   # dirb is single-threaded, so a fixed delay == a rate cap
                    cmd += ["-z", str(max(1, 1000 // rate))]
                if cfg["ua"]:
                    cmd += ["-a", cfg["ua"]]
                self._feed_begin("dirb", base, self._count_words(cfg["dirb_wl"]))
                # dirb block-buffers stdout into a pipe; force line buffering
                if shutil.which("stdbuf"):
                    cmd = ["stdbuf", "-oL"] + cmd
                self.run_stream(cmd, w, on_line=lambda ln, b=base: self._dirb_line(ln, b, w, add))
                self._feed["done"] = True

            if "ffuf" in tools and not self.stop_requested:
                self.update_status(f"ffuf -> {base} ({i}/{len(targets)})")
                common = ["-noninteractive", "-json", "-mc", "all", "-t", str(threads)]
                if rate:
                    common += ["-rate", str(rate)]
                if cfg["jitter"]:
                    common += ["-p", "0.1-1.0"]
                if cfg["ua"]:
                    common += ["-H", f"User-Agent: {cfg['ua']}"]
                if fspec["fr"]:   # needs the body, so ffuf applies it natively
                    common += ["-fr", fspec["fr"]]
                # Global Burp proxy + custom headers (the tab owns rate + UA).
                if self._proxy_url():
                    common += ["-x", self._proxy_url()]
                for h in self._all_headers():
                    if not (cfg["ua"] and h.lower().startswith("user-agent:")):
                        common += ["-H", h]
                calib = self._ffuf_calibrate(base, common, w) if fspec["ac"] else {}
                if self.stop_requested:
                    continue
                cmd = ["ffuf", "-u", base + "/FUZZ", "-w", cfg["ffuf_wl"], "-ic"] + common
                if cfg["recursive"]:
                    cmd += ["-recursion", "-recursion-depth", "2"]
                hits = []
                self._feed_begin("ffuf", base, self._count_words(cfg["ffuf_wl"]))
                # stderr = banner + progress bar; stdout = one JSON line per response
                self.run_stream(cmd, w, merge_stderr=False, on_line=lambda ln, b=base:
                                self._ffuf_line(ln, b, w, add, fspec, calib, hits))
                self._feed["done"] = True
                if hits:
                    with open(os.path.join(outdir, f"ffuf_{tag}.txt"), "w") as fh:
                        fh.write("\n".join(hits) + "\n")

        rows = sorted(merged.values(), key=lambda e: e["url"].lower())
        combined = os.path.join(outdir, "dirbust_combined.txt")
        with open(combined, "w") as f:
            f.write("url\tstatus\tsize\tfound_by\n")
            for e in rows:
                f.write(f"{e['url']}\t{e['status']}\t{e['size']}\t"
                        f"{','.join(sorted(e['sources']))}\n")
        self.state["dirs"] = [e["url"] for e in rows]
        both = sum(1 for e in rows if len(e["sources"]) > 1)

        def fill():
            for e in rows:
                src = sorted(e["sources"])
                self.dirbust_tree.insert("", tk.END, values=(
                    e["url"], e["status"], e["size"],
                    "both" if len(src) > 1 else src[0]))
            self.dirbust_summary.config(
                text=f"Combined results: {len(rows)} unique paths "
                     f"({both} found by both) — double-click a row to copy its URL")
        self.master.after(0, fill)
        self.append(w, f"\n[+] {len(rows)} unique paths ({both} found by both) -> {combined}\n")
        self.update_status(f"Dir busting done. {len(rows)} paths -> {combined}")

    DIRB_HIT_RE = re.compile(r'^\+ (\S+) \(CODE:(\d+)\|SIZE:(\d+)\)')
    DIRB_DIR_RE = re.compile(r'^==> DIRECTORY: (\S+)')

    @staticmethod
    def _rel(url, base):
        return (url[len(base):] or "/") if url.startswith(base) else url

    def _dirb_line(self, line, base, w, add):
        ln = line.strip()
        m = self.DIRB_HIT_RE.match(ln)
        if m:   # with -v dirb reports every word; 404 = not found
            url, code, size = m.groups()
            hit = code != "404"
            self._feed_push(self._rel(url, base), code, size, hit)
            if hit:
                add(url, code, size, "dirb")
                self.append(w, f"[dirb] {url}  [{code}]  {size} B\n")
            return
        m = self.DIRB_DIR_RE.match(ln)
        if m:
            add(m.group(1), "DIR", "", "dirb")
            self.append(w, f"[dirb] {m.group(1)}  [DIRECTORY]\n")
        elif ln.startswith("(!)"):   # dirb warnings/errors
            self.append(w, f"[dirb] {ln}\n")

    def _ffuf_line(self, line, base, w, add, fspec, calib, hits):
        try:
            r = json.loads(line)
        except ValueError:
            if line.strip():
                self.append(w, f"[ffuf] {line.strip()}\n")
            return
        url, code, size = r.get("url", ""), r.get("status", 0), r.get("length", 0)
        hit = self._ffuf_is_hit(r, fspec, calib)
        self._feed_push(self._rel(url, base), code, size, hit)
        if hit:
            add(url, code, size, "ffuf")
            hits.append(f"{url}\t{code}\t{size}")
            self.append(w, f"[ffuf] {url}  [{code}]  {size} B  "
                           f"(words {r.get('words')}, lines {r.get('lines')})\n")

    @staticmethod
    def _ffuf_is_hit(r, fspec, calib):
        code, size = r.get("status", 0), r.get("length", 0)
        words, lines = r.get("words", 0), r.get("lines", 0)
        if fspec["mc"] != "all" and not in_ranges(code, fspec["mc"]):
            return False
        if (in_ranges(code, fspec["fc"]) or in_ranges(size, fspec["fs"])
                or in_ranges(words, fspec["fw"]) or in_ranges(lines, fspec["fl"])):
            return False
        rule = calib.get(code)   # auto-calibration: (field, value) per status
        if rule and r.get(rule[0]) == rule[1]:
            return False
        return True

    def _ffuf_calibrate(self, base, common, w):
        """Our own -ac: request a few paths that can't exist and learn what the
        server's "not found" looks like per status code (size, else words,
        else lines). ffuf's built-in -ac can't be used because it would also
        hide those responses from the live feed."""
        rnd = lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
        probes = [rnd(8), rnd(16), rnd(32), "admin" + rnd(8), ".htaccess" + rnd(8), rnd(10) + "/"]
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tmp.write("\n".join(probes) + "\n")
        tmp.close()
        self.append(w, f"[*] Auto-calibrating against {base} ({len(probes)} probe requests) ...\n")
        recs = []

        def grab(ln):
            try:
                recs.append(json.loads(ln))
            except ValueError:
                pass
        try:
            self.run_stream(["ffuf", "-u", base + "/FUZZ", "-w", tmp.name] + common,
                            w, on_line=grab, echo=False, merge_stderr=False)
        finally:
            os.unlink(tmp.name)
        by_code = {}
        for r in recs:
            by_code.setdefault(r.get("status"), []).append(r)
        calib = {}
        for code, rs in by_code.items():
            for field in ("length", "words", "lines"):
                vals = {r.get(field) for r in rs}
                if len(vals) == 1:
                    calib[code] = (field, vals.pop())
                    break
        if calib:
            desc = ", ".join(f"{c} with {f}={v}" for c, (f, v) in sorted(calib.items()))
            self.append(w, f"[*] Calibration: treating {desc} as not-found\n")
        else:
            self.append(w, "[!] Calibration found no stable not-found signature.\n")
        return calib

    # ================================================================== #
    # Recon+ tab (JS & Secrets · Takeover · Params · Vhosts)
    # ================================================================== #
    def _mini_targets(self, parent, label, load_buttons):
        """A small multiline target box + a row of 'load from stage' buttons.
        load_buttons: list of (text, callable). Returns the Text widget."""
        ttk.Label(parent, text=label).grid(row=0, column=0, columnspan=4,
                                           sticky="w", padx=4, pady=(4, 0))
        box = tk.Text(parent, height=4, wrap=tk.NONE, font=("Courier New", 10))
        box.grid(row=1, column=0, columnspan=4, sticky="ew", padx=4, pady=4)
        parent.columnconfigure(0, weight=1)
        bar = ttk.Frame(parent)
        bar.grid(row=2, column=0, columnspan=4, sticky="w", padx=4)
        for text, cmd in load_buttons:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=(0, 4))
        return box

    def _fill(self, widget, items, kind="text"):
        if not items:
            messagebox.showinfo("No data", "Nothing available from that stage yet.")
            return
        if kind == "text":
            widget.delete("1.0", tk.END)
            widget.insert("1.0", "\n".join(items))
        else:
            widget.delete(0, tk.END)
            widget.insert(0, items[0])

    def _build_reconplus_tab(self):
        outer = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(outer, text="7. Recon+")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        inner = ttk.Notebook(outer)
        inner.grid(row=0, column=0, sticky="nsew")
        self._build_js_subtab(inner)
        self._build_takeover_subtab(inner)
        self._build_params_subtab(inner)
        self._build_vhost_subtab(inner)
        self._build_api_subtab(inner)

    # --- JS & Secrets ----------------------------------------------------- #
    def _build_js_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="JS & Secrets")
        self.js_input = self._mini_targets(
            tab, "JavaScript URLs, or page URLs/hosts to crawl for .js:",
            [("Load URLs (stage 3)", lambda: self._fill(self.js_input, self.state["urls"])),
             ("Load live hosts", lambda: self._fill(self.js_input, self.state["live_hosts"]))])
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        self.js_crawl = tk.BooleanVar(value=True)
        self.js_endpoints = tk.BooleanVar(value=True)
        self.js_secrets = tk.BooleanVar(value=True)
        self.js_beautify = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Crawl hosts with katana to find .js (if inputs aren't .js)",
                        variable=self.js_crawl).pack(side="left")
        ttk.Checkbutton(opt, text="Endpoints", variable=self.js_endpoints).pack(side="left", padx=6)
        ttk.Checkbutton(opt, text="Secrets", variable=self.js_secrets).pack(side="left")
        ttk.Checkbutton(opt, text="Beautify (unminify)",
                        variable=self.js_beautify).pack(side="left", padx=6)
        btn = ttk.Button(tab, text="Analyze JavaScript", command=self.start_js)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["js"] = self._make_output(tab)

    # --- Subdomain takeover ----------------------------------------------- #
    def _build_takeover_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Takeover")
        self.takeover_input = self._mini_targets(
            tab, "Subdomains / hosts to check for dangling CNAME takeover:",
            [("Load subdomains (stage 1)",
              lambda: self._fill(self.takeover_input, self.state["subdomains"])),
             ("Load live hosts",
              lambda: self._fill(self.takeover_input, self.state["live_hosts"])),
             ("Load checked scope",
              lambda: self._fill(self.takeover_input,
                                 [h[2:] if h.startswith("*.") else h
                                  for h in self.scope_checked_hosts()]))])
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        self.tko_dnsx = tk.BooleanVar(value=True)
        self.tko_nuclei = tk.BooleanVar(value=True)
        self.tko_subzy = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="dnsx CNAME map", variable=self.tko_dnsx).pack(side="left")
        ttk.Checkbutton(opt, text="nuclei takeover templates",
                        variable=self.tko_nuclei).pack(side="left", padx=6)
        ttk.Checkbutton(opt, text="subzy (if installed)",
                        variable=self.tko_subzy).pack(side="left")
        btn = ttk.Button(tab, text="Check takeovers", command=self.start_takeover)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["takeover"] = self._make_output(tab)

    # --- Parameter discovery (arjun) -------------------------------------- #
    def _build_params_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Params")
        self.params_input = self._mini_targets(
            tab, "URLs/endpoints to probe for hidden parameters (arjun):",
            [("Load URLs (stage 3)",
              lambda: self._fill(self.params_input, self.state["urls"])),
             ("Load live URLs",
              lambda: self._fill(self.params_input, self.state.get("live_urls", [])))])
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Method:").pack(side="left")
        self.params_method = ttk.Combobox(opt, state="readonly", width=6,
                                          values=["GET", "POST", "JSON", "XML"])
        self.params_method.set("GET")
        self.params_method.pack(side="left", padx=4)
        ttk.Label(opt, text="Threads:").pack(side="left")
        self.params_threads = tk.IntVar(value=5)
        ttk.Spinbox(opt, from_=1, to=50, width=5,
                    textvariable=self.params_threads).pack(side="left", padx=4)
        btn = ttk.Button(tab, text="Find parameters", command=self.start_params)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["params"] = self._make_output(tab)

    # --- Virtual-host fuzzing --------------------------------------------- #
    def _build_vhost_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Vhosts")
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="Target (host or IP to send requests to):"
                  ).grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.vhost_target = ttk.Entry(tab)
        self.vhost_target.grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(tab, text="Base domain (FUZZ.<base> in Host header):"
                  ).grid(row=1, column=0, sticky="w", padx=4, pady=3)
        self.vhost_domain = ttk.Entry(tab)
        self.vhost_domain.grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Label(tab, text="Wordlist:").grid(row=2, column=0, sticky="w", padx=4, pady=3)
        wlf = ttk.Frame(tab)
        wlf.grid(row=2, column=1, sticky="ew", padx=4)
        wlf.columnconfigure(0, weight=1)
        self.vhost_wordlist = tk.StringVar(value=self.best_vhost_wordlist() or "")
        ttk.Entry(wlf, textvariable=self.vhost_wordlist).grid(row=0, column=0, sticky="ew")
        ttk.Button(wlf, text="Browse…",
                   command=lambda: self._browse_wordlist(self.vhost_wordlist)
                   ).grid(row=0, column=1, padx=4)
        self.vhost_https = tk.BooleanVar(value=False)
        ttk.Checkbutton(tab, text="Use HTTPS", variable=self.vhost_https
                        ).grid(row=3, column=1, sticky="w", padx=4)
        btn = ttk.Button(tab, text="Fuzz virtual hosts", command=self.start_vhost)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["vhost"] = self._make_output(tab)

    @staticmethod
    def best_vhost_wordlist():
        for p in ("/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                  "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
                  "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
                  "/usr/share/seclists/Discovery/DNS/namelist.txt"):
            if os.path.isfile(p):
                return p
        return None

    # --- API route discovery (kiterunner) --------------------------------- #
    def _build_api_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="API Routes")
        self.api_input = self._mini_targets(
            tab, "API hosts / base URLs to scan for routes (kiterunner):",
            [("Load live hosts",
              lambda: self._fill(self.api_input, self.state.get("live_urls")
                                 or self.state["live_hosts"])),
             ("Load checked scope",
              lambda: self._fill(self.api_input,
                                 [h[2:] if h.startswith("*.") else h
                                  for h in self.scope_checked_hosts()]))])
        wl = ttk.LabelFrame(tab, text="Wordlist", padding=6)
        wl.grid(row=3, column=0, columnspan=4, sticky="ew", padx=4, pady=(4, 2))
        wl.columnconfigure(1, weight=1)
        ttk.Label(wl, text="File (.kite or .txt):").grid(row=0, column=0, sticky="w")
        self.api_wordlist = tk.StringVar(value=self.best_api_wordlist() or "")
        ttk.Entry(wl, textvariable=self.api_wordlist).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(wl, text="Browse…",
                   command=lambda: self._browse_wordlist(self.api_wordlist)
                   ).grid(row=0, column=2)
        ttk.Label(wl, text="Assetnote list (-A):").grid(row=1, column=0, sticky="w")
        self.api_assetnote = ttk.Entry(wl)
        self.api_assetnote.grid(row=1, column=1, sticky="w", padx=4)
        ttk.Label(wl, text="e.g. apiroutes-210328 (auto-downloads; overrides file if set)",
                  foreground="#888").grid(row=1, column=2, sticky="w")

        opt = ttk.Frame(tab)
        opt.grid(row=4, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Preflight depth:").pack(side="left")
        self.api_depth = tk.IntVar(value=1)
        ttk.Spinbox(opt, from_=1, to=5, width=4, textvariable=self.api_depth
                    ).pack(side="left", padx=4)
        ttk.Label(opt, text="Conns/host:").pack(side="left")
        self.api_conns = tk.IntVar(value=3)
        ttk.Spinbox(opt, from_=1, to=20, width=4, textvariable=self.api_conns
                    ).pack(side="left", padx=4)
        btn = ttk.Button(tab, text="Scan API routes", command=self.start_kiterunner)
        btn.grid(row=5, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["api"] = self._make_output(tab)

    @staticmethod
    def best_api_wordlist():
        import glob as _glob
        kites = _glob.glob(os.path.expanduser("~/.cache/kiterunner/*.kite")) \
            + _glob.glob(os.path.expanduser("~/*.kite")) \
            + _glob.glob("/usr/share/wordlists/**/*.kite", recursive=True)
        if kites:
            return kites[0]
        for p in ("/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
                  "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt"):
            if os.path.isfile(p):
                return p
        return None

    # ================================================================== #
    # Web Scan tab (403 Bypass · WPScan · Nikto)
    # ================================================================== #
    def _build_webscan_tab(self):
        outer = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(outer, text="8. Web Scan")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        inner = ttk.Notebook(outer)
        inner.grid(row=0, column=0, sticky="nsew")
        self._build_bypass_subtab(inner)
        self._build_wpscan_subtab(inner)
        self._build_nikto_subtab(inner)

    # --- 403 bypass ------------------------------------------------------- #
    def _build_bypass_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="403 Bypass")
        self.bypass_input = self._mini_targets(
            tab, "Forbidden/▲401 URLs to try to bypass (one per line):",
            [("Load 403/401 from Dir Busting", self._load_forbidden_dirs)])
        btn = ttk.Button(tab, text="Try bypass techniques", command=self.start_bypass)
        btn.grid(row=3, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["bypass"] = self._make_output(tab)

    def _load_forbidden_dirs(self):
        urls = []
        for iid in getattr(self, "dirbust_tree", None).get_children() \
                if getattr(self, "dirbust_tree", None) else []:
            vals = self.dirbust_tree.item(iid)["values"]
            if len(vals) >= 2 and str(vals[1]) in ("401", "403"):
                urls.append(str(vals[0]))
        self._fill(self.bypass_input, urls)

    # --- WPScan ----------------------------------------------------------- #
    def _build_wpscan_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="WPScan")
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="WordPress URL:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.wpscan_url = ttk.Entry(tab)
        self.wpscan_url.grid(row=0, column=1, sticky="ew", padx=4)
        opt = ttk.Frame(tab)
        opt.grid(row=1, column=0, columnspan=2, sticky="w", padx=4, pady=2)
        self.wp_enum = {}
        for code, label in (("vp", "vuln plugins"), ("vt", "vuln themes"),
                            ("u", "users"), ("cb", "config backups")):
            var = tk.BooleanVar(value=code in ("vp", "u"))
            self.wp_enum[code] = var
            ttk.Checkbutton(opt, text=label, variable=var).pack(side="left", padx=3)
        self.wp_stealth = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="stealthy", variable=self.wp_stealth).pack(side="left", padx=6)
        tok = ttk.Frame(tab)
        tok.grid(row=2, column=0, columnspan=2, sticky="ew", padx=4, pady=2)
        ttk.Label(tok, text="API token (optional, for CVE data):").pack(side="left")
        self.wp_token = ttk.Entry(tok, show="*")
        self.wp_token.pack(side="left", fill="x", expand=True, padx=4)
        btn = ttk.Button(tab, text="Scan WordPress", command=self.start_wpscan)
        btn.grid(row=3, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["wpscan"] = self._make_output(tab)

    # --- Nikto ------------------------------------------------------------ #
    def _build_nikto_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Nikto")
        self.nikto_input = self._mini_targets(
            tab, "URLs / hosts for a Nikto web-server scan:",
            [("Load live hosts",
              lambda: self._fill(self.nikto_input, self.state.get("live_urls")
                                 or self.state["live_hosts"]))])
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Tuning:").pack(side="left")
        self.nikto_tuning = ttk.Entry(opt, width=12)
        self.nikto_tuning.pack(side="left", padx=4)
        ttk.Label(opt, text="(e.g. 1234b; blank = default)").pack(side="left")
        self.nikto_ssl = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Force SSL", variable=self.nikto_ssl).pack(side="left", padx=6)
        btn = ttk.Button(tab, text="Run Nikto", command=self.start_nikto)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["nikto"] = self._make_output(tab)

    # ------------------------------------------------------------------ #
    # Recon+/Web Scan runners
    # ------------------------------------------------------------------ #
    def _lines_from(self, widget):
        return [ln.strip() for ln in widget.get("1.0", tk.END).splitlines() if ln.strip()]

    def _curl_probe(self, url, extra_headers=None, method="GET", resolve=None):
        """curl returning (status, size) for url, honouring global proxy/headers.
        Returns (None, None) on error."""
        cmd = ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
               "--max-time", "12", "-X", method]
        if self._proxy_url():
            cmd += ["-x", self._proxy_url()]
        for h in self._all_headers():
            cmd += ["-H", h]
        for h in (extra_headers or []):
            cmd += ["-H", h]
        if resolve:
            cmd += ["--resolve", resolve]
        cmd.append(url)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            code, _, size = r.stdout.strip().partition(" ")
            return code or None, size or "0"
        except (subprocess.SubprocessError, OSError):
            return None, None

    # ---- JS analysis ---- #
    def start_js(self):
        items = self._lines_from(self.js_input)
        if not items:
            messagebox.showwarning("Input", "Enter JS URLs or hosts.")
            return
        self._launch(self.run_js, self.outputs["js"], (items,))

    def run_js(self, items):
        w = self.outputs["js"]
        if not self.require(w, "curl"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', items[0]).split("/")[0])
        js_urls = [u for u in items if re.search(r'\.js(\?|$)', u, re.I)]
        hosts = [u for u in items if u not in js_urls]
        if hosts and self.js_crawl.get() and self.has_tool("katana"):
            self.append(w, f"[*] Crawling {len(hosts)} host(s) with katana for .js URLs ...\n")
            for h in hosts:
                if self.stop_requested:
                    break
                url = h if h.startswith("http") else f"https://{h}"
                lines = self.run_stream(self.augment(
                    ["katana", "-u", url, "-silent", "-jc", "-d", "2"], "katana"), w)
                js_urls += [ln.strip() for ln in lines if re.search(r'\.js(\?|$)', ln, re.I)]
        elif hosts and not self.has_tool("katana"):
            self.append(w, "[!] katana not installed; treating all inputs as JS URLs.\n")
            js_urls = items
        js_urls = sorted(set(js_urls))
        if not js_urls:
            self.append(w, "[!] No .js URLs found to analyze.\n")
            return
        self.append(w, f"[*] Analyzing {len(js_urls)} JS file(s) ...\n")
        has_jsluice = self.has_tool("jsluice")
        all_ep, all_sec = set(), []
        beautify_on = self.js_beautify.get()
        bdir = os.path.join(outdir, "js_beautified")
        warned_no_beautify = [False]
        for i, ju in enumerate(js_urls, 1):
            if self.stop_requested:
                self.append(w, "\n[!] Stopped.\n")
                break
            self.update_status(f"JS {i}/{len(js_urls)}: {ju[:60]}")
            tmp = tempfile.NamedTemporaryFile("w+", suffix=".js", delete=False)
            tmp.close()
            cmd = ["curl", "-s", "-k", "--max-time", "20", "-o", tmp.name]
            if self._proxy_url():
                cmd += ["-x", self._proxy_url()]
            for h in self._all_headers():
                cmd += ["-H", h]
            cmd.append(ju)
            try:
                subprocess.run(cmd, capture_output=True, timeout=25)
                body = open(tmp.name, errors="replace").read()
            except (subprocess.SubprocessError, OSError) as e:
                self.append(w, f"[!] {ju}: {e}\n")
                body = ""
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
            if not body:
                continue
            if beautify_on:
                pretty, method = beautify_js(body)
                if method in ("jsbeautifier", "js-beautify cli"):
                    body = pretty
                    os.makedirs(bdir, exist_ok=True)
                    stem = re.sub(r'\.js(\?.*)?$', '', re.sub(r'^https?://', '', ju), flags=re.I)
                    name = (sanitize_for_path(stem) or "script")[:120]
                    try:
                        with open(os.path.join(bdir, name + ".js"), "w") as bf:
                            bf.write(pretty)
                    except OSError:
                        pass
                elif method == "none" and not warned_no_beautify[0]:
                    warned_no_beautify[0] = True
                    self.append(w, "[*] No JS beautifier found — analyzing minified "
                                   "source. Install via Settings → Install missing tools "
                                   "(js-beautify) for readable output.\n")
            eps, secs = [], []
            if self.js_endpoints.get():
                eps = extract_js_endpoints(body)
            if self.js_secrets.get():
                secs = extract_js_secrets(body)
            if has_jsluice:
                try:
                    jr = subprocess.run(["jsluice", "urls", "-"], input=body,
                                        capture_output=True, text=True, timeout=20)
                    for line in jr.stdout.splitlines():
                        try:
                            eps.append(json.loads(line).get("url", ""))
                        except ValueError:
                            pass
                except (subprocess.SubprocessError, OSError):
                    pass
            all_ep.update(e for e in eps if e)
            for s in secs:
                if s not in all_sec:
                    all_sec.append(s)
            self.append(w, f"[+] {ju}  ->  {len(eps)} endpoints, {len(secs)} secrets\n")
        ep_file = os.path.join(outdir, "js_endpoints.txt")
        with open(ep_file, "w") as f:
            f.write("\n".join(sorted(all_ep)) + ("\n" if all_ep else ""))
        self.state.setdefault("js_endpoints", [])
        self.state["js_endpoints"] = sorted(all_ep)
        self.append(w, f"\n=== {len(all_ep)} unique endpoints -> {ep_file} ===\n")
        for e in sorted(all_ep):
            self.append(w, f"  {e}\n")
        if all_sec:
            sec_file = os.path.join(outdir, "js_secrets.txt")
            with open(sec_file, "w") as f:
                for lbl, v in all_sec:
                    f.write(f"{lbl}\t{v}\n")
            self.append(w, f"\n=== {len(all_sec)} possible secrets -> {sec_file} ===\n")
            for lbl, v in all_sec:
                self.append(w, f"  [{lbl}] {v}\n")
        else:
            self.append(w, "\n[*] No secrets matched.\n")
        if beautify_on and os.path.isdir(bdir):
            self.append(w, f"\n[*] Beautified JS saved in {bdir}/\n")
        self.update_status(f"JS analysis done: {len(all_ep)} endpoints, {len(all_sec)} secrets")

    # ---- Takeover ---- #
    def start_takeover(self):
        hosts = [h for h in self._lines_from(self.takeover_input)
                 if is_host(re.sub(r'^https?://', '', h).split("/")[0])]
        hosts = self.scope_filter(hosts, self.outputs["takeover"])
        if not hosts:
            messagebox.showwarning("Input", "No valid in-scope hosts.")
            return
        self._launch(self.run_takeover, self.outputs["takeover"], (hosts,))

    def run_takeover(self, hosts):
        w = self.outputs["takeover"]
        hosts = [re.sub(r'^https?://', '', h).split("/")[0] for h in hosts]
        outdir = self.state["outdir"] or self._new_outdir(hosts[0])
        infile = os.path.join(outdir, "takeover_hosts.txt")
        with open(infile, "w") as f:
            f.write("\n".join(hosts) + "\n")
        did = False
        if self.tko_dnsx.get() and self.require(w, "dnsx"):
            did = True
            self.append(w, "\n=== dnsx CNAME map ===\n")
            self.run_stream(self.augment(
                ["dnsx", "-l", infile, "-cname", "-resp", "-silent"], "dnsx"),
                w, outfile=os.path.join(outdir, "takeover_cnames.txt"))
        if self.tko_subzy.get() and self.has_tool("subzy"):
            did = True
            self.append(w, "\n=== subzy ===\n")
            self.run_stream(["subzy", "run", "--targets", infile, "--hide_fails"], w)
        elif self.tko_subzy.get():
            self.append(w, "[*] subzy not installed (optional) — skipping.\n")
        if self.tko_nuclei.get() and self.require(w, "nuclei"):
            did = True
            self.append(w, "\n=== nuclei takeover templates ===\n")
            self.run_stream(self.augment(
                ["nuclei", "-l", infile, "-tags", "takeover", "-silent"], "nuclei"),
                w, outfile=os.path.join(outdir, "takeover_nuclei.txt"))
        if did:
            self.append(w, f"\n[+] Takeover checks done -> {outdir}\n")
        self.update_status("Takeover check done.")

    # ---- Params (arjun) ---- #
    def start_params(self):
        urls = [u for u in self._lines_from(self.params_input) if is_url(u)]
        urls = self.scope_filter(urls, self.outputs["params"])
        if not urls:
            messagebox.showwarning("Input", "No valid in-scope URLs.")
            return
        self._launch(self.run_params, self.outputs["params"], (urls,))

    def run_params(self, urls):
        w = self.outputs["params"]
        if not self.require(w, "arjun"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', urls[0]).split("/")[0])
        infile = os.path.join(outdir, "arjun_urls.txt")
        with open(infile, "w") as f:
            f.write("\n".join(urls) + "\n")
        out = os.path.join(outdir, "arjun_params.txt")
        cmd = ["arjun", "-i", infile, "-oT", out,
               "-m", self.params_method.get(),
               "-t", str(max(1, self.params_threads.get()))]
        if self.gopts["rate"]:
            # arjun has no req/s flag; -d adds a per-request delay instead.
            cmd += ["-d", str(round(1.0 / self.gopts["rate"], 2))]
        if self._proxy_url():
            self.append(w, "[*] Note: arjun has no proxy option; its traffic won't "
                           "go through Burp.\n")
        cmd = self.augment(cmd, "arjun")   # adds --headers
        self.update_status(f"arjun on {len(urls)} URL(s) ...")
        self.run_stream(cmd, w)
        if os.path.isfile(out):
            self.append(w, f"\n[+] Parameters saved -> {out}\n")
        self.update_status("Param discovery done.")

    # ---- Vhost fuzzing ---- #
    def start_vhost(self):
        target = self.vhost_target.get().strip()
        target = re.sub(r'^https?://', '', target).split("/")[0]
        domain = self.vhost_domain.get().strip().lstrip(".")
        wl = self.vhost_wordlist.get().strip()
        if not is_host(target):
            messagebox.showwarning("Input", "Enter a valid target host or IP.")
            return
        if not is_domain(domain):
            messagebox.showwarning("Input", "Enter a valid base domain (e.g. example.com).")
            return
        if not os.path.isfile(wl):
            messagebox.showwarning("Wordlist", f"Wordlist not found:\n{wl}")
            return
        if not self.scope_filter([domain], self.outputs["vhost"]):
            messagebox.showwarning("Scope", f"{domain} is out of scope.")
            return
        self._launch(self.run_vhost, self.outputs["vhost"], (target, domain, wl))

    def run_vhost(self, target, domain, wl):
        w = self.outputs["vhost"]
        if not self.require(w, "ffuf"):
            return
        outdir = self.state["outdir"] or self._new_outdir(domain)
        scheme = "https" if self.vhost_https.get() else "http"
        out = os.path.join(outdir, f"vhosts_{sanitize_for_path(domain)}.json")
        cmd = ["ffuf", "-u", f"{scheme}://{target}/", "-w", wl,
               "-H", f"Host: FUZZ.{domain}", "-noninteractive", "-s",
               "-o", out, "-of", "json", "-ac", "-mc", "all"]
        rate = self.gopts["rate"]
        if rate:
            cmd += ["-rate", str(rate)]
        if self._proxy_url():
            cmd += ["-x", self._proxy_url()]
        for h in self._all_headers():
            cmd += ["-H", h]
        self.update_status(f"Fuzzing vhosts on {target} for *.{domain} ...")
        self.append(w, f"[*] ffuf Host: FUZZ.{domain} -> {scheme}://{target}/  "
                       f"(auto-calibrated)\n")
        # ffuf deadlocks if its stderr is merged into the stdout pipe -> keep split
        self.run_stream(cmd, w, skip_blank=True, merge_stderr=False)
        hits = self._parse_ffuf_file(out)
        if hits:
            self.append(w, f"\n[+] {len(hits)} candidate vhost(s):\n")
            for label, code, size in hits:
                self.append(w, f"  {label}.{domain}  -> [{code}] {size} B\n")
            self.state["vhosts"] = [f"{lb}.{domain}" for lb, _, _ in hits]
        else:
            self.append(w, "\n[*] No vhosts stood out from the calibrated baseline.\n")
        self.update_status(f"Vhost fuzzing done -> {out}")

    @staticmethod
    def _parse_ffuf_file(path):
        """Read an ffuf JSON output file -> [(label, status, length)].
        label is the FUZZ input value when present, else the matched URL."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        out = []
        for r in data.get("results", []):
            label = (r.get("input", {}) or {}).get("FUZZ") or r.get("url", "")
            out.append((label, r.get("status", ""), r.get("length", "")))
        return out

    # ---- API routes (kiterunner) ---- #
    def start_kiterunner(self):
        targets = [t for t in self._lines_from(self.api_input)
                   if is_host(re.sub(r'^https?://', '', t).split("/")[0].split(":")[0])]
        targets = self.scope_filter(targets, self.outputs["api"])
        if not targets:
            messagebox.showwarning("Input", "No valid in-scope API hosts.")
            return
        wl = self.api_wordlist.get().strip()
        an = self.api_assetnote.get().strip()
        if not an and not os.path.isfile(wl):
            messagebox.showwarning("Wordlist", "Choose a .kite/.txt wordlist file, or set "
                                              "an Assetnote wordlist name (-A).")
            return
        self._launch(self.run_kiterunner, self.outputs["api"], (targets, wl, an))

    def run_kiterunner(self, targets, wl, an):
        w = self.outputs["api"]
        if not self.require(w, "kr"):
            self.append(w, "[*] kiterunner (kr) isn't installed. Install via Settings → "
                           "Install missing tools, or grab a release binary from "
                           "https://github.com/assetnote/kiterunner/releases\n")
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', targets[0]).split("/")[0])
        infile = os.path.join(outdir, "kr_targets.txt")
        with open(infile, "w") as f:
            f.write("\n".join(targets) + "\n")
        out = os.path.join(outdir, "kiterunner.txt")
        cmd = ["kr", "scan", infile, "-o", "text",
               "-d", str(max(1, self.api_depth.get())),
               "-x", str(max(1, self.api_conns.get()))]
        if an:
            cmd += ["-A", an]      # named Assetnote wordlist (auto-downloads)
        else:
            cmd += ["-w", wl]      # local .kite or .txt
        if self.gopts["rate"]:     # kr throttles by delay, not req/s
            cmd += ["--delay", f"{max(1, int(1000 / self.gopts['rate']))}ms"]
        cmd = self.augment(cmd, "kr")   # proxy + headers
        self.update_status(f"kiterunner on {len(targets)} host(s) ...")
        self.append(w, f"[*] Scanning {len(targets)} host(s) with "
                       f"{'Assetnote ' + an if an else os.path.basename(wl)}\n")
        self.run_stream(cmd, w, outfile=out)
        self.append(w, f"\n[+] kiterunner done -> {out}\n")
        self.update_status("API route scan done.")

    # ---- 403 bypass ---- #
    BYPASS_PATHS = [
        "{p}/", "{p}/.", "{p}//", "{p}/./", "{p}/%2e/", "{p}%20", "{p}%09",
        "{p}?", "{p}#", "{p}/..;/", "{p};/", "{p}.json", "{p}.html", "{p}/~",
        "/%2e{p}", "{p}..%2f", "{p}%2e%2e%2f",
    ]
    BYPASS_HEADERS = [
        ("X-Forwarded-For", "127.0.0.1"), ("X-Forwarded-Host", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"), ("X-Remote-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"), ("X-Host", "127.0.0.1"),
        ("X-Original-URL", "{path}"), ("X-Rewrite-URL", "{path}"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
    ]

    def start_bypass(self):
        urls = [u for u in self._lines_from(self.bypass_input) if is_url(u)]
        urls = self.scope_filter(urls, self.outputs["bypass"])
        if not urls:
            messagebox.showwarning("Input", "No valid in-scope URLs.")
            return
        self._launch(self.run_bypass, self.outputs["bypass"], (urls,))

    def run_bypass(self, urls):
        w = self.outputs["bypass"]
        if not self.require(w, "curl"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', urls[0]).split("/")[0])
        results = []
        for url in urls:
            if self.stop_requested:
                break
            base = re.sub(r'^(https?://[^/]+)(/.*)?$', r'\1', url)
            path = url[len(base):] or "/"
            orig_code, orig_size = self._curl_probe(url)
            self.append(w, f"\n=== {url}  (baseline [{orig_code}] {orig_size} B) ===\n")
            wins = []
            # path mutations
            for tmpl in self.BYPASS_PATHS:
                if self.stop_requested:
                    break
                mutated = base + tmpl.format(p=path)
                code, size = self._curl_probe(mutated)
                if code and code not in ("403", "401", orig_code) and code[0] in "23":
                    wins.append((f"path {tmpl.format(p=path)}", code, size))
                    self.append(w, f"  [BYPASS] {mutated}  -> [{code}] {size} B\n")
            # header tricks
            for name, val in self.BYPASS_HEADERS:
                if self.stop_requested:
                    break
                hv = val.format(path=path)
                code, size = self._curl_probe(url, extra_headers=[f"{name}: {hv}"])
                if code and code not in ("403", "401", orig_code) and code[0] in "23":
                    wins.append((f"header {name}: {hv}", code, size))
                    self.append(w, f"  [BYPASS] {name}: {hv}  -> [{code}] {size} B\n")
            # method change
            for method in ("POST", "PUT", "TRACE", "OPTIONS"):
                if self.stop_requested:
                    break
                code, size = self._curl_probe(url, method=method)
                if code and code not in ("403", "401", orig_code) and code[0] in "23":
                    wins.append((f"method {method}", code, size))
                    self.append(w, f"  [BYPASS] method {method}  -> [{code}] {size} B\n")
            if not wins:
                self.append(w, "  no bypass found.\n")
            results.append((url, orig_code, wins))
        out = os.path.join(outdir, "bypass_403.txt")
        with open(out, "w") as f:
            for url, oc, wins in results:
                f.write(f"{url} (baseline {oc})\n")
                for desc, code, size in wins:
                    f.write(f"  BYPASS {desc} -> {code} {size}B\n")
        total = sum(len(wn) for _, _, wn in results)
        self.append(w, f"\n[+] {total} bypass(es) across {len(urls)} URL(s) -> {out}\n")
        self.update_status(f"403 bypass done: {total} hit(s).")

    # ---- WPScan ---- #
    def start_wpscan(self):
        url = self.wpscan_url.get().strip()
        if not url.startswith("http"):
            url = "https://" + url
        host = re.sub(r'^https?://', '', url).split("/")[0]
        if not is_host(host):
            messagebox.showwarning("Input", "Enter a valid WordPress URL.")
            return
        if not self.scope_filter([host], self.outputs["wpscan"]):
            messagebox.showwarning("Scope", f"{host} is out of scope.")
            return
        self._launch(self.run_wpscan, self.outputs["wpscan"], (url,))

    def run_wpscan(self, url):
        w = self.outputs["wpscan"]
        if not self.require(w, "wpscan"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', url).split("/")[0])
        out = os.path.join(outdir, "wpscan.txt")
        enum = "".join(c for c, v in self.wp_enum.items() if v.get())
        cmd = ["wpscan", "--url", url, "--no-banner", "--disable-tls-checks",
               "-f", "cli-no-color", "-o", out]
        if enum:
            cmd += ["-e", enum]
        if self.wp_stealth.get():
            cmd += ["--stealthy"]
        if self.wp_token.get().strip():
            cmd += ["--api-token", self.wp_token.get().strip()]
        cmd = self.augment(cmd, "wpscan")
        self.update_status(f"wpscan {url} ...")
        self.run_stream(cmd, w)
        self.append(w, f"\n[+] Saved -> {out}\n")
        self.update_status("wpscan done.")

    # ---- Nikto ---- #
    def start_nikto(self):
        targets = [t for t in self._lines_from(self.nikto_input)
                   if is_host(re.sub(r'^https?://', '', t).split("/")[0])]
        targets = self.scope_filter(targets, self.outputs["nikto"])
        if not targets:
            messagebox.showwarning("Input", "No valid in-scope hosts.")
            return
        self._launch(self.run_nikto, self.outputs["nikto"], (targets,))

    def run_nikto(self, targets):
        w = self.outputs["nikto"]
        if not self.require(w, "nikto"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', targets[0]).split("/")[0])
        for i, tgt in enumerate(targets, 1):
            if self.stop_requested:
                break
            self.update_status(f"nikto {i}/{len(targets)}: {tgt}")
            safe = sanitize_for_path(re.sub(r'^https?://', '', tgt))
            out = os.path.join(outdir, f"nikto_{safe}.txt")
            cmd = ["nikto", "-h", tgt, "-ask", "no", "-nointeractive",
                   "-Format", "txt", "-output", out]
            if self.nikto_ssl.get():
                cmd += ["-ssl"]
            if self.nikto_tuning.get().strip():
                cmd += ["-Tuning", self.nikto_tuning.get().strip()]
            if self._proxy_url():
                cmd += ["-useproxy", self._proxy_url()]
            for h in self._all_headers():
                cmd += ["-Add-header", h]
            self.append(w, f"\n=== nikto {tgt} ===\n")
            self.run_stream(cmd, w)
        self.append(w, f"\n[+] Nikto done -> {outdir}\n")
        self.update_status("nikto done.")

if __name__ == "__main__":
    root = tk.Tk()
    app = GhostReconGUI(root)
    root.mainloop()
