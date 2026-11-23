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
import shlex
import socket
import sqlite3
from urllib.parse import urlsplit, parse_qsl, quote, urlencode

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
    "sqlmap": "--proxy", "dalfox": "--proxy", "crlfuzz": "-x",
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
    "sqlmap": ("-H", "repeat"), "dalfox": ("-H", "repeat"),
    "crlfuzz": ("-H", "repeat"),
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
    # Active Testing: LFImap must never reach out-of-band unless explicitly allowed
    "lfi_allow_callbacks": False,  # permit LFImap RFI / reverse-shell / --callback vectors
}

# Install one-liner for Python git-clone tools: clone into a shared dir + venv,
# then drop a PATH wrapper in ~/.local/bin so shutil.which() can find them.
GR_PYTOOL_INSTALL = (
    'GRT="$HOME/.local/share/ghostrecon-tools"; '
    'mkdir -p "$GRT" "$HOME/.local/bin"; '
    'test -d "$GRT/{name}" || git clone --depth 1 {repo} "$GRT/{name}"; '
    'test -d "$GRT/.venv" || python3 -m venv "$GRT/.venv"; '
    '"$GRT/.venv/bin/pip" install -q {deps}; '
    "printf '#!/bin/sh\\nexec \"%s\" \"%s\" \"$@\"\\n' "
    '"$GRT/.venv/bin/python" "$GRT/{entry}" > "$HOME/.local/bin/{cmd}"; '
    'chmod +x "$HOME/.local/bin/{cmd}"'
)
# trufflehog can't `go install` (replace directives) -> fetch the release binary.
GR_TRUFFLEHOG_INSTALL = (
    'mkdir -p "$HOME/.local/bin"; '
    'ARCH=$(uname -m | sed "s/aarch64/arm64/;s/x86_64/amd64/"); '
    'URL=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest '
    '| grep -o "https://[^\\"]*linux_${ARCH}.tar.gz" | head -1); '
    'curl -sSL -o /tmp/gr_th.tgz "$URL"; '
    'tar -xzf /tmp/gr_th.tgz -C "$HOME/.local/bin" trufflehog; '
    'chmod +x "$HOME/.local/bin/trufflehog"; rm -f /tmp/gr_th.tgz'
)


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
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)
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
        lfi_cb = tk.BooleanVar(value=g["lfi_allow_callbacks"])
        ttk.Checkbutton(frm, text="Allow LFImap external callbacks (RFI / reverse shell / "
                                 "--callback) in Active Testing", variable=lfi_cb
                        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Label(frm, text="Off by default: LFImap runs only local-inclusion techniques and "
                            "never reaches out-of-band.\nTurn on only when a program permits it; "
                            "set the Callback host above for the payload target.",
                  foreground=t["tab_fg"]).grid(row=row, column=0, columnspan=3,
                                               sticky="w", pady=(0, 6))
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
                "lfi_allow_callbacks": lfi_cb.get(),
            })
            self._save_settings()
            self._refresh_lfi_callback_ui()
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
        settings.add_command(label="Update installed tools…",
                             command=self.open_update_dialog)
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
        self._build_notes_tab()
        self._build_oneshot_tab()
        self._build_subdomain_tab()
        self._build_livehost_tab()
        self._build_url_tab()
        self._build_port_tab()
        self._build_vuln_tab()
        self._build_dirbust_tab()
        self._build_reconplus_tab()
        self._build_webscan_tab()
        self._build_active_tab()
        self._build_vulnscan_tab()

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
        self._notes_sync_scope(path, entries)

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
        self._select_tab(dest)
        self.update_status(f"Sent {msg} to {dest}")

    def _select_tab(self, label):
        """Select a top-level tab by its label (robust to tabs being added/reordered)."""
        for tab_id in self.notebook.tabs():
            if self.notebook.tab(tab_id, "text") == label:
                self.notebook.select(tab_id)
                return

    # --- Tab: Notes — per-asset notebook backed by SQLite ------------------ #
    # Every scope asset (auto-imported when a scope file loads) plus anything
    # added by hand gets a row; each row carries a status, tags and free-form
    # notes. Stored in ~/.config/ghostrecon/notes.db so notes survive restarts
    # and accumulate across sessions. Only touched from the Tk main thread.
    NOTE_STATUSES = ["untested", "in progress", "interesting", "finding",
                     "reported", "done", "ignore"]

    @staticmethod
    def _notes_db_path():
        return os.path.expanduser("~/.config/ghostrecon/notes.db")

    def _notes_db(self):
        if getattr(self, "_notes_conn", None) is None:
            path = self._notes_db_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fresh = not os.path.exists(path)
            self._notes_conn = sqlite3.connect(path)
            self._notes_conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id      INTEGER PRIMARY KEY,
                    program TEXT NOT NULL,
                    host    TEXT NOT NULL,
                    scope   TEXT NOT NULL DEFAULT 'manual',
                    status  TEXT NOT NULL DEFAULT 'untested',
                    tags    TEXT NOT NULL DEFAULT '',
                    notes   TEXT NOT NULL DEFAULT '',
                    created TEXT NOT NULL,
                    updated TEXT NOT NULL,
                    UNIQUE(program, host))""")
            self._notes_conn.commit()
            if fresh:
                os.chmod(path, 0o600)   # notes may hold creds/tokens found in testing
        return self._notes_conn

    @staticmethod
    def _now():
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    def _build_notes_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Notes")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        self._notes_current = None      # asset id shown in the editor
        self._notes_save_job = None     # pending debounced autosave

        ctl = ttk.Frame(tab)
        ctl.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(ctl, text="Program:").pack(side="left")
        self.notes_program = ttk.Combobox(ctl, state="readonly", width=24)
        self.notes_program.pack(side="left", padx=4)
        self.notes_program.bind("<<ComboboxSelected>>", lambda e: self._notes_refresh())
        ttk.Label(ctl, text="  Status:").pack(side="left")
        self.notes_status_filter = ttk.Combobox(ctl, state="readonly", width=12,
                                                values=["all"] + self.NOTE_STATUSES)
        self.notes_status_filter.set("all")
        self.notes_status_filter.pack(side="left", padx=4)
        self.notes_status_filter.bind("<<ComboboxSelected>>",
                                      lambda e: self._notes_refresh())
        ttk.Label(ctl, text="  Search:").pack(side="left")
        self.notes_search = tk.StringVar()
        self.notes_search.trace_add("write", lambda *a: self._notes_refresh())
        ttk.Entry(ctl, textvariable=self.notes_search, width=24).pack(side="left", padx=4)
        ttk.Label(ctl, text="(host, tags or note text)", foreground="#888"
                  ).pack(side="left")

        pane = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        pane.grid(row=1, column=0, sticky="nsew")

        # Left: asset list
        left = ttk.Frame(pane)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        cols = ("host", "scope", "status", "n", "updated")
        self.notes_tree = ttk.Treeview(left, columns=cols, show="headings",
                                       selectmode="browse")
        for col, label, width, stretch in (("host", "Asset", 220, True),
                                           ("scope", "Scope", 60, False),
                                           ("status", "Status", 90, False),
                                           ("n", "📝", 30, False),
                                           ("updated", "Updated", 130, False)):
            self.notes_tree.heading(col, text=label)
            self.notes_tree.column(col, width=width, stretch=stretch,
                                   anchor="w" if col == "host" else "center")
        self.notes_tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(left, command=self.notes_tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.notes_tree["yscrollcommand"] = sb.set
        self.notes_tree.tag_configure("out", foreground="#c0392b")
        self.notes_tree.tag_configure("finding", foreground="#e67e22")
        self.notes_tree.bind("<<TreeviewSelect>>", self._notes_on_select)

        btns = ttk.Frame(left)
        btns.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(btns, text="Add asset…", command=self._notes_add_dialog
                   ).pack(side="left")
        ttk.Button(btns, text="Import found subs",
                   command=self._notes_import_discovered).pack(side="left", padx=4)
        ttk.Button(btns, text="Delete", command=self._notes_delete).pack(side="left")
        ttk.Button(btns, text="Export .md…", command=self._notes_export
                   ).pack(side="right")
        pane.add(left, weight=1)

        # Right: editor for the selected asset
        right = ttk.Frame(pane, padding=(10, 0, 0, 0))
        right.columnconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)
        self.notes_title = ttk.Label(right, text="Select an asset",
                                     font=("Helvetica", 13, "bold"))
        self.notes_title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
        ttk.Label(right, text="Status:").grid(row=1, column=0, sticky="w")
        self.notes_status = ttk.Combobox(right, state="disabled", width=14,
                                         values=self.NOTE_STATUSES)
        self.notes_status.grid(row=1, column=1, sticky="w", padx=4, pady=2)
        self.notes_status.bind("<<ComboboxSelected>>", lambda e: self._notes_save())
        ttk.Label(right, text="Tags:").grid(row=2, column=0, sticky="w")
        self.notes_tags = ttk.Entry(right, state="disabled")
        self.notes_tags.grid(row=2, column=1, columnspan=2, sticky="ew", padx=4, pady=2)
        self.notes_tags.bind("<KeyRelease>", lambda e: self._notes_schedule_save())

        self.notes_text = tk.Text(right, wrap=tk.WORD, undo=True, state="disabled",
                                  font=("Courier New", 10), relief=tk.FLAT, bd=0)
        self.notes_text.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(6, 0))
        nsb = ttk.Scrollbar(right, command=self.notes_text.yview)
        nsb.grid(row=3, column=3, sticky="ns", pady=(6, 0))
        self.notes_text["yscrollcommand"] = nsb.set
        self.notes_text.bind("<KeyRelease>", lambda e: self._notes_schedule_save())
        self.notes_text.bind("<Control-s>", lambda e: (self._notes_save(), "break")[1])

        foot = ttk.Frame(right)
        foot.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        ttk.Button(foot, text="Insert timestamp",
                   command=self._notes_insert_timestamp).pack(side="left")
        self.notes_saved = ttk.Label(foot, text="", foreground="#888")
        self.notes_saved.pack(side="right")
        pane.add(right, weight=2)

        self._notes_refresh()

    # Data access ---------------------------------------------------------- #
    def _notes_upsert(self, program, host, scope):
        """Insert an asset if new; refresh its scope label if it already exists.
        Never touches existing notes/status. Returns True if a row was added."""
        db, now = self._notes_db(), self._now()
        cur = db.execute("INSERT OR IGNORE INTO assets(program, host, scope, created, "
                         "updated) VALUES (?,?,?,?,?)", (program, host, scope, now, now))
        if not cur.rowcount and scope != "manual":
            db.execute("UPDATE assets SET scope=? WHERE program=? AND host=?",
                       (scope, program, host))
        return bool(cur.rowcount)

    def _notes_program_name(self):
        """Program for new assets: the selected one, else the loaded scope file's
        name, else 'default'."""
        sel = self.notes_program.get()
        if sel and sel != "All programs":
            return sel
        if self.scope.get("file"):
            return os.path.splitext(os.path.basename(self.scope["file"]))[0]
        return "default"

    def _notes_sync_scope(self, path, entries):
        program = os.path.splitext(os.path.basename(path))[0]
        added = sum(self._notes_upsert(program, e["host"], e["scope"]) for e in entries)
        self._notes_db().commit()
        self._notes_refresh(program=program)
        self.append(self.outputs["scope"],
                    f"[+] Notes: {added} new asset(s) added under program '{program}'\n")

    def _notes_refresh(self, program=None):
        if not hasattr(self, "notes_tree"):
            return
        db = self._notes_db()
        programs = [r[0] for r in db.execute(
            "SELECT DISTINCT program FROM assets ORDER BY program")]
        self.notes_program["values"] = ["All programs"] + programs
        if program:
            self.notes_program.set(program)
        elif self.notes_program.get() not in self.notes_program["values"]:
            self.notes_program.set("All programs")

        sql, args = "SELECT id, program, host, scope, status, notes, updated " \
                    "FROM assets WHERE 1=1", []
        prog = self.notes_program.get()
        if prog != "All programs":
            sql += " AND program=?"
            args.append(prog)
        st = self.notes_status_filter.get()
        if st and st != "all":
            sql += " AND status=?"
            args.append(st)
        needle = self.notes_search.get().strip()
        if needle:
            sql += " AND (host LIKE ? OR tags LIKE ? OR notes LIKE ?)"
            args += [f"%{needle}%"] * 3
        sql += " ORDER BY program, scope, host"

        tree = self.notes_tree
        tree.delete(*tree.get_children())
        show_prog = prog == "All programs" and len(programs) > 1
        for aid, p, host, scope, status, notes, updated in db.execute(sql, args):
            tags = ("out",) if scope == "out" else \
                   ("finding",) if status in ("finding", "reported") else ()
            label = f"{host}   [{p}]" if show_prog else host
            tree.insert("", tk.END, iid=str(aid), tags=tags,
                        values=(label, scope, status, "•" if notes.strip() else "",
                                updated))
        if self._notes_current is not None and tree.exists(str(self._notes_current)):
            tree.selection_set(str(self._notes_current))
            tree.see(str(self._notes_current))

    # Editor --------------------------------------------------------------- #
    def _notes_on_select(self, _event=None):
        sel = self.notes_tree.selection()
        if not sel or int(sel[0]) == self._notes_current:
            return
        self._notes_save()                      # flush the asset we're leaving
        row = self._notes_db().execute(
            "SELECT program, host, scope, status, tags, notes, updated FROM assets "
            "WHERE id=?", (int(sel[0]),)).fetchone()
        if not row:
            return
        program, host, scope, status, tags, notes, updated = row
        self._notes_current = int(sel[0])
        self.notes_title.config(text=f"{host}   ·   {program}   ·   {scope}-scope"
                                if scope in ("in", "out") else f"{host}   ·   {program}")
        self.notes_status.config(state="readonly")
        self.notes_status.set(status)
        self.notes_tags.config(state="normal")
        self.notes_tags.delete(0, tk.END)
        self.notes_tags.insert(0, tags)
        self.notes_text.config(state="normal")
        self.notes_text.delete("1.0", tk.END)
        self.notes_text.insert("1.0", notes)
        self.notes_text.edit_reset()
        self.notes_saved.config(text=f"Last saved {updated}")

    def _notes_schedule_save(self):
        if self._notes_save_job:
            self.master.after_cancel(self._notes_save_job)
        self.notes_saved.config(text="Editing…")
        self._notes_save_job = self.master.after(800, self._notes_save)

    def _notes_save(self):
        if self._notes_save_job:
            self.master.after_cancel(self._notes_save_job)
            self._notes_save_job = None
        if self._notes_current is None:
            return
        db = self._notes_db()
        new = (self.notes_status.get() or "untested", self.notes_tags.get().strip(),
               self.notes_text.get("1.0", "end-1c"))
        old = db.execute("SELECT status, tags, notes FROM assets WHERE id=?",
                         (self._notes_current,)).fetchone()
        if old is None or tuple(old) == new:
            return
        now = self._now()
        db.execute("UPDATE assets SET status=?, tags=?, notes=?, updated=? WHERE id=?",
                   (*new, now, self._notes_current))
        db.commit()
        self.notes_saved.config(text=f"Saved {now}")
        iid = str(self._notes_current)
        if self.notes_tree.exists(iid):
            self.notes_tree.set(iid, "status", new[0])
            self.notes_tree.set(iid, "n", "•" if new[2].strip() else "")
            self.notes_tree.set(iid, "updated", now)

    def _on_close(self):
        """Flush any pending note edit before the window goes away."""
        try:
            self._stop_shots_server()
        except Exception:
            pass
        try:
            self._notes_save()
            if getattr(self, "_notes_conn", None) is not None:
                self._notes_conn.close()
        except Exception:
            pass
        self.master.destroy()

    def _notes_insert_timestamp(self):
        if self._notes_current is None:
            return
        self.notes_text.insert(tk.INSERT, f"[{self._now()}] ")
        self.notes_text.focus_set()
        self._notes_schedule_save()

    def _notes_clear_editor(self):
        self._notes_current = None
        self.notes_title.config(text="Select an asset")
        self.notes_status.set("")
        self.notes_status.config(state="disabled")
        self.notes_tags.delete(0, tk.END)
        self.notes_tags.config(state="disabled")
        self.notes_text.delete("1.0", tk.END)
        self.notes_text.config(state="disabled")
        self.notes_saved.config(text="")

    # Actions -------------------------------------------------------------- #
    def _notes_add_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Add asset")
        win.configure(bg=THEMES[self.theme_name]["bg"])
        win.transient(self.master)
        frm = ttk.Frame(win, padding=12)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        ttk.Label(frm, text="Program:").grid(row=0, column=0, sticky="w")
        prog = ttk.Combobox(frm, width=30,
                            values=[v for v in self.notes_program["values"]
                                    if v != "All programs"])
        prog.set(self._notes_program_name())
        prog.grid(row=0, column=1, sticky="ew", pady=3)
        ttk.Label(frm, text="Assets (one per line —\nhost, wildcard, URL or IP):"
                  ).grid(row=1, column=0, sticky="nw")
        box = tk.Text(frm, width=44, height=8, font=("Courier New", 10))
        t = THEMES[self.theme_name]
        box.configure(bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["text_fg"])
        box.grid(row=1, column=1, sticky="nsew", pady=3)
        box.focus_set()

        def _add():
            program = prog.get().strip() or "default"
            hosts = [h.strip().lower() for h in box.get("1.0", tk.END).splitlines()
                     if h.strip()]
            added = 0
            for h in hosts:
                bare = re.sub(r'^https?://', '', h).split("/")[0]
                scope = "manual"
                if self.scope["in_pats"]:
                    scope = "in" if self.in_scope(bare.split(":")[0].lstrip("*.")) \
                        else "out"
                added += self._notes_upsert(program, bare, scope)
            self._notes_db().commit()
            win.destroy()
            self._notes_refresh(program=program)
            self.update_status(f"Notes: added {added} asset(s) to '{program}'")

        ttk.Button(frm, text="Add", command=_add).grid(row=2, column=1, sticky="e",
                                                       pady=(8, 0))

    def _notes_import_discovered(self):
        subs = self.state.get("subdomains") or []
        if not subs:
            messagebox.showinfo("Notes", "No discovered subdomains yet — run "
                                         "1. Subdomains (or One-Stop) first.")
            return
        program = self._notes_program_name()
        added = skipped = 0
        for h in subs:
            if self.scope["in_pats"] and not self.in_scope(h):
                skipped += 1
                continue
            scope = "in" if self.scope["in_pats"] else "manual"
            added += self._notes_upsert(program, h.lower(), scope)
        self._notes_db().commit()
        self._notes_refresh(program=program)
        msg = f"Added {added} new subdomain(s) to '{program}'"
        if skipped:
            msg += f"; skipped {skipped} out-of-scope"
        messagebox.showinfo("Notes", msg + ".")

    def _notes_delete(self):
        if self._notes_current is None:
            return
        host = self.notes_tree.set(str(self._notes_current), "host")
        if not messagebox.askyesno("Notes", f"Delete '{host}' and all its notes?"):
            return
        db = self._notes_db()
        db.execute("DELETE FROM assets WHERE id=?", (self._notes_current,))
        db.commit()
        self._notes_clear_editor()
        self._notes_refresh()

    def _notes_export(self):
        self._notes_save()
        prog = self.notes_program.get()
        path = filedialog.asksaveasfilename(
            title="Export notes", defaultextension=".md",
            initialfile=f"ghostrecon-notes-{prog.replace(' ', '_')}.md",
            filetypes=[("Markdown", "*.md"), ("All files", "*.*")])
        if not path:
            return
        sql, args = ("SELECT program, host, scope, status, tags, notes, updated "
                     "FROM assets"), []
        if prog != "All programs":
            sql += " WHERE program=?"
            args.append(prog)
        sql += " ORDER BY program, scope, host"
        out, last_prog = [f"# GhostRecon notes — {prog}\n",
                          f"_Exported {self._now()}_\n"], None
        for p, host, scope, status, tags, notes, updated in \
                self._notes_db().execute(sql, args):
            if p != last_prog:
                out.append(f"\n## {p}\n")
                last_prog = p
            meta = f"scope: {scope} · status: {status} · updated: {updated}"
            if tags:
                meta += f" · tags: {tags}"
            out.append(f"\n### {host}\n\n{meta}\n")
            if notes.strip():
                out.append(f"\n{notes.rstrip()}\n")
        try:
            with open(path, "w") as f:
                f.write("".join(out))
        except OSError as e:
            messagebox.showerror("Notes", f"Could not write {path}:\n{e}")
            return
        self.update_status(f"Notes exported to {path}")

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

    # ------------------------------------------------------------------ #
    # Tab: One-Stop — run the whole recon pipeline from a single URL.
    # This tab is self-contained: it drives the existing per-stage runners
    # in sequence (they already chain through self.state) and funnels all of
    # their output into its own consolidated log, so the normal recon tabs
    # are never written to and the usual manual workflow is untouched.
    # ------------------------------------------------------------------ #
    # (key, label, default-on). Heavy / intrusive / setup-needing stages
    # default OFF; core recon + quick passive checks default ON.
    ONESHOT_STAGES = [
        ("subdomains",   "Subdomains (subfinder · subfaster · crt.sh)", True),
        ("livehosts",    "Live hosts (httpx)",                      True),
        ("urls",         "URLs & patterns (gau · katana · gf · uro)", True),
        ("ports",        "Port scan (naabu / nmap)",                True),
        ("nuclei",       "Vulnerabilities (nuclei)",                True),
        ("js",           "JS analysis (katana · jsluice)",          True),
        ("takeover",     "Subdomain takeover (dnsx · subzy)",       True),
        ("cors",         "CORS misconfig (corsy)",                  True),
        ("crlf",         "CRLF injection (crlfuzz)",                True),
        ("openredirect", "Open redirect (OpenRedireX)",             True),
        ("exposure",     "Exposed files (.env · .git · backups)",   True),
        ("screenshots",  "Screenshots (gowitness)",                 False),
        ("dirbust",      "Directory busting (dirb / ffuf)",         False),
        ("params",       "Parameter discovery (arjun)",             False),
        ("bypass",       "403 / 401 bypass",                        False),
        ("nikto",        "Nikto web scan",                          False),
        ("ssrf",         "SSRF (needs a reachable callback)",       False),
    ]

    def _build_oneshot_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="★ One-Stop")
        tab.columnconfigure(1, weight=1)

        ttk.Label(tab, text="One-Stop Recon — give one URL, run the whole pipeline",
                  font=("Helvetica", 13, "bold")).grid(
                      row=0, column=0, columnspan=3, sticky="w", pady=(0, 2))
        ttk.Label(tab, foreground=THEMES[self.theme_name]["tab_fg"], wraplength=900,
                  text=("Chains every recon stage from a single target and streams all "
                        "output here. Results also land in results/<target>/. SQLMap, "
                        "LFImap and Dalfox are intentionally excluded — they need "
                        "targeted parameters/request files; run them from Active Testing.")
                  ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 8))

        ttk.Label(tab, text="Target URL / domain:").grid(row=2, column=0, sticky="w", padx=5)
        self.os_target = ttk.Entry(tab, width=55)
        self.os_target.grid(row=2, column=1, sticky="ew", padx=5, pady=4)
        self.os_target.bind("<Return>", lambda e: self.start_oneshot())
        self.os_run_btn = ttk.Button(tab, text="▶ Run Full Pipeline",
                                     command=self.start_oneshot)
        self.os_run_btn.grid(row=2, column=2, padx=5)
        self.run_buttons.append(self.os_run_btn)

        # Stage selection grid
        box = ttk.LabelFrame(tab, text="Stages to run", padding=8)
        box.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=6)
        self.os_stage_vars = {}
        ncols = 2
        for i, (key, label, default) in enumerate(self.ONESHOT_STAGES):
            var = tk.BooleanVar(value=default)
            self.os_stage_vars[key] = var
            ttk.Checkbutton(box, text=label, variable=var).grid(
                row=i // ncols, column=i % ncols, sticky="w", padx=6, pady=1)
        for c in range(ncols):
            box.columnconfigure(c, weight=1)

        ctl = ttk.Frame(tab)
        ctl.grid(row=4, column=0, columnspan=3, sticky="w", padx=4, pady=(0, 4))
        ttk.Button(ctl, text="Select all",
                   command=lambda: [v.set(True) for v in self.os_stage_vars.values()]
                   ).pack(side="left")
        ttk.Button(ctl, text="Select none",
                   command=lambda: [v.set(False) for v in self.os_stage_vars.values()]
                   ).pack(side="left", padx=6)
        ttk.Button(ctl, text="Defaults", command=self._oneshot_reset_defaults
                   ).pack(side="left", padx=(0, 16))
        ttk.Label(ctl, text="Max hosts/URLs per stage:").pack(side="left")
        self.os_maxhosts = tk.IntVar(value=10)
        ttk.Spinbox(ctl, from_=1, to=500, width=5, textvariable=self.os_maxhosts
                    ).pack(side="left", padx=4)
        ttk.Checkbutton(ctl, text="Also run amass (slow; opt-in)",
                        variable=self._amass_var()).pack(side="left", padx=(16, 0))

        extrow = ttk.Frame(tab)
        extrow.grid(row=5, column=0, columnspan=3, sticky="w", padx=4, pady=(0, 4))
        ttk.Label(extrow, text="Dir busting extensions:").pack(side="left", padx=(0, 4))
        self._ext_widgets(extrow, hint="e.g. .aspx,.html — shared with the Dir Busting tab")

        self.ro_output = self._make_output(tab)

    def _oneshot_reset_defaults(self):
        for key, _label, default in self.ONESHOT_STAGES:
            self.os_stage_vars[key].set(default)

    # --- Tab: Subdomains -------------------------------------------------- #
    def _build_subdomain_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="1. Subdomains")

        ttk.Label(tab, text="Domain:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.domain_entry = ttk.Entry(tab, width=45)
        self.domain_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.domain_entry.bind("<Return>", lambda e: self.start_subdomain_recon())
        tab.columnconfigure(1, weight=1)

        btn = ttk.Button(tab, text="Enumerate (subfinder, subfaster, crt.sh, crt.name)",
                         command=self.start_subdomain_recon)
        btn.grid(row=0, column=2, padx=5, pady=5)
        self.run_buttons.append(btn)

        ttk.Checkbutton(tab, text="Also run amass (opt-in: takes several minutes and "
                                  "mostly overlaps subfinder)",
                        variable=self._amass_var()
                        ).grid(row=1, column=0, columnspan=3, sticky="w", padx=5)

        self.outputs["sub"] = self._make_output(tab)

    def _ext_widgets(self, parent, hint):
        """Extensions entry + 'bare words' toggle, packed into `parent`. The
        variables are shared, so the Dir Busting tab and One-Stop stay in sync."""
        if not hasattr(self, "db_extensions"):
            self.db_extensions = tk.StringVar(value="")
            self.db_ext_bare = tk.BooleanVar(value=True)
        ttk.Entry(parent, textvariable=self.db_extensions, width=30).pack(side="left")
        ttk.Checkbutton(parent, text="Also try bare words",
                        variable=self.db_ext_bare).pack(side="left", padx=(8, 0))
        ttk.Label(parent, text=hint, foreground="#888").pack(side="left", padx=(8, 0))

    @staticmethod
    def _parse_extensions(text):
        """'.aspx, html .asp' -> ['.aspx', '.html', '.asp']. Raises ValueError
        naming the first invalid entry."""
        exts = []
        for e in re.split(r'[\s,;]+', text.strip()):
            if not e:
                continue
            e = e if e.startswith(".") else "." + e
            if not re.match(r'^\.[A-Za-z0-9_.~-]+$', e):
                raise ValueError(e)
            if e not in exts:
                exts.append(e)
        return exts

    def _amass_var(self):
        """Shared opt-in toggle for amass (Subdomains tab + One-Stop). Off by default."""
        if not hasattr(self, "use_amass"):
            self.use_amass = tk.BooleanVar(value=False)
        return self.use_amass

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
        # File extensions appended to every word (IIS/.NET-style sites where
        # pages are e.g. login.aspx, default.html rather than directories)
        ttk.Label(wl, text="Extensions:").grid(row=2, column=0, sticky="w")
        extf = ttk.Frame(wl)
        extf.grid(row=2, column=1, columnspan=2, sticky="ew", padx=4, pady=(3, 1))
        self._ext_widgets(extf, hint="e.g. .aspx,.asp,.html  (word -> word.aspx; blank = off)")

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
            "nikto_input", "api_input", "notes_text", "shots_input")]
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
        if self._on_notes_tab():
            return   # never wipe notes from the generic Clear button
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

    def _on_notes_tab(self):
        try:
            return self.notebook.tab(self.notebook.select(), "text") == "Notes"
        except tk.TclError:
            return False

    def save_active_output(self):
        if self._on_notes_tab():
            return self._notes_export()
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
        "sqlmap": "https://github.com/sqlmapproject/sqlmap",
        "lfimap": "https://github.com/hansmach1ne/LFImap",
        "dalfox": "https://github.com/hahwul/dalfox",
        "corsy": "https://github.com/s0md3v/Corsy",
        "crlfuzz": "https://github.com/dwisiswant0/crlfuzz",
        "openredirex": "https://github.com/devanshbatham/OpenRedireX",
        "gitleaks": "https://github.com/gitleaks/gitleaks",
        "trufflehog": "https://github.com/trufflesecurity/trufflehog",
        "gowitness": "https://github.com/sensepost/gowitness",
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
        "sqlmap":    ("apt", "sudo apt-get install -y sqlmap"),
        "lfimap":    ("pip", "pipx install lfimap 2>/dev/null || pip3 install --user lfimap"),
        "dalfox":    ("go", "go install github.com/hahwul/dalfox/v2@latest"),
        "crlfuzz":   ("go", "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
        "gitleaks":  ("go", "go install github.com/zricethezav/gitleaks/v8@latest"),
        "gowitness": ("go", "go install github.com/sensepost/gowitness@latest"),
        # Python git-clone tools: clone into a shared dir + venv, then drop a
        # PATH wrapper in ~/.local/bin so `which` finds them.
        "corsy":     ("pip", GR_PYTOOL_INSTALL.format(
                        repo="https://github.com/s0md3v/Corsy", name="Corsy",
                        deps="requests", cmd="corsy", entry="Corsy/corsy.py")),
        "openredirex": ("pip", GR_PYTOOL_INSTALL.format(
                        repo="https://github.com/devanshbatham/OpenRedireX",
                        name="OpenRedireX", deps="aiohttp tqdm", cmd="openredirex",
                        entry="OpenRedireX/openredirex.py")),
        # trufflehog can't `go install` (replace directives); fetch the release binary.
        "trufflehog": ("pip", GR_TRUFFLEHOG_INSTALL),
    }
    # Tools that are optional enhancers: never block a stage, just improve it.
    OPTIONAL_TOOLS = {"jsluice", "subzy", "x8", "js-beautify", "kr", "amass"}

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
    # Settings: auto-install missing tools  (+ self-healing diagnostics)
    # ------------------------------------------------------------------ #
    # Named-on-PyPI tools we can fall back to installing in a dedicated venv
    # (console-script name) when the system blocks a plain pip/pipx install.
    PIP_PKG = {
        "lfimap":      ("lfimap",      ["lfimap"]),
        "uro":         ("uro",         ["uro"]),
        "arjun":       ("arjun",       ["arjun"]),
        "js-beautify": ("jsbeautifier", ["js-beautify"]),
    }
    GR_TOOLS_DIR = "~/.local/share/ghostrecon-tools"

    def _go_toolchain_cmd(self):
        """Shell that downloads the latest official Go into the GhostRecon tools
        dir. Used to self-heal 'go too old' / 'go not found' install failures
        without touching the system/apt Go."""
        grt = self.GR_TOOLS_DIR
        return (
            f'set -e; GRT="$(eval echo {grt})"; mkdir -p "$GRT"; '
            'ARCH=$(uname -m | sed "s/aarch64/arm64/;s/x86_64/amd64/;s/armv7l/armv6l/"); '
            'VER=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1); '
            'test -n "$VER" || { echo "could not resolve latest Go version"; exit 1; }; '
            'echo "downloading ${VER} (linux-${ARCH}) ..."; '
            'curl -fsSL -o /tmp/gr_go.tgz "https://go.dev/dl/${VER}.linux-${ARCH}.tar.gz"; '
            'rm -rf "$GRT/go"; tar -xzf /tmp/gr_go.tgz -C "$GRT"; rm -f /tmp/gr_go.tgz; '
            'echo "installed ${VER} to $GRT/go"'
        )

    def _venv_pip_cmd(self, pkgs, cmds):
        """Shell that installs PyPI packages into the shared GhostRecon venv and
        links their console scripts onto ~/.local/bin — the PEP 668 fallback."""
        links = "; ".join(
            'ln -sf "$GRT/.venv/bin/%s" "$HOME/.local/bin/%s"' % (c, c) for c in cmds)
        grt = self.GR_TOOLS_DIR
        return (
            f'GRT="$(eval echo {grt})"; mkdir -p "$HOME/.local/bin"; '
            'test -d "$GRT/.venv" || python3 -m venv "$GRT/.venv"; '
            '"$GRT/.venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true; '
            '"$GRT/.venv/bin/pip" install -q %s && { %s; }' % (pkgs, links)
        )

    def _go_bin_dir(self):
        return os.path.expanduser(self.GR_TOOLS_DIR + "/go/bin")

    def _diagnose_install(self, name, method, cmd, output):
        """Inspect a failed install's captured output and work out what the tool
        actually needs. Returns a remediation dict understood by the retry path:
            {why, pre, pre_go, cmd}
        where `pre` is an optional prerequisite shell step, `pre_go` flags that a
        fresh Go toolchain was placed and PATH must be updated, and `cmd` is the
        (possibly rewritten) install command to run on retry. `cmd=None` means the
        fix is manual (no auto-retry)."""
        low = (output or "").lower()

        # --- transient network failure (checked first: can hit any method) -- #
        if ('could not resolve host' in low or 'connection refused' in low
                or 'connection timed out' in low or 'temporary failure in name' in low
                or 'tls handshake timeout' in low or 'i/o timeout' in low
                or 'network is unreachable' in low):
            return {"why": "Looks like a network error. Fix: retry the same command.",
                    "pre": None, "pre_go": False, "cmd": cmd}

        # --- Go module needs a newer Go than is installed ------------------- #
        mver = re.search(r'requires go[ >=]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', low)
        if not mver:
            mver = re.search(r'go\.mod[^\n]*\bgo ([0-9]+\.[0-9]+)', low)
        go_old = bool(mver) or 'note: module requires go' in low or \
            'but go.mod requires go' in low or 'compile: version "go' in low or \
            'invalid go version' in low or 'go: updates to go.mod needed' in low
        if method == "go" and go_old and self.has_tool("go"):
            want = mver.group(1) if mver else "a newer"
            return {
                "why": (f"This module needs Go {want}, but the Go on PATH is older. "
                        "Fix: fetch the latest official Go toolchain into "
                        f"{self.GR_TOOLS_DIR}/go and retry the build with it."),
                "pre": self._go_toolchain_cmd(), "pre_go": True, "cmd": cmd,
            }

        # --- Go not installed at all ---------------------------------------- #
        if method == "go" and ('command not found' in low or 'go: not found' in low
                               or ': go: ' in low or not self.has_tool("go")):
            return {
                "why": ("The Go toolchain isn't installed. Fix: fetch the latest "
                        f"official Go into {self.GR_TOOLS_DIR}/go and retry."),
                "pre": self._go_toolchain_cmd(), "pre_go": True, "cmd": cmd,
            }

        # --- Python: PEP 668 externally-managed / pipx missing -------------- #
        pep668 = 'externally-managed-environment' in low or 'externally managed' in low
        pipx_missing = ('pipx: command not found' in low or 'pipx: not found' in low
                        or 'no module named pipx' in low or ': pipx:' in low)
        if method == "pip" and name in self.PIP_PKG:
            pkg, consoles = self.PIP_PKG[name]
            if pep668:
                why = ("This system blocks pip from installing into it (PEP 668 "
                       "'externally-managed-environment'). Fix: install "
                       f"{pkg} into a dedicated venv and link it onto your PATH.")
            elif pipx_missing:
                why = ("pipx isn't available, so the pipx path failed. Fix: install "
                       f"{pkg} into a dedicated venv and link it onto your PATH.")
            else:
                why = (f"The pip install of {pkg} failed. Fix: retry inside a "
                       "dedicated venv and link it onto your PATH.")
            return {"why": why, "pre": None, "pre_go": False,
                    "cmd": self._venv_pip_cmd(pkg, consoles)}

        # --- apt needs sudo / interactive ----------------------------------- #
        if method == "apt" and ('are you root' in low or 'permission denied' in low
                                or 'sudo: a password is required' in low
                                or 'could not open lock' in low):
            return {"why": ("This package installs via apt and needs root. Fix: run "
                            f"in a terminal:\n        {cmd}"),
                    "pre": None, "pre_go": False, "cmd": None}

        # --- unknown: still let the user re-run the same command ------------- #
        return {"why": "Install failed (see log). Retrying re-runs the same command.",
                "pre": None, "pre_go": False, "cmd": cmd}

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
            ("ⓘ 'go' not found — GhostRecon will fetch the official Go toolchain "
             "automatically if you install a Go-based tool.")
        ttk.Label(win, text=note, wraplength=690).pack(anchor="w", padx=12, pady=(0, 8))

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
            # go/pip are auto-installable; a missing Go gets bootstrapped on demand,
            # so Go tools are selectable even before Go is present.
            installable = method in ("go", "pip")
            var = tk.BooleanVar(value=installable)
            self._install_vars[name] = (var, method, cmd)
            cb = ttk.Checkbutton(row, variable=var, text=f"{name}")
            cb.pack(side="left")
            if name == "amass":
                hint = "opt-in only — " + ("needs sudo — run in a terminal"
                                           if method == "apt" else cmd)
            elif method == "apt":
                hint = "needs sudo — run in a terminal"
            elif method == "go" and not have_go:
                hint = "needs Go (fetched automatically)"
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
        retry_btn = ttk.Button(btnrow, text="⟳ Retry failed (apply fixes)")
        retry_btn.pack(side="right", padx=6)
        ttk.Button(btnrow, text="Close", command=win.destroy).pack(side="right", padx=6)

        # Failures persist on self so a reopened dialog can still retry them.
        if not hasattr(self, "_install_failures"):
            self._install_failures = {}   # name -> {method, cmd, rem}

        def append(text):
            win.after(0, lambda: (out.config(state="normal"), out.insert(tk.END, text),
                                  out.see(tk.END), out.config(state="disabled")))

        def set_running(flag):
            install_btn.config(state=(tk.DISABLED if flag else tk.NORMAL))
            fixable = any(d.get("rem") and d["rem"].get("cmd")
                          for d in self._install_failures.values())
            retry_btn.config(state=(tk.NORMAL if (not flag and fixable) else tk.DISABLED))

        def stream(command, sink=None):
            """Run a shell command, streaming output into the log (and optionally
            collecting it for diagnosis). Returns the exit code."""
            try:
                proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
            except Exception as e:
                append(f"[ERROR] could not start: {e}\n")
                if sink is not None:
                    sink.append(str(e))
                return 1
            for line in proc.stdout:
                append(line)
                if sink is not None:
                    sink.append(line)
            proc.wait()
            return proc.returncode

        def run_one(name, method, cmd, rem=None):
            """Install one tool, optionally applying a diagnosed remediation.
            Records/clears the failure and returns True on success."""
            if rem and rem.get("pre"):
                append(f"\n--- preparing prerequisite for {name} ---\n")
                stream(rem["pre"])
                if rem.get("pre_go"):
                    gb = self._go_bin_dir()
                    if os.path.isdir(gb) and gb not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = gb + os.pathsep + os.environ.get("PATH", "")
                        append(f"    ↳ added {gb} to PATH for this session\n")
            runcmd = (rem or {}).get("cmd") or cmd
            if not runcmd:
                append(f"\n=== {name}: no automatic installer — manual step required ===\n")
                return False
            append(f"\n=== Installing {name} ===\n$ {runcmd}\n")
            captured = []
            stream(runcmd, captured)
            if self.has_tool(name):
                append(f"[OK] {name} installed.\n")
                self._install_failures.pop(name, None)
                return True
            # Failed: diagnose what the tool actually needs and remember it.
            diag = self._diagnose_install(name, method, runcmd, "".join(captured))
            self._install_failures[name] = {"method": method, "cmd": cmd, "rem": diag}
            append(f"[FAILED] {name} — not found after install.\n")
            if diag and diag.get("why"):
                append(f"    ↳ diagnosis: {diag['why']}\n")
                append("    ↳ Click '⟳ Retry failed (apply fixes)' below.\n"
                       if diag.get("cmd")
                       else "    ↳ This needs a manual step (above); auto-retry isn't available.\n")
            return False

        def run_jobs(jobs, header=None):
            """jobs: list of (name, method, cmd, rem). Runs in a worker thread."""
            win.after(0, lambda: set_running(True))

            def worker():
                if header:
                    append(header)
                for name, method, cmd, rem in jobs:
                    run_one(name, method, cmd, rem)
                append("\nDone.\n")
                if self._install_failures:
                    fixable = [n for n, d in self._install_failures.items()
                               if d.get("rem") and d["rem"].get("cmd")]
                    append(f"{len(self._install_failures)} still missing: "
                           f"{', '.join(sorted(self._install_failures))}.\n")
                    if fixable:
                        append(f"    → '⟳ Retry failed (apply fixes)' can auto-fix: "
                               f"{', '.join(sorted(fixable))}\n")
                win.after(0, lambda: set_running(False))
                self.update_status("Tool installation finished.")

            threading.Thread(target=worker, daemon=True).start()

        def do_install():
            chosen = [(n, m, c) for n, (v, m, c) in self._install_vars.items()
                      if v.get() and c]
            if not chosen:
                append("Nothing selected.\n")
                return
            run_jobs([(n, m, c, None) for n, m, c in chosen])

        def do_retry():
            jobs = [(n, d["method"], d["cmd"], d["rem"])
                    for n, d in self._install_failures.items()
                    if d.get("rem") and d["rem"].get("cmd")]
            if not jobs:
                append("No auto-fixable failures to retry.\n")
                return
            run_jobs(jobs, header="\n########## RETRY WITH DIAGNOSED FIXES ##########\n")

        install_btn.config(command=do_install)
        retry_btn.config(command=do_retry)
        # Reflect any failures carried over from a previous dialog session.
        set_running(False)
        if self._install_failures:
            fixable = [n for n, d in self._install_failures.items()
                       if d.get("rem") and d["rem"].get("cmd")]
            if fixable:
                append(f"Previous session left fixable failures: {', '.join(sorted(fixable))}.\n"
                       "Click '⟳ Retry failed (apply fixes)' to apply the diagnosed fixes.\n")

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
    # Settings: update installed tools
    # ------------------------------------------------------------------ #
    # Each tool is updated the same way it was installed, detected from where
    # its binary actually lives -- never by guessing. Mixing methods (e.g.
    # `go install` over an apt binary) would leave two copies fighting on PATH.
    #   apt     : dpkg owns the file      -> apt-get install --only-upgrade (pkexec)
    #   go      : `go version -m` works   -> go install <pkg>@latest
    #   pipx    : lives in a pipx venv    -> pipx upgrade
    #   venv    : GhostRecon's shared venv-> venv pip install -U
    #   git     : GhostRecon git clone    -> git pull --ff-only
    #   release : trufflehog binary       -> re-download latest release
    UPDATE_TIMEOUT = 20

    def _sh(self, cmd, timeout=None):
        """Run a command quietly; return (returncode, stdout+stderr)."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout or self.UPDATE_TIMEOUT,
                               shell=isinstance(cmd, str))
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)

    def _fetch_json(self, url):
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "GhostRecon-updater",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.UPDATE_TIMEOUT) as r:
            return json.loads(r.read().decode())

    @staticmethod
    def _ver_tuple(v):
        """Loose numeric version key: 'v3.11.1' / '1.10.8-1' -> (3, 11, 1)."""
        v = re.sub(r'^[vV]', '', (v or "").strip()).split("-")[0].split("+")[0]
        return tuple(int(x) for x in re.findall(r'\d+', v)[:4])

    def _newer(self, latest, installed):
        try:
            return self._ver_tuple(latest) > self._ver_tuple(installed)
        except ValueError:
            return False

    @staticmethod
    def _goproxy_escape(module):
        # proxy.golang.org case-encodes uppercase letters as '!' + lowercase.
        return re.sub(r'[A-Z]', lambda m: "!" + m.group(0).lower(), module)

    def _tool_path(self, name):
        return self.pd_httpx_path() if name == "httpx" else shutil.which(name)

    def _detect_install(self, name):
        """Work out how `name` was installed and its installed version.
        Returns a dict: {name, method, path, installed, + method-specific keys}."""
        path = self._tool_path(name)
        info = {"name": name, "method": "unknown", "path": path, "installed": "?"}
        if not path:
            return None
        real = os.path.realpath(path)
        grt = os.path.expanduser(self.GR_TOOLS_DIR)
        pipx_root = os.path.expanduser("~/.local/share/pipx/venvs") + os.sep

        # GhostRecon git-clone tools: ~/.local/bin/<cmd> is a sh wrapper -> clone dir
        try:
            with open(real, "rb") as f:
                head = f.read(400).decode(errors="replace")
        except OSError:
            head = ""
        # The wrapper names the venv python first, then the clone's entry script.
        clones = [c for c in re.findall(re.escape(grt) + r'/([^/"]+)/', head)
                  if c != ".venv"]
        if head.startswith("#!/bin/sh") and clones:
            d = os.path.join(grt, clones[0])
            if os.path.isdir(os.path.join(d, ".git")):
                rc, out = self._sh(["git", "-C", d, "log", "-1", "--format=%h %cs"])
                info.update(method="git", dir=d,
                            installed=out.strip() if rc == 0 else "?")
                return info

        if real.startswith(pipx_root):
            venv = real[len(pipx_root):].split(os.sep)[0]
            rc, out = self._sh(["pipx", "list", "--json"])
            try:
                meta = json.loads(out)["venvs"][venv]["metadata"]["main_package"]
                info.update(method="pipx", venv=venv, pkg=meta["package"],
                            installed=meta["package_version"])
            except (ValueError, KeyError):
                info.update(method="pipx", venv=venv, pkg=venv)
            return info

        if real.startswith(os.path.join(grt, ".venv") + os.sep):
            pkg = self.PIP_PKG.get(name, (name, None))[0]
            rc, out = self._sh([os.path.join(grt, ".venv/bin/pip"), "show", pkg])
            mv = re.search(r'^Version:\s*(\S+)', out, re.M)
            info.update(method="venv", pkg=pkg, installed=mv.group(1) if mv else "?")
            return info

        rc, out = self._sh(["dpkg", "-S", real])
        if rc == 0 and ":" in out:
            pkg = out.split(":")[0].strip().split(",")[0]
            rc, pol = self._sh(["apt-cache", "policy", pkg])
            mi = re.search(r'Installed:\s*(\S+)', pol)
            mc = re.search(r'Candidate:\s*(\S+)', pol)
            info.update(method="apt", pkg=pkg, installed=mi.group(1) if mi else "?",
                        candidate=mc.group(1) if mc else None)
            return info

        if self.has_tool("go"):
            rc, out = self._sh(["go", "version", "-m", real])
            mp = re.search(r'^\s*path\s+(\S+)', out, re.M)
            mm = re.search(r'^\s*mod\s+(\S+)\s+(\S+)', out, re.M)
            if rc == 0 and mp and mm:
                info.update(method="go", gopkg=mp.group(1), module=mm.group(1),
                            installed=mm.group(2), bindir=os.path.dirname(real))
                return info

        if name == "trufflehog":
            rc, out = self._sh([real, "--version"])
            mv = re.search(r'(\d+\.\d+\.\d+)', out)
            info.update(method="release", installed=mv.group(1) if mv else "?")
        return info

    def _latest_version(self, info):
        """Fill info['latest'] and info['update'] (True/False/None=unknown)."""
        m = info["method"]
        try:
            if m == "apt":
                info["latest"] = info.get("candidate") or "?"
                if info["latest"] in ("?", "(none)"):
                    info["update"] = None
                else:
                    rc, _ = self._sh(["dpkg", "--compare-versions", info["installed"],
                                      "lt", info["latest"]])
                    info["update"] = rc == 0
            elif m == "go":
                d = self._fetch_json("https://proxy.golang.org/%s/@latest"
                                     % self._goproxy_escape(info["module"]))
                info["latest"] = d.get("Version", "?")
                info["update"] = (None if info["installed"] in ("(devel)", "?")
                                  else self._newer(info["latest"], info["installed"]))
            elif m in ("pipx", "venv"):
                d = self._fetch_json(f"https://pypi.org/pypi/{info['pkg']}/json")
                info["latest"] = d["info"]["version"]
                info["update"] = self._newer(info["latest"], info["installed"])
            elif m == "git":
                rc, url = self._sh(["git", "-C", info["dir"], "remote", "get-url", "origin"])
                rc2, out = self._sh(["git", "ls-remote", url.strip(), "HEAD"])
                remote = out.split()[0][:7] if rc2 == 0 and out.strip() else "?"
                info["latest"] = remote
                info["update"] = (None if remote == "?"
                                  else not info["installed"].startswith(remote))
            elif m == "release":
                d = self._fetch_json("https://api.github.com/repos/trufflesecurity/"
                                     "trufflehog/releases/latest")
                info["latest"] = d.get("tag_name", "?")
                info["update"] = self._newer(info["latest"], info["installed"])
            else:
                info["latest"], info["update"] = "—", None
        except Exception as e:   # network / API hiccup: report, don't crash
            info["latest"], info["update"] = "check failed", None
            info["error"] = str(e)
        return info

    def _update_command(self, info):
        """Shell command that updates one non-apt tool in place (apt is batched)."""
        m = info["method"]
        if m == "go":
            return (f'GOBIN={shlex.quote(info["bindir"])} '
                    f'go install -v {shlex.quote(info["gopkg"])}@latest')
        if m == "pipx":
            return f'pipx upgrade {shlex.quote(info["venv"])}'
        if m == "venv":
            pip = os.path.join(os.path.expanduser(self.GR_TOOLS_DIR), ".venv/bin/pip")
            return f'{shlex.quote(pip)} install -U {shlex.quote(info["pkg"])}'
        if m == "git":
            return f'git -C {shlex.quote(info["dir"])} pull --ff-only'
        if m == "release":
            return GR_TRUFFLEHOG_INSTALL
        return None

    @staticmethod
    def _apt_lists_age():
        """Days since apt's package lists were last refreshed (None if unknown)."""
        try:
            d = "/var/lib/apt/lists"
            newest = max(os.path.getmtime(os.path.join(d, f)) for f in os.listdir(d)
                         if f.endswith(("Release", "InRelease", "Packages")))
            return (time.time() - newest) / 86400
        except (OSError, ValueError):
            return None

    def open_update_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Update Installed Tools")
        win.geometry("900x640")
        t = THEMES[self.theme_name]
        win.configure(bg=t["bg"])

        ttk.Label(win, text="Update installed tools",
                  font=("Helvetica", 14, "bold")).pack(anchor="w", padx=12, pady=(12, 2))
        ttk.Label(win, wraplength=870, text=(
            "Each tool is updated the same way it was installed (apt, go, pipx, venv, "
            "git or release binary). apt updates ask for your password once.")
                  ).pack(anchor="w", padx=12)
        age = self._apt_lists_age()
        apt_note = ttk.Label(win, foreground=t["tab_fg"], wraplength=870, text=(
            "apt package lists: unknown age" if age is None else
            f"apt package lists last refreshed {age:.0f} day(s) ago"
            + (" — stale; apt's 'Latest' may be behind. Updating refreshes them "
               "first, or use 'Refresh apt lists'." if age > 7 else ".")))
        apt_note.pack(anchor="w", padx=12, pady=(2, 6))

        wrap = ttk.Frame(win)
        wrap.pack(fill="both", expand=True, padx=12)
        cols = ("sel", "tool", "method", "installed", "latest", "status")
        tree = ttk.Treeview(wrap, columns=cols, show="headings", height=12,
                            selectmode="none")
        for col, label, width, anchor in (("sel", "✓", 34, "center"),
                                          ("tool", "Tool", 110, "w"),
                                          ("method", "Method", 70, "center"),
                                          ("installed", "Installed", 190, "w"),
                                          ("latest", "Latest", 190, "w"),
                                          ("status", "Status", 150, "w")):
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor=anchor, stretch=col in ("installed",
                                                                        "latest"))
        tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, command=tree.yview)
        sb.pack(side="right", fill="y")
        tree["yscrollcommand"] = sb.set
        tree.tag_configure("update", foreground="#e67e22")
        tree.tag_configure("muted", foreground="#888888")

        out = tk.Text(win, height=10, wrap=tk.WORD, state="disabled",
                      font=("Courier New", 9), bg=t["text_bg"], fg=t["text_fg"],
                      insertbackground=t["text_fg"], relief=tk.FLAT)
        out.pack(fill="both", expand=False, padx=12, pady=8)

        btnrow = ttk.Frame(win)
        btnrow.pack(fill="x", padx=12, pady=(0, 12))
        check_btn = ttk.Button(btnrow, text="Check for updates")
        check_btn.pack(side="left")
        refresh_btn = ttk.Button(btnrow, text="Refresh apt lists")
        refresh_btn.pack(side="left", padx=6)
        ttk.Button(btnrow, text="Select all updates",
                   command=lambda: set_all(True)).pack(side="left")
        ttk.Button(btnrow, text="Select none",
                   command=lambda: set_all(False)).pack(side="left", padx=6)
        update_btn = ttk.Button(btnrow, text="Update selected")
        update_btn.pack(side="right")
        ttk.Button(btnrow, text="Close", command=win.destroy).pack(side="right", padx=6)

        infos = {}       # tool -> detected info
        checked = {}     # tool -> bool

        def ui(fn):
            win.after(0, lambda: fn() if win.winfo_exists() else None)

        def append(text):
            def _do():
                out.config(state="normal")
                out.insert(tk.END, text)
                out.see(tk.END)
                out.config(state="disabled")
            ui(_do)

        def busy(flag):
            def _do():
                for b in (check_btn, refresh_btn, update_btn):
                    b.config(state=tk.DISABLED if flag else tk.NORMAL)
            ui(_do)

        def render(name):
            i = infos[name]
            upd = i.get("update")
            status = ("checking…" if "latest" not in i else
                      "update available" if upd else
                      "up to date" if upd is False else
                      (i.get("error", "")[:40] or "can't tell") if i["method"] != "unknown"
                      else "unmanaged — update manually")
            mark = "☑" if checked.get(name) else ("☐" if upd else "")
            vals = (mark, name, i["method"], i["installed"], i.get("latest", "…"), status)
            tags = ("update",) if upd else (("muted",) if i["method"] == "unknown" else ())
            if tree.exists(name):
                tree.item(name, values=vals, tags=tags)
            else:
                tree.insert("", tk.END, iid=name, values=vals, tags=tags)

        def on_click(event):
            if tree.identify("region", event.x, event.y) != "cell":
                return
            name = tree.identify_row(event.y)
            if name and infos.get(name, {}).get("update"):
                checked[name] = not checked.get(name)
                render(name)
        tree.bind("<Button-1>", on_click)

        def set_all(value):
            for name, i in infos.items():
                if i.get("update"):
                    checked[name] = value
                    render(name)

        def do_check():
            busy(True)
            ui(lambda: tree.delete(*tree.get_children()))
            infos.clear()
            checked.clear()

            def worker():
                from concurrent.futures import ThreadPoolExecutor
                names = [n for n in self.TOOLS if self._tool_path(n)]
                append(f"Checking {len(names)} installed tools…\n")
                with ThreadPoolExecutor(max_workers=8) as pool:
                    detected = [d for d in pool.map(self._detect_install, names) if d]
                for d in detected:
                    infos[d["name"]] = d
                    ui(lambda n=d["name"]: render(n))
                with ThreadPoolExecutor(max_workers=8) as pool:
                    for d in pool.map(self._latest_version, detected):
                        if d.get("update"):
                            checked[d["name"]] = True
                        ui(lambda n=d["name"]: render(n))
                def sort_rows():   # updates first, then alphabetical
                    order = sorted(infos, key=lambda n: (not infos[n].get("update"), n))
                    for idx, n in enumerate(order):
                        if tree.exists(n):
                            tree.move(n, "", idx)
                ui(sort_rows)
                n_upd = sum(1 for d in detected if d.get("update"))
                n_fail = [d["name"] for d in detected if d.get("error")]
                append(f"{n_upd} update(s) available.\n")
                if n_fail:
                    append(f"Could not check: {', '.join(n_fail)} (network/API).\n")
                busy(False)
                self.update_status(f"Tool update check: {n_upd} update(s) available.")
            threading.Thread(target=worker, daemon=True).start()

        def stream(cmd):
            """Run a shell command, streaming output into the dialog log."""
            try:
                proc = subprocess.Popen(cmd, shell=isinstance(cmd, str),
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1)
            except OSError as e:
                append(f"[!] {e}\n")
                return 1, ""
            buf = []
            for line in proc.stdout:
                line = strip_ansi(line)
                buf.append(line)
                append(line)
            proc.wait()
            return proc.returncode, "".join(buf)

        def can_pkexec():
            return bool(shutil.which("pkexec") and os.environ.get("DISPLAY"))

        def do_refresh_apt():
            if not can_pkexec():
                append("\nNo graphical sudo (pkexec) available. In a terminal run:\n"
                       "    sudo apt-get update\nthen click 'Check for updates'.\n")
                return
            busy(True)

            def worker():
                append("\n=== Refreshing apt package lists (password prompt) ===\n")
                rc, _ = stream(["pkexec", "apt-get", "update"])
                if rc in (126, 127):
                    append("[!] Authentication cancelled or denied.\n")
                busy(False)
                if rc == 0:
                    ui(lambda: apt_note.config(
                        text="apt package lists refreshed just now."))
                    ui(do_check)
            threading.Thread(target=worker, daemon=True).start()

        def do_update():
            chosen = [infos[n] for n, on in checked.items() if on]
            if not chosen:
                append("\nNothing selected — tick tools marked 'update available'.\n")
                return
            busy(True)

            def worker():
                apt_pkgs = sorted({i["pkg"] for i in chosen if i["method"] == "apt"})
                others = [i for i in chosen if i["method"] != "apt"]
                results = {}
                if apt_pkgs:
                    pk = " ".join(shlex.quote(p) for p in apt_pkgs)
                    inner = f"apt-get update && apt-get install -y --only-upgrade {pk}"
                    if can_pkexec():
                        append(f"\n=== apt: upgrading {', '.join(apt_pkgs)} "
                               "(password prompt) ===\n")
                        rc, _ = stream(["pkexec", "sh", "-c", inner])
                        if rc in (126, 127):
                            append("[!] Authentication cancelled or denied.\n")
                    else:
                        rc = 1
                        append("\nNo graphical sudo (pkexec). In a terminal run:\n"
                               f"    sudo sh -c '{inner}'\n")
                    for i in chosen:
                        if i["method"] == "apt":
                            results[i["name"]] = rc == 0
                for i in others:
                    cmd = self._update_command(i)
                    append(f"\n=== {i['name']} ({i['method']}) ===\n$ {cmd}\n")
                    rc, log = stream(cmd)
                    if rc != 0 and i["method"] == "go":
                        # Reuse the installer's diagnosis (e.g. module needs newer Go).
                        diag = self._diagnose_install(i["name"], "go", cmd, log)
                        if diag.get("pre"):
                            append(f"    ↳ {diag['why']}\n")
                            stream(diag["pre"])
                            gb = self._go_bin_dir()
                            os.environ["PATH"] = gb + os.pathsep + os.environ["PATH"]
                            rc, _ = stream(cmd)
                    results[i["name"]] = rc == 0
                append("\n=== Re-checking versions ===\n")
                for name in results:
                    fresh = self._detect_install(name)
                    if fresh:
                        infos[name] = self._latest_version(fresh)
                    checked[name] = False
                    ui(lambda n=name: render(n))
                    append(f"{'[OK]' if results[name] else '[FAILED]'} {name}: "
                           f"now {infos[name]['installed']}\n")
                busy(False)
                self.update_status("Tool updates finished.")
            threading.Thread(target=worker, daemon=True).start()

        check_btn.config(command=do_check)
        refresh_btn.config(command=do_refresh_apt)
        update_btn.config(command=do_update)
        do_check()

    # ------------------------------------------------------------------ #
    # Stage 1: Subdomains
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # One-Stop orchestrator
    # ------------------------------------------------------------------ #
    def _oneshot_apex(self, bare):
        """Best-effort registrable domain from a host. Returns None for an IP."""
        if IP_RE.match(bare):
            return None
        labels = bare.split(".")
        if len(labels) <= 2:
            return bare
        two_level = {"co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "com.au",
                     "net.au", "org.au", "co.jp", "co.nz", "co.za", "com.br",
                     "com.mx", "co.in", "co.kr"}
        if ".".join(labels[-2:]) in two_level:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def _oneshot_dirbust_cfg(self):
        """Build a minimal valid dirbust cfg from the Dir Busting tab's wordlist
        settings. Returns None (skip) if no usable tool+wordlist is available."""
        dirb_wl = self.dirb_wordlist.get().strip()
        ffuf_wl = self.ffuf_wordlist.get().strip()
        use_ffuf = self.has_tool("ffuf") and os.path.isfile(ffuf_wl)
        use_dirb = self.has_tool("dirb") and os.path.isfile(dirb_wl)
        if not (use_ffuf or use_dirb):
            return None
        try:
            threads = max(1, int(self.db_threads.get()))
            rate = max(0, int(self.db_rate.get()))
        except (tk.TclError, ValueError):
            threads, rate = 20, 0
        return {
            "dirb": use_dirb, "ffuf": use_ffuf,
            "dirb_wl": dirb_wl, "ffuf_wl": ffuf_wl,
            "threads": threads, "rate": rate,
            "jitter": self.db_jitter.get(),
            "ua": BROWSER_UA if self.db_browser_ua.get() else None,
            "recursive": self.db_recursive.get(),
            # validated in start_oneshot before the pipeline launches
            "exts": self._parse_extensions(self.db_extensions.get()),
            "ext_bare": self.db_ext_bare.get(),
            "fspec": {"mc": parse_ranges(FFUF_DEFAULT_MC), "fc": [], "fs": [],
                      "fw": [], "fl": [], "fr": None, "ac": False},
        }

    def start_oneshot(self):
        raw = self.os_target.get().strip().lower()
        bare = re.sub(r'^https?://', '', raw).split("/")[0].split(":")[0]
        if not (raw and is_host(bare)):
            messagebox.showwarning("Input", "Enter a valid URL or domain, e.g. "
                                            "https://example.com or example.com")
            return
        if self.os_stage_vars["dirbust"].get():
            try:
                self._parse_extensions(self.db_extensions.get())
            except ValueError as e:
                messagebox.showwarning("Extensions", f"Invalid dir busting extension: {e}\n"
                                       "Use a comma-separated list like .aspx,.html")
                return
        if not any(v.get() for v in self.os_stage_vars.values()):
            messagebox.showwarning("Stages", "Select at least one stage to run.")
            return
        self._launch(self.run_oneshot, self.ro_output, (raw,))

    def run_oneshot(self, raw):
        w = self.ro_output
        bare = re.sub(r'^https?://', '', raw).split("/")[0].split(":")[0]
        target_url = raw if re.match(r'^https?://', raw) else f"https://{bare}"
        apex = self._oneshot_apex(bare)
        try:
            lim = max(1, int(self.os_maxhosts.get()))
        except (tk.TclError, ValueError):
            lim = 10
        self._new_outdir(bare)
        ctx = {"bare": bare, "target_url": target_url, "apex": apex, "lim": lim}

        enabled = [(k, lbl) for k, lbl, _d in self.ONESHOT_STAGES
                   if self.os_stage_vars[k].get()]
        self.append(w, "=" * 70 + "\n")
        self.append(w, f"  ONE-STOP RECON  →  {target_url}\n")
        self.append(w, f"  apex: {apex or '(IP — subdomain enum skipped)'}   "
                       f"cap: {lim}/stage   stages: {len(enabled)}\n")
        self.append(w, f"  results dir: {self.state['outdir']}\n")
        self.append(w, "=" * 70 + "\n")

        # Funnel every stage runner's output into this one log; the real recon
        # tabs are left untouched. Restored in `finally`.
        saved_outputs = dict(self.outputs)
        for k in list(self.outputs):
            self.outputs[k] = w
        done, failed, skipped = [], [], []
        try:
            for idx, (key, label) in enumerate(enabled, 1):
                if self.stop_requested:
                    self.append(w, "\n[!] Stopped by user — aborting remaining stages.\n")
                    break
                self.append(w, f"\n{'─' * 70}\n[{idx}/{len(enabled)}] {label}\n{'─' * 70}\n")
                self.update_status(f"One-Stop [{idx}/{len(enabled)}]: {label}")
                try:
                    status = self._oneshot_dispatch(key, ctx)
                    if status == "skip":
                        skipped.append(label)
                        self.append(w, f"[skip] {label}\n")
                    else:
                        done.append(label)
                except Exception as e:
                    failed.append(label)
                    self.append(w, f"[!] Stage error ({label}): {e}\n")
        finally:
            self.outputs.update(saved_outputs)

        self.append(w, "\n" + "=" * 70 + "\n  ONE-STOP SUMMARY\n" + "=" * 70 + "\n")
        self.append(w, f"  subdomains : {len(self.state.get('subdomains', []))}\n")
        self.append(w, f"  live hosts : {len(self.state.get('live_hosts', []))}\n")
        self.append(w, f"  URLs       : {len(self.state.get('urls', []))}\n")
        self.append(w, f"  ran        : {len(done)}   "
                       f"skipped: {len(skipped)}   errored: {len(failed)}\n")
        if skipped:
            self.append(w, f"  skipped → {', '.join(skipped)}\n")
        if failed:
            self.append(w, f"  errored → {', '.join(failed)}\n")
        self.append(w, f"  results dir: {self.state['outdir']}\n")
        self.update_status(f"One-Stop finished — {len(done)} ran, "
                           f"{len(failed)} errored. Results in {self.state['outdir']}")

    def _oneshot_dispatch(self, key, ctx):
        """Prepare inputs from shared state and invoke the matching stage runner.
        Return 'skip' to mark the stage as skipped (nothing to do)."""
        bare, target_url, apex, lim = (ctx["bare"], ctx["target_url"],
                                       ctx["apex"], ctx["lim"])
        st = self.state
        live_urls = st.get("live_urls") or []
        live_hosts = st.get("live_hosts") or []
        urls = st.get("urls") or []
        subs = st.get("subdomains") or []
        param_urls = [u for u in urls if "?" in u]
        web = live_urls or [target_url]

        if key == "subdomains":
            if not apex:
                return "skip"   # IP target: nothing to enumerate
            self.run_subdomains(apex)
        elif key == "livehosts":
            hosts = sorted(set(subs) | {bare})
            self.run_httpx(hosts)
        elif key == "urls":
            self.run_url_recon(target_url, bare)
        elif key == "ports":
            for h in (live_hosts or [bare])[:lim]:
                if self.stop_requested:
                    break
                self.run_port_scan(h)
        elif key == "nuclei":
            self.run_nuclei((live_urls or live_hosts or [target_url])[:max(lim, 50)])
        elif key == "js":
            js_urls = [u for u in urls if re.search(r'\.js(\?|$)', u, re.I)]
            items = js_urls[:max(lim, 50)] if js_urls else (live_hosts or [target_url])[:lim]
            self.run_js(items)
        elif key == "takeover":
            self.run_takeover(subs or live_hosts or [bare])
        elif key == "cors":
            self.run_cors(web[:lim])
        elif key == "crlf":
            self.run_crlf((param_urls or web)[:lim])
        elif key == "openredirect":
            self.run_openredirect((param_urls or web)[:lim])
        elif key == "exposure":
            self.run_exposure((live_urls or live_hosts or [target_url])[:lim])
        elif key == "dirbust":
            cfg = self._oneshot_dirbust_cfg()
            if cfg is None:
                self.append(self.ro_output,
                            "[skip] no dirb/ffuf + wordlist configured "
                            "(set one in the Dir Busting tab).\n")
                return "skip"
            self.run_dirbust((live_urls or [target_url])[:lim], cfg)
        elif key == "params":
            self.run_params((param_urls or live_urls)[:lim] or [target_url])
        elif key == "bypass":
            self.run_bypass(web[:lim])
        elif key == "screenshots":
            self.run_screenshots((live_urls or [target_url])[:max(lim, 50)])
        elif key == "nikto":
            self.run_nikto(web[:min(lim, 3)])   # nikto is slow; cap hard
        elif key == "ssrf":
            self.run_ssrf((param_urls or web)[:lim])
        return "ran"

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

        if not self._amass_var().get():
            pass   # amass is opt-in; skipped silently by default
        elif self.has_tool("amass"):
            self.update_status("Running amass (passive, can take a few minutes) ...")
            out = os.path.join(outdir, "amass.txt")
            # amass v5 quirks (verified on v5.1.1):
            #  * `enum` does NOT print discovered names — it only fills amass's
            #    graph DB (~/.config/amass). Names are read back with `amass subs`.
            #  * Do NOT pass -dir: the client hands work to a shared background
            #    engine, and with a custom -dir the session ends in ~10s with
            #    only the apex. Use the default DB.
            #  * enum's stdout is a \r progress bar (one "line" per tick), so it
            #    is swallowed rather than streamed into the log.
            self.append(w, f"$ amass enum -passive -d {domain} -timeout 10  "
                           "(progress hidden)\n")
            self.run_stream(["amass", "enum", "-passive", "-d", domain, "-timeout", "10"],
                            w, merge_stderr=False, echo=False, on_line=lambda _l: None)
            if self.stop_requested:
                return
            lines = self.run_stream(["amass", "subs", "-names", "-d", domain],
                                    w, merge_stderr=False, echo=False,
                                    on_line=None)
            names = {ln.strip().lower() for ln in lines
                     if ln.strip() and (ln.strip().lower() == domain
                                        or ln.strip().lower().endswith("." + domain))}
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
        hosts = [h for h in hosts
                 if is_host(re.sub(r'^https?://', '', h).split("/")[0].split(":")[0])]
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
        bare = re.sub(r'^https?://', '', target).split("/")[0].split(":")[0]
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
                if not os.path.exists(out) or os.path.getsize(out) == 0:
                    self.append(w, f"\n[*] 0 matches for '{pattern}' in this URL set (file saved, but empty).\n")
                else:
                    self.append(w, f"\n[+] Saved to {out}\n")
        self.update_status(f"URL recon done. Results in {outdir}")

    # ------------------------------------------------------------------ #
    # Stage 4: Ports (naabu / nmap)
    # ------------------------------------------------------------------ #
    def start_port_scan(self):
        host = self.port_entry.get().strip().lower()
        # a port scanner wants the bare host; strip any scheme/path/port
        host = re.sub(r'^https?://', '', host).split("/")[0].split(":")[0]
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
        targets = [t for t in targets
                   if is_host(re.sub(r'^https?://', '', t).split("/")[0].split(":")[0])]
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

        try:
            cfg["exts"] = self._parse_extensions(self.db_extensions.get())
        except ValueError as e:
            messagebox.showwarning("Extensions", f"Invalid extension: {e}\n"
                                   "Use a comma-separated list like .aspx,.html")
            return
        cfg["ext_bare"] = self.db_ext_bare.get()

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
        exts = cfg.get("exts") or []
        wls = {t: cfg[f"{t}_wl"] for t in tools}
        if exts:
            built = {}   # source wordlist -> expanded copy (shared if dirb == ffuf)
            for t in tools:
                src = wls[t]
                if src not in built:
                    dst = os.path.join(outdir, f"wordlist_{t}_ext.txt")
                    n = self._expand_wordlist(src, exts, cfg["ext_bare"], dst)
                    built[src] = dst
                    self.append(w, f"[*] Extensions {','.join(exts)}"
                                   f"{' + bare words' if cfg['ext_bare'] else ''}: "
                                   f"{os.path.basename(src)} -> {n} entries ({dst})\n")
                wls[t] = built[src]
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
                cmd = ["dirb", base + "/", wls["dirb"], "-S", "-v", "-o", out]
                if not cfg["recursive"]:
                    cmd.append("-r")
                if rate:   # dirb is single-threaded, so a fixed delay == a rate cap
                    cmd += ["-z", str(max(1, 1000 // rate))]
                if cfg["ua"]:
                    cmd += ["-a", cfg["ua"]]
                self._feed_begin("dirb", base, self._count_words(wls["dirb"]))
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
                calib = self._ffuf_calibrate(base, common, w, exts) if fspec["ac"] else {}
                if self.stop_requested:
                    continue
                cmd = ["ffuf", "-u", base + "/FUZZ", "-w", wls["ffuf"], "-ic"] + common
                if cfg["recursive"]:
                    cmd += ["-recursion", "-recursion-depth", "2"]
                hits = []
                self._feed_begin("ffuf", base, self._count_words(wls["ffuf"]))
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
    def _expand_wordlist(src, exts, bare, dst):
        """Write `src` to `dst` with each extension appended to every word
        (word -> word.aspx, word.html; plus the bare word if `bare`). Comment
        and blank lines are dropped, entries de-duplicated. Words ending in '/'
        are directories, so they're kept bare and never get an extension.
        Returns the number of entries written."""
        seen, n = set(), 0
        with open(src, encoding="utf-8", errors="surrogateescape") as fin, \
                open(dst, "w", encoding="utf-8", errors="surrogateescape") as fout:
            for line in fin:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                if word.endswith("/"):
                    cands = [word] if bare else []
                else:
                    cands = ([word] if bare else []) + [word + e for e in exts]
                for c in cands:
                    if c not in seen:
                        seen.add(c)
                        fout.write(c + "\n")
                        n += 1
        return n

    @staticmethod
    def _ffuf_is_hit(r, fspec, calib):
        code, size = r.get("status", 0), r.get("length", 0)
        words, lines = r.get("words", 0), r.get("lines", 0)
        if fspec["mc"] != "all" and not in_ranges(code, fspec["mc"]):
            return False
        if (in_ranges(code, fspec["fc"]) or in_ranges(size, fspec["fs"])
                or in_ranges(words, fspec["fw"]) or in_ranges(lines, fspec["fl"])):
            return False
        rule = calib.get(code)   # auto-calibration: (field, value(s)) per status
        if rule:
            vals = rule[1]
            v = r.get(rule[0])
            if (v in vals) if isinstance(vals, (set, frozenset)) else v == vals:
                return False
        return True

    def _ffuf_calibrate(self, base, common, w, exts=()):
        """Our own -ac: request a few paths that can't exist and learn what the
        server's "not found" looks like per status code (size, else words,
        else lines). ffuf's built-in -ac can't be used because it would also
        hide those responses from the live feed.

        With extensions, each one is probed too: IIS/ASP.NET typically serves
        a different not-found page for /x.aspx than for /x, so each extension
        gets its own signature (a code's rule may then hold several values)."""
        rnd = lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
        probes = [rnd(8), rnd(16), rnd(32), "admin" + rnd(8), ".htaccess" + rnd(8), rnd(10) + "/"]
        for e in exts:
            probes += [rnd(10) + e, rnd(18) + e]
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
        def kind(r):   # which probe class a response belongs to ("" = bare word)
            path = urlsplit(r.get("url", "")).path
            return next((e for e in sorted(exts, key=len, reverse=True)
                         if path.endswith(e)), "")

        by_code = {}
        for r in recs:
            by_code.setdefault(r.get("status"), {}).setdefault(kind(r), []).append(r)
        calib = {}
        for code, classes in by_code.items():
            for field in ("length", "words", "lines"):
                per_class = [{r.get(field) for r in rs} for rs in classes.values()]
                if all(len(v) == 1 for v in per_class):   # stable within each class
                    vals = set().union(*per_class)
                    calib[code] = (field, vals.pop() if len(vals) == 1 else frozenset(vals))
                    break
        if calib:
            def fmt(v):
                return "/".join(map(str, sorted(v))) if isinstance(v, frozenset) else v
            desc = ", ".join(f"{c} with {f}={fmt(v)}" for c, (f, v) in sorted(calib.items()))
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
        self._build_screenshots_subtab(inner)

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
        dlbtn = ttk.Button(wl, text="Download kite wordlists…",
                           command=self.start_kite_download)
        dlbtn.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self.run_buttons.append(dlbtn)
        ttk.Label(wl, text="routes-small (~0.4 MB) + optional routes-large (~36 MB) "
                          "from Assetnote", foreground="#888"
                  ).grid(row=2, column=2, sticky="w")

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

    KITE_DIR = os.path.expanduser("~/.cache/kiterunner")
    KITE_CDN = "https://wordlists-cdn.assetnote.io/data/kiterunner/"

    @staticmethod
    def best_api_wordlist():
        import glob as _glob
        # routes-small is the sensible default (fast, broad); then any other .kite
        small = os.path.join(GhostReconGUI.KITE_DIR, "routes-small.kite")
        if os.path.isfile(small):
            return small
        kites = _glob.glob(os.path.join(GhostReconGUI.KITE_DIR, "*.kite")) \
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
        self.bypass_thorough = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tab, text="Thorough (full header matrix — many more requests/URL)",
            variable=self.bypass_thorough).grid(row=3, column=1, sticky="w", padx=4)
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
                 if is_host(re.sub(r'^https?://', '', h).split("/")[0].split(":")[0])]
        hosts = self.scope_filter(hosts, self.outputs["takeover"])
        if not hosts:
            messagebox.showwarning("Input", "No valid in-scope hosts.")
            return
        self._launch(self.run_takeover, self.outputs["takeover"], (hosts,))

    def run_takeover(self, hosts):
        w = self.outputs["takeover"]
        # dnsx/subzy want bare hostnames (no scheme/path/port)
        hosts = [re.sub(r'^https?://', '', h).split("/")[0].split(":")[0] for h in hosts]
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
        raw = self.vhost_target.get().strip()
        m = re.match(r'^(https?)://', raw, re.I)
        if m:   # an explicit scheme in the target wins over the checkbox
            self.vhost_https.set(m.group(1).lower() == "https")
        target = re.sub(r'^https?://', '', raw, flags=re.I).split("/")[0]
        domain = self.vhost_domain.get().strip().lstrip(".")
        wl = self.vhost_wordlist.get().strip()
        # target may carry a :port (e.g. an internal app on :8443) -> validate
        # the host part only, keep the full target for the request.
        host_only = target.rsplit(":", 1)[0] if re.search(r':\d+$', target) else target
        if not is_host(host_only):
            messagebox.showwarning("Input", "Enter a valid target host or IP "
                                           "(optionally host:port).")
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
        """Host-header vhost fuzzing with ffuf.

        ffuf's own -ac isn't used: on vhost fuzzing it misfires both ways.
        Catch-all pages that echo the Host header change size with every
        word, and its words/lines fallback then hides real vhosts whose page
        happens to share a word count. Instead GhostRecon probes random
        labels of different lengths first and models the server's default
        response per status code (incl. "size grows with the label", and the
        redirect Location with the label masked out)."""
        w = self.outputs["vhost"]
        if not self.require(w, "ffuf"):
            return
        outdir = self.state["outdir"] or self._new_outdir(domain)
        scheme = "https" if self.vhost_https.get() else "http"
        host, port = (target.rsplit(":", 1) if re.search(r':\d+$', target)
                      else (target, ""))
        port_n = int(port) if port else (443 if scheme == "https" else 80)

        try:
            ip = socket.gethostbyname(host)
        except OSError as e:
            self.append(w, f"[!] Could not resolve {host}: {e}\n")
            self.update_status("Vhost fuzzing: target did not resolve.")
            return
        connect = target
        if scheme == "https" and not IP_RE.match(host):
            # ffuf sends the URL's hostname as TLS SNI for every request (its
            # -sni can't take FUZZ). With SNI=<target> Apache answers 421 to
            # every other Host, so connect by IP: no SNI, Host header decides.
            connect = ip + (f":{port}" if port else "")
            self.append(w, f"[*] HTTPS: connecting to {host} by IP ({ip}) so no SNI is "
                           "sent — otherwise servers like Apache reply 421 to every "
                           "other Host header.\n")
        url = f"{scheme}://{connect}/"

        common = ["-H", f"Host: FUZZ.{domain}", "-noninteractive", "-json", "-mc", "all"]
        if self.gopts["rate"]:
            common += ["-rate", str(self.gopts["rate"])]
        if self._proxy_url():
            common += ["-x", self._proxy_url()]
        for h in self._all_headers():
            if not h.lower().startswith("host:"):
                common += ["-H", h]

        # --- 1) calibrate: what does an unknown vhost look like? ------------ #
        rnd = lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
        recs = []

        def probe(labels):
            tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
            tmp.write("\n".join(labels) + "\n")
            tmp.close()
            try:
                self.run_stream(["ffuf", "-u", url, "-w", tmp.name] + common, w,
                                echo=False, merge_stderr=False,
                                on_line=lambda ln: self._vhost_rec(ln, domain, recs.append))
            finally:
                os.unlink(tmp.name)

        self.append(w, f"[*] Target {url}  Host: FUZZ.{domain}\n"
                       "[*] Calibrating with random vhosts ...\n")
        probe([rnd(n) for n in (6, 9, 13, 18, 24, 31)])
        if self.stop_requested:
            return
        if not recs:
            self._vhost_unreachable(w, url, ip, port_n, scheme, common)
            return
        model = self._vhost_baseline(recs)
        if any(not m["fit"] for m in model.values()):
            # size isn't predictable -> sample more to learn its real range
            probe([rnd(random.randint(5, 30)) for _ in range(24)])
            model = self._vhost_baseline(recs)
        for code, m in sorted(model.items()):
            if m["fit"] and m["fit"][0]:
                how = (f"size = {m['fit'][1]} + {m['fit'][0]}×len(label) "
                       "(default page echoes the Host header)")
            elif m["fit"]:
                how = f"size {m['fit'][1]}"
            else:
                how = f"size varies {m['min']}–{m['max']} (dynamic page; using a range)"
            loc = next(iter(m["loc"])) if len(m["loc"]) == 1 else ""
            self.append(w, f"[*] Baseline [{code}]: {how}"
                           f"{f', redirects to {loc}' if loc else ''}\n")

        # --- 2) fuzz ------------------------------------------------------- #
        total = self._count_words(wl)
        out = os.path.join(outdir, f"vhosts_{sanitize_for_path(domain)}.txt")
        raw = os.path.join(outdir, f"vhosts_{sanitize_for_path(domain)}.json")
        self.update_status(f"Fuzzing vhosts on {target} for *.{domain} ...")
        cmd = ["ffuf", "-u", url, "-w", wl, "-ic", "-o", raw, "-of", "json"] + common
        hits, seen = [], [0]
        step = max(100, total // 20)
        t0 = time.time()

        def on_rec(r):
            seen[0] += 1
            if not self._vhost_is_baseline(r, model):
                hits.append(r)
                loc = f" -> {r['redirectlocation']}" if r.get("redirectlocation") else ""
                self.append(w, f"[+] {r['host']}  [{r['status']}]  {r['length']} B{loc}\n")
            if seen[0] % step == 0:
                el = time.time() - t0
                self.append(w, f"    ... {seen[0]}/{total} tested "
                               f"({seen[0] / el if el else 0:.0f} req/s), "
                               f"{len(hits)} hit(s)\n")
                self.update_status(f"Vhosts: {seen[0]}/{total} tested, {len(hits)} hit(s)")

        self.run_stream(cmd, w, merge_stderr=False,
                        on_line=lambda ln: self._vhost_rec(ln, domain, on_rec))

        missing = total - seen[0]
        if missing > 0 and not self.stop_requested:
            self.append(w, f"[!] {missing} of {total} requests got no response "
                           "(timeouts / connection errors / rate limiting).\n")
        if len(hits) > 25 and len(hits) > 0.2 * max(seen[0], 1):
            self.append(w, f"[!] {len(hits)} of {seen[0]} words differ from the baseline — "
                           "the default response isn't stable (WAF, rate limiting, "
                           "load balancer), so these are likely noise.\n")
        with open(out, "w") as f:
            for r in hits:
                f.write(f"{r['host']}\t{r['status']}\t{r['length']}\t"
                        f"{r.get('redirectlocation', '')}\n")
        if hits:
            self.append(w, f"\n[+] {len(hits)} candidate vhost(s) -> {out}\n")
            self.state["vhosts"] = [r["host"] for r in hits]
        else:
            self.append(w, f"\n[*] No vhosts differed from the baseline "
                           f"({seen[0]} tested).\n")
        self.update_status(f"Vhost fuzzing done: {len(hits)} candidate(s) -> {out}")

    @staticmethod
    def _vhost_rec(line, domain, sink):
        """Parse one ffuf -json line, tag it with its vhost label, pass it on."""
        try:
            r = json.loads(line)
        except ValueError:
            return
        h = (r.get("host") or "").lower()
        suffix = "." + domain.lower()
        r["host"] = h
        r["_label"] = h[:-len(suffix)] if h.endswith(suffix) else h
        sink(r)

    @staticmethod
    def _vhost_loc(r):
        """Redirect Location with the fuzzed label masked, so 'redirect to
        https://<same host>/' compares equal across words."""
        loc = (r.get("redirectlocation") or "").lower()
        # mask the whole host, not the bare label ("s" would also hit "https")
        return loc.replace(r["host"], "§") if r["host"] else loc

    @classmethod
    def _vhost_baseline(cls, recs):
        model = {}
        by = {}
        for r in recs:
            by.setdefault(r.get("status"), []).append(r)
        for code, rs in by.items():
            fit = None
            for n in range(5):   # size = a + n*len(label): host echoed n times
                a = {r.get("length", 0) - n * len(r["_label"]) for r in rs}
                if len(a) == 1:
                    fit = (n, a.pop())
                    break
            lens = [r.get("length", 0) for r in rs]
            model[code] = {"fit": fit, "min": min(lens), "max": max(lens),
                           "words": {r.get("words") for r in rs},
                           "lines": {r.get("lines") for r in rs},
                           "loc": {cls._vhost_loc(r) for r in rs}}
        return model

    @classmethod
    def _vhost_is_baseline(cls, r, model):
        m = model.get(r.get("status"))
        if m is None:
            return False                       # a status the default never gives
        if cls._vhost_loc(r) not in m["loc"]:
            return False                       # redirects somewhere else
        size = r.get("length", 0)
        if m["fit"]:
            n, a = m["fit"]
            return size == a + n * len(r["_label"])
        # Dynamic default page (nonce/CSRF token/timestamp): sizes jitter but
        # the page's shape usually doesn't. Same word+line count -> allow a
        # wide size window; otherwise only a tight one around what was seen.
        spread = m["max"] - m["min"]
        pad = spread + 64 if (r.get("words") in m["words"]
                              and r.get("lines") in m["lines"]) else max(16, spread // 2)
        return m["min"] - pad <= size <= m["max"] + pad

    def _vhost_unreachable(self, w, url, ip, port, scheme, common):
        """Calibration got zero responses: say why instead of 'no vhosts'."""
        try:
            socket.create_connection((ip, port), timeout=6).close()
        except OSError as e:
            other = "off" if scheme == "https" else "on"
            self.append(w, f"[!] Cannot connect to {ip}:{port} ({e}).\n"
                           f"    Check the host/port, or turn 'Use HTTPS' {other}.\n")
            self.update_status("Vhost fuzzing: target unreachable.")
            return
        # Port is open but ffuf got nothing back: surface ffuf's own error.
        try:
            p = subprocess.run(["ffuf", "-u", url, "-w", "-"]
                               + [a for a in common if a != "-json"],
                               input="ghostreconprobe\n",
                               capture_output=True, text=True, timeout=40)
            lines = [strip_ansi(ln).strip() for ln in
                     (p.stderr + p.stdout).replace("\r", "\n").splitlines()]
            errs = [ln for ln in lines if not ln.startswith("::")   # banner/progress
                    and re.search(r'error|fail|invalid|refused|tls|x509|timeout', ln, re.I)]
        except Exception as e:
            errs = [str(e)]
        self.append(w, f"[!] {ip}:{port} is open but ffuf got no HTTP response"
                       f"{' over TLS' if scheme == 'https' else ''}.\n")
        for ln in errs[-5:]:
            self.append(w, f"    {ln}\n")
        if not errs:
            self.append(w, "    Wrong protocol? Try toggling 'Use HTTPS'. If a proxy is "
                           "set in Settings, check that it's running.\n")
        self.update_status("Vhost fuzzing: no response from target.")

    # ---- kite wordlist download ---- #
    def start_kite_download(self):
        big = messagebox.askyesno(
            "Download kite wordlists",
            "Download routes-small.kite (~0.4 MB) now.\n\n"
            "Also download routes-large.kite (~36 MB download, ~190 MB on disk)?")
        self._launch(self.download_kite_wordlists, self.outputs["api"], (big,))

    def download_kite_wordlists(self, include_large):
        import tarfile
        w = self.outputs["api"]
        if not self.require(w, "curl"):
            return
        os.makedirs(self.KITE_DIR, exist_ok=True)
        wanted = ["routes-small.kite.tar.gz"]
        if include_large:
            wanted.append("routes-large.kite.tar.gz")
        for arc in wanted:
            if self.stop_requested:
                break
            dest = os.path.join(self.KITE_DIR, arc)
            kite = arc[:-len(".tar.gz")]
            self.append(w, f"[*] Downloading {arc} ...\n")
            self.update_status(f"Downloading {arc} ...")
            self.run_stream(["curl", "-fL", "--progress-bar", "-o", dest,
                             self.KITE_CDN + arc], w, merge_stderr=True)
            if not os.path.isfile(dest) or os.path.getsize(dest) == 0:
                self.append(w, f"[!] Download of {arc} failed.\n")
                continue
            try:
                with tarfile.open(dest) as tf:
                    member = next((m for m in tf.getmembers()
                                   if m.name.endswith(".kite")), None)
                    if member:
                        member.name = os.path.basename(member.name)  # flatten
                        tf.extract(member, self.KITE_DIR)
                os.remove(dest)   # drop the archive once extracted
            except (tarfile.TarError, OSError) as e:
                self.append(w, f"[!] Could not extract {arc}: {e}\n")
                continue
            kpath = os.path.join(self.KITE_DIR, kite)
            if os.path.isfile(kpath):
                size = os.path.getsize(kpath) // (1024 * 1024)
                self.append(w, f"[+] {kite} ready ({size} MB) -> {kpath}\n")
        small = os.path.join(self.KITE_DIR, "routes-small.kite")
        if os.path.isfile(small):
            self.master.after(0, lambda: self.api_wordlist.set(small))
            self.append(w, f"[*] Wordlist set to {small}\n")
        self.update_status("kite wordlists ready.")

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
        # trailing / dot / slash tricks
        "{p}/", "{p}/.", "{p}//", "{p}/./", "{p}/%2e/", "{p}/%2f/",
        "{p}/.randomstring", "{p}/*", "{p}/?", "{p}/..;/", "{p};/", "{p};",
        # whitespace & null/newline
        "{p}%20", "{p}%09", "{p}%00", "{p}%0a", "{p}%0d", "{p}%2500",
        # query / fragment truncation
        "{p}?", "{p}#", "{p}%23", "{p}?x=1",
        # extension / semicolon tricks (Spring, IIS, ...)
        "{p}.json", "{p}.html", "{p}.css", "{p}.js", "{p};.css", "{p};.json",
        "{p}%2e.json", "{p}/~",
        # traversal + single/double url-encoding
        "{p}..%2f", "{p}%2e%2e%2f", "{p}%2e%2e/", "{p}..%252f", "{p}%252e%252e%252f",
        "{p}/..%00/", "{p}/..;/..;/",
        # leading tricks (prepend to path)
        "/%2e{p}", "/%2f{p}", "//{p}", "/.{p}", "/{p}/..",
    ]
    # IP-spoof headers: every name is tried with every value below.
    BYPASS_IP_HEADERS = [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Originating-IP",
        "X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "X-Host",
        "X-Real-IP", "X-ProxyUser-Ip", "True-Client-IP",
        "Cluster-Client-IP", "X-Forwarded-Server", "Forwarded-For",
        "X-Custom-IP-Authorization",
    ]
    BYPASS_IP_VALUES = [
        "127.0.0.1", "localhost", "0.0.0.0", "127.0.0.1:80", "127.0.0.1:443",
        "0177.0.0.1", "2130706433", "::1",
    ]
    # path-override headers: value is set to the forbidden request path.
    BYPASS_PATH_HEADERS = [
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
        "X-Originating-URL", "X-Forwarded-Path", "Request-Uri", "Base-Url",
    ]
    # method-override headers: value is set to a benign method.
    BYPASS_METHOD_HEADERS = [
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
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
        thorough = self.bypass_thorough.get()
        # Fast mode trims the IP-header matrix and method-override verbs;
        # thorough mode fires the full lists.
        if thorough:
            ip_headers, ip_values = self.BYPASS_IP_HEADERS, self.BYPASS_IP_VALUES
            mo_verbs = ("GET", "POST", "TRACE")
        else:
            ip_headers = ["X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
                          "X-Client-IP", "X-Originating-IP", "X-Host",
                          "X-Custom-IP-Authorization"]
            ip_values = ["127.0.0.1", "localhost", "::1"]
            mo_verbs = ("GET",)
        self.append(w, f"[*] Mode: {'thorough' if thorough else 'fast'}\n")
        results = []
        for url in urls:
            if self.stop_requested:
                break
            base = re.sub(r'^(https?://[^/]+)(/.*)?$', r'\1', url)
            path = url[len(base):] or "/"
            orig_code, orig_size = self._curl_probe(url)
            self.append(w, f"\n=== {url}  (baseline [{orig_code}] {orig_size} B) ===\n")
            wins = []

            def _try(desc, probe_url, **kw):
                if self.stop_requested:
                    return
                code, size = self._curl_probe(probe_url, **kw)
                if code and code not in ("403", "401", orig_code) and code[0] in "23":
                    wins.append((desc, code, size))
                    self.append(w, f"  [BYPASS] {desc}  -> [{code}] {size} B\n")

            # path mutations
            for tmpl in self.BYPASS_PATHS:
                if self.stop_requested:
                    break
                mut = tmpl.format(p=path)
                _try(f"path {mut}", base + mut)
            # case mutation of the last path segment (/Admin, /ADMIN)
            seg = path.rstrip("/").rsplit("/", 1)
            if len(seg) == 2 and seg[1]:
                head, last = seg[0], seg[1]
                for variant in {last.upper(), last.capitalize(), last.swapcase()}:
                    if self.stop_requested:
                        break
                    if variant != last:
                        cm = f"{head}/{variant}"
                        _try(f"case {cm}", base + cm)
            # IP-spoof headers (name x value)
            for name in ip_headers:
                if self.stop_requested:
                    break
                for val in ip_values:
                    if self.stop_requested:
                        break
                    _try(f"header {name}: {val}", url, extra_headers=[f"{name}: {val}"])
            # path-override headers (value = forbidden path)
            for name in self.BYPASS_PATH_HEADERS:
                if self.stop_requested:
                    break
                _try(f"header {name}: {path}", url, extra_headers=[f"{name}: {path}"])
            # method-override headers (keep GET verb, override via header)
            for name in self.BYPASS_METHOD_HEADERS:
                if self.stop_requested:
                    break
                for mv in mo_verbs:
                    if self.stop_requested:
                        break
                    _try(f"header {name}: {mv}", url, extra_headers=[f"{name}: {mv}"])
            # method change
            for method in ("POST", "PUT", "PATCH", "TRACE", "OPTIONS", "HEAD"):
                if self.stop_requested:
                    break
                _try(f"method {method}", url, method=method)
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
        host = re.sub(r'^https?://', '', url).split("/")[0].split(":")[0]
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
                   if is_host(re.sub(r'^https?://', '', t).split("/")[0].split(":")[0])]
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

    # --- Screenshots (gowitness) ------------------------------------------ #
    def _build_screenshots_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Screenshots")
        self.shots_input = self._mini_targets(
            tab, "URLs / hosts to screenshot (bare hosts get http:// and https:// tried):",
            [("Load live hosts",
              lambda: self._fill(self.shots_input, self.state.get("live_urls")
                                 or self.state["live_hosts"])),
             ("Load subdomains",
              lambda: self._fill(self.shots_input, self.state.get("subdomains")))])
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        self.shots_threads = tk.IntVar(value=4)
        self.shots_timeout = tk.IntVar(value=20)
        self.shots_delay = tk.IntVar(value=3)
        for label, var, lo, hi in (("Threads:", self.shots_threads, 1, 32),
                                   ("Timeout (s):", self.shots_timeout, 5, 120),
                                   ("Delay (s):", self.shots_delay, 0, 15)):
            ttk.Label(opt, text=label).pack(side="left", padx=(0, 2))
            ttk.Spinbox(opt, from_=lo, to=hi, width=4, textvariable=var
                        ).pack(side="left", padx=(0, 10))
        self.shots_fullpage = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Full page", variable=self.shots_fullpage
                        ).pack(side="left", padx=(0, 10))
        ttk.Label(opt, text="Only codes:").pack(side="left")
        self.shots_codes = ttk.Entry(opt, width=14)
        self.shots_codes.pack(side="left", padx=4)
        ttk.Label(opt, text="(e.g. 200,401,403; blank = all)").pack(side="left")

        bar = ttk.Frame(tab)
        bar.grid(row=4, column=0, columnspan=4, sticky="w", padx=4, pady=4)
        btn = ttk.Button(bar, text="Take screenshots", command=self.start_screenshots)
        btn.pack(side="left")
        self.run_buttons.append(btn)
        ttk.Button(bar, text="Open gallery (report server)",
                   command=self.open_shots_report).pack(side="left", padx=6)
        ttk.Button(bar, text="Open screenshots folder",
                   command=self.open_shots_folder).pack(side="left")
        self.outputs["shots"] = self._make_output(tab)

    @staticmethod
    def _chrome_path():
        for name in ("chromium", "chromium-browser", "google-chrome",
                     "google-chrome-stable"):
            p = shutil.which(name)
            if p:
                return p
        return None

    @staticmethod
    def _pin_default_port(target):
        """gowitness applies its port list (80,443) even to full URLs, so
        'https://x' would also be probed as 'https://x:80'. Pin the scheme's
        default port on URLs that lack one; leave bare hosts for gowitness to
        probe over http and https."""
        parts = urlsplit(target)
        if parts.scheme in ("http", "https") and parts.hostname and parts.port is None:
            port = 443 if parts.scheme == "https" else 80
            host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
            netloc = (parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc
                      else "") + f"{host}:{port}"
            return parts._replace(netloc=netloc).geturl()
        return target

    def start_screenshots(self):
        targets = self.scope_filter(self._lines_from(self.shots_input),
                                    self.outputs["shots"])
        if not targets:
            messagebox.showwarning("Input", "No in-scope URLs/hosts to screenshot.")
            return
        self._launch(self.run_screenshots, self.outputs["shots"], (targets,))

    def run_screenshots(self, targets):
        w = self.outputs["shots"]
        if not self.require(w, "gowitness"):
            return
        chrome = self._chrome_path()
        if not chrome:
            self.append(w, "[!] No Chromium/Chrome found — gowitness needs one. "
                           "Install with: sudo apt install chromium\n")
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', targets[0]).split("/")[0])
        shots = os.path.join(outdir, "screenshots")
        os.makedirs(shots, exist_ok=True)
        db = os.path.join(outdir, "gowitness.sqlite3")
        jsonl = os.path.join(outdir, "gowitness.jsonl")
        tfile = os.path.join(outdir, "screenshot_targets.txt")
        with open(tfile, "w") as f:
            f.write("\n".join(self._pin_default_port(t) for t in targets) + "\n")

        cmd = ["gowitness", "--no-log-color", "scan", "file", "-f", tfile,
               "-s", shots, "--write-db", "--write-db-uri", f"sqlite://{db}",
               "--write-jsonl", "--write-jsonl-file", jsonl,
               "-t", str(self.shots_threads.get()), "-T", str(self.shots_timeout.get()),
               "--delay", str(self.shots_delay.get()), "--chrome-path", chrome,
               # gorod, not the default chromedp: with Chromium 150 chromedp's
               # capture call intermittently hangs until timeout (page loads,
               # title is read, but no screenshot); gorod was reliable.
               "--driver", "gorod"]
        if self.shots_fullpage.get():
            cmd += ["--screenshot-fullpage"]
        codes = [c for c in re.split(r'[,\s]+', self.shots_codes.get().strip())
                 if c.isdigit()]
        if codes:
            cmd += ["--http-code-filter", ",".join(codes)]
        # Global request settings: Burp proxy, headers/cookie, browser UA.
        if self._proxy_url():
            cmd += ["--chrome-proxy", self._proxy_url()]
        for h in self._all_headers():
            name, _, value = h.partition(":")
            if name.strip().lower() == "user-agent":
                cmd += ["--chrome-user-agent", value.strip()]
            else:
                cmd += ["--chrome-header", h]

        n = len(targets)
        self.append(w, f"--- gowitness: {n} target(s), {self.shots_threads.get()} "
                       f"thread(s) · {self.proxy_summary()} ---\n")
        self.update_status(f"gowitness: screenshotting {n} target(s) ...")
        self.run_stream(cmd, w)
        self.state["shots_dir"] = outdir
        self._shots_summary(w, jsonl, shots, n)

    def _shots_summary(self, w, jsonl, shots, n_targets):
        """Summarize gowitness' JSONL results: one line per page, sorted by status."""
        rows = []
        try:
            with open(jsonl) as f:
                for ln in f:
                    try:
                        j = json.loads(ln)
                    except ValueError:
                        continue
                    tech = ", ".join(t.get("value", "") for t in
                                     (j.get("technologies") or []) if t.get("value"))
                    rows.append((j.get("response_code") or 0, j.get("url", ""),
                                 (j.get("title") or "").strip(),
                                 bool(j.get("failed")), tech))
        except OSError:
            pass
        n_png = len([f for f in os.listdir(shots)
                     if f.lower().endswith((".jpeg", ".jpg", ".png"))]) \
            if os.path.isdir(shots) else 0
        if not rows:
            self.append(w, f"\n[!] No results recorded ({n_png} screenshot file(s)). "
                           "Check the log above for Chrome/network errors.\n")
            return
        ok = [r for r in rows if not r[3]]
        self.append(w, f"\n=== {len(ok)} page(s) captured from {n_targets} target(s), "
                       f"{n_png} screenshot(s) ===\n"
                       "    (targets with no line below were unreachable or filtered)\n")
        for code, url, title, failed, tech in sorted(rows,
                                                     key=lambda r: (r[3], r[0], r[1])):
            tag = "FAIL" if failed else str(code)
            line = f"  [{tag:>4}] {url}"
            if title:
                line += f"  — {title[:70]}"
            if tech:
                line += f"  [{tech[:60]}]"
            self.append(w, line + "\n")
        self.append(w, f"\n[+] Screenshots: {shots}\n"
                       "    'Open gallery' browses them with titles, tech & headers.\n")
        self.update_status(f"gowitness done: {len(ok)} page(s) captured.")

    def _shots_paths(self):
        d = self.state.get("shots_dir")
        if not d:
            return None
        return d, os.path.join(d, "gowitness.sqlite3"), os.path.join(d, "screenshots")

    def open_shots_folder(self):
        p = self._shots_paths()
        if not p or not os.path.isdir(p[2]):
            messagebox.showinfo("Screenshots", "No screenshots yet — run them first.")
            return
        subprocess.Popen(["xdg-open", p[2]], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

    def open_shots_report(self):
        """Serve the latest run's gallery with `gowitness report server` on a free
        localhost port and open it in the browser. Restarts if already running."""
        p = self._shots_paths()
        if not p or not os.path.exists(p[1]):
            messagebox.showinfo("Screenshots", "No gowitness results yet — run "
                                               "'Take screenshots' first.")
            return
        if not self.has_tool("gowitness"):
            messagebox.showwarning("Screenshots", "gowitness is not installed.")
            return
        self._stop_shots_server()
        import socket
        import webbrowser
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self._shots_server = subprocess.Popen(
            ["gowitness", "--no-log-color", "report", "server", "--host", "127.0.0.1",
             "--port", str(port), "--db-uri", f"sqlite://{p[1]}",
             "--screenshot-path", p[2]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{port}/"
        self.append(self.outputs["shots"], f"[+] Gallery served at {url} "
                                           "(stops when GhostRecon closes)\n")
        # give the server a moment to bind before the browser hits it
        self.master.after(1500, lambda: webbrowser.open(url))

    def _stop_shots_server(self):
        srv = getattr(self, "_shots_server", None)
        if srv and srv.poll() is None:
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
        self._shots_server = None

    # ================================================================== #
    # Active Testing tab (SQLMap · LFImap · Dalfox)
    # ================================================================== #
    # Parameter names that frequently carry SQL injection.
    SQL_PARAM_HINTS = {
        "id", "uid", "pid", "cid", "sid", "eid", "gid", "tid", "itemid", "item",
        "productid", "product", "cat", "category", "catid", "page", "pageid", "p",
        "news", "newsid", "article", "articleid", "sort", "order", "orderby",
        "sortby", "user", "userid", "username", "account", "number", "no", "num",
        "year", "month", "day", "view", "query", "q", "search", "keyword", "key",
        "s", "ref", "lang", "report", "sel", "select", "type", "mode", "action",
        "do", "func", "option", "group", "filter", "from", "to", "start", "limit",
        "offset", "email", "name", "title", "code", "token", "file",
    }

    # Passive/active WAF fingerprints -> (name, [lowercase needles in headers+body]).
    WAF_SIGNATURES = [
        ("Cloudflare", ["cf-ray", "cloudflare", "__cfduid", "cf_clearance",
                        "cf-cache-status", "cf-mitigated"]),
        ("Imperva/Incapsula", ["incap_ses", "visid_incap", "x-iinfo",
                               "incapsula", "x-cdn: incapsula"]),
        ("Akamai", ["akamaighost", "x-akamai", "akamai"]),
        ("Sucuri", ["x-sucuri", "sucuri/cloudproxy", "sucuri"]),
        ("F5 BIG-IP ASM", ["bigipserver", "x-waf-event", "big-ip", "bigip"]),
        ("AWS WAF", ["x-amzn-waf", "awselb", "x-amz-cf-id", "x-amzn-requestid"]),
        ("ModSecurity", ["mod_security", "modsecurity", "libmodsecurity",
                         "this error was generated by mod_security"]),
        ("Barracuda", ["barra_counter_session", "barracuda"]),
        ("FortiWeb", ["fortiwafsid", "fortiweb", "fortigate"]),
        ("DDoS-Guard", ["ddos-guard", "__ddg"]),
        ("StackPath", ["stackpath"]),
        ("Wordfence", ["wordfence", "generated by wordfence"]),
        ("Reblaze", ["rbzid", "reblaze"]),
    ]
    # sqlmap --tamper chains tuned per WAF (all are real tamper scripts).
    WAF_TAMPER = {
        "Cloudflare": "space2comment,charencode,randomcase",
        "Imperva/Incapsula": "space2comment,between,percentage,randomcase",
        "Akamai": "space2randomblank,randomcase,charencode",
        "Sucuri": "space2comment,randomcase,charencode",
        "F5 BIG-IP ASM": "space2hash,randomcase,charencode",
        "AWS WAF": "charencode,space2comment,randomcase",
        "ModSecurity": "between,randomcase,space2comment,modsecurityversioned",
        "Barracuda": "space2hash,randomcase",
        "FortiWeb": "space2comment,randomcase,charencode",
        "DDoS-Guard": "space2comment,randomcase",
        "StackPath": "space2comment,charencode,randomcase",
        "Wordfence": "space2comment,randomcase",
        "Reblaze": "space2comment,charencode,randomcase",
        "Generic/Unknown WAF": "between,space2comment,randomcase",
    }
    # LFImap local-only techniques: code -> (flag, label, default-on). None of
    # these reach out-of-band; the callback vectors live in a separate, gated set.
    LFI_LOCAL_TECHNIQUES = {
        "heur":   ("-heur", "Heuristics", True),
        "filter": ("-f", "PHP filter", True),
        "input":  ("-i", "php://input", True),
        "data":   ("-d", "data://", True),
        "expect": ("-e", "expect://", False),
        "file":   ("-file", "file://", True),
        "trunc":  ("-t", "Truncation", False),
        "cmd":    ("-c", "Cmd polyglot", True),
    }

    def _build_active_tab(self):
        outer = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(outer, text="9. Active Testing")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        inner = ttk.Notebook(outer)
        inner.grid(row=0, column=0, sticky="nsew")
        self._build_sqlmap_subtab(inner)
        self._build_lfimap_subtab(inner)
        self._build_dalfox_subtab(inner)

    def _choose_file(self, var, filetypes, title="Choose a file"):
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if path:
            var.set(path)

    def _active_scope_ok(self, host, w):
        if not host:
            return True
        return bool(self.scope_filter([host], w))

    # ---- shared analysis helpers ---- #
    def _http_capture(self, url, timeout=12):
        """Return (status_code, headers+body lowercased) for a single request,
        honouring the global proxy/headers. ('', '') on error."""
        cmd = ["curl", "-s", "-k", "-i", "--max-time", str(timeout)]
        if self._proxy_url():
            cmd += ["-x", self._proxy_url()]
        for h in self._all_headers():
            cmd += ["-H", h]
        cmd.append(url)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        except (subprocess.SubprocessError, OSError):
            return "", ""
        blob = r.stdout
        m = re.search(r'HTTP/\d(?:\.\d)?\s+(\d{3})', blob)
        return (m.group(1) if m else ""), blob.lower()

    def _match_waf(self, blob):
        if not blob:
            return None
        for name, needles in self.WAF_SIGNATURES:
            if any(n in blob for n in needles):
                return name
        return None

    def _waf_detect(self, url, w):
        """Fingerprint a WAF passively, then actively with a hostile probe."""
        self.append(w, "[*] WAF detection ...\n")
        b_status, b_blob = self._http_capture(url)
        name = self._match_waf(b_blob)
        if name:
            self.append(w, f"    [waf] passive signature -> {name}\n")
            return name
        sep = "&" if "?" in url else "?"
        payload = quote("1' OR '1'='1 UNION SELECT NULL-- -"
                        "<script>alert(1)</script>../../../etc/passwd")
        m_status, m_blob = self._http_capture(url + sep + "gr_probe=" + payload)
        name = self._match_waf(m_blob)
        if name:
            self.append(w, f"    [waf] active signature -> {name}\n")
            return name
        block = {"403", "406", "429", "501", "419", "494", "999", "503", "418"}
        if m_status in block and b_status not in block:
            self.append(w, f"    [waf] hostile probe blocked ({m_status}, baseline "
                           f"{b_status or '?'}) -> Generic/Unknown WAF\n")
            return "Generic/Unknown WAF"
        self.append(w, "    [waf] none detected.\n")
        return None

    def _extract_params(self, url, data=""):
        """List (name, value, where) for query-string and body parameters."""
        out = []
        try:
            q = urlsplit(url if url.startswith("http") else "http://" + url).query
        except Exception:
            q = ""
        out += [(k, v, "GET") for k, v in parse_qsl(q, keep_blank_values=True)]
        dt = (data or "").strip()
        if dt.startswith("{"):
            try:
                for k, v in json.loads(dt).items():
                    out.append((k, str(v), "JSON"))
            except Exception:
                pass
        elif dt:
            out += [(k, v, "POST") for k, v in parse_qsl(dt, keep_blank_values=True)]
        return out

    def _likely_sql_params(self, params):
        """Rank parameters that look injectable (known name, numeric, or id-ish)."""
        res, seen = [], set()
        for name, val, _where in params:
            lname = name.lower()
            hit = (lname in self.SQL_PARAM_HINTS
                   or bool(re.fullmatch(r'-?\d+', (val or "").strip()))
                   or bool(re.search(r'(id|cat|user|order|sort|page|item|'
                                     r'num|key|name|search|query)', lname)))
            if hit and name not in seen:
                seen.add(name)
                res.append(name)
        return res

    def _parse_request_file(self, path):
        """Best-effort parse of a raw HTTP request file (Burp 'Save item')."""
        try:
            raw = open(path, "r", errors="replace").read()
        except OSError:
            return None
        lines = raw.splitlines()
        if not lines:
            return None
        m = re.match(r'([A-Z]+)\s+(\S+)\s+HTTP', lines[0])
        if not m:
            return None
        method, target = m.group(1), m.group(2)
        headers, body_idx = {}, None
        for i in range(1, len(lines)):
            if lines[i] == "":
                body_idx = i + 1
                break
            if ":" in lines[i]:
                hk, _, hv = lines[i].partition(":")
                headers[hk.strip().lower()] = hv.strip()
        host = headers.get("host", "")
        data = "\n".join(lines[body_idx:]).strip() if body_idx else ""
        if target.startswith("http"):
            url = target
        else:
            scheme = "http" if ":80" in host else "https"
            url = f"{scheme}://{host}{target}"
        return {"method": method, "url": url, "data": data,
                "host": host.split(":")[0]}

    # ---- SQLMap ---- #
    def _build_sqlmap_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="SQLMap")
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="Target URL (include params for GET, e.g. "
                            "https://site/view?id=1):").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=4, pady=(4, 0))
        self.sqlmap_url = ttk.Entry(tab)
        self.sqlmap_url.grid(row=1, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        mrow = ttk.Frame(tab)
        mrow.grid(row=2, column=0, columnspan=3, sticky="ew", padx=4)
        ttk.Label(mrow, text="Method:").pack(side="left")
        self.sqlmap_method = ttk.Combobox(mrow, state="readonly", width=6,
                                          values=["GET", "POST"])
        self.sqlmap_method.set("GET")
        self.sqlmap_method.pack(side="left", padx=4)
        ttk.Label(mrow, text="POST data / JSON body:").pack(side="left", padx=(8, 2))
        self.sqlmap_data = ttk.Entry(mrow)
        self.sqlmap_data.pack(side="left", fill="x", expand=True)
        frow = ttk.LabelFrame(tab, text="…or load from file", padding=6)
        frow.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=4)
        frow.columnconfigure(1, weight=1)
        ttk.Label(frow, text="Request file (-r):").grid(row=0, column=0, sticky="w")
        self.sqlmap_reqfile = tk.StringVar()
        ttk.Entry(frow, textvariable=self.sqlmap_reqfile).grid(row=0, column=1,
                                                               sticky="ew", padx=4)
        ttk.Button(frow, text="Browse…", command=lambda: self._choose_file(
            self.sqlmap_reqfile, [("HTTP request", "*.txt *.req *.http"),
                                  ("All files", "*")],
            "Choose a saved HTTP request")).grid(row=0, column=2)
        ttk.Label(frow, text="Bulk URL file (-m):").grid(row=1, column=0, sticky="w")
        self.sqlmap_bulk = tk.StringVar()
        ttk.Entry(frow, textvariable=self.sqlmap_bulk).grid(row=1, column=1,
                                                            sticky="ew", padx=4)
        ttk.Button(frow, text="Browse…", command=lambda: self._choose_file(
            self.sqlmap_bulk, [("URL list", "*.txt"), ("All files", "*")],
            "Choose a URL list")).grid(row=1, column=2)
        o1 = ttk.Frame(tab)
        o1.grid(row=4, column=0, columnspan=3, sticky="w", padx=4, pady=2)
        ttk.Label(o1, text="Level:").pack(side="left")
        self.sqlmap_level = tk.IntVar(value=1)
        ttk.Spinbox(o1, from_=1, to=5, width=4,
                    textvariable=self.sqlmap_level).pack(side="left", padx=4)
        ttk.Label(o1, text="Risk:").pack(side="left")
        self.sqlmap_risk = tk.IntVar(value=1)
        ttk.Spinbox(o1, from_=1, to=3, width=4,
                    textvariable=self.sqlmap_risk).pack(side="left", padx=4)
        self.sqlmap_autoparam = tk.BooleanVar(value=True)
        ttk.Checkbutton(o1, text="Auto-detect & target likely params (-p)",
                        variable=self.sqlmap_autoparam).pack(side="left", padx=6)
        self.sqlmap_waf = tk.BooleanVar(value=True)
        ttk.Checkbutton(o1, text="WAF detect + adapt tamper",
                        variable=self.sqlmap_waf).pack(side="left")
        o2 = ttk.Frame(tab)
        o2.grid(row=5, column=0, columnspan=3, sticky="w", padx=4, pady=2)
        self.sqlmap_dbs = tk.BooleanVar(value=True)
        self.sqlmap_banner = tk.BooleanVar(value=True)
        self.sqlmap_curuser = tk.BooleanVar(value=False)
        self.sqlmap_randagent = tk.BooleanVar(value=True)
        ttk.Checkbutton(o2, text="--dbs", variable=self.sqlmap_dbs).pack(side="left")
        ttk.Checkbutton(o2, text="--banner",
                        variable=self.sqlmap_banner).pack(side="left", padx=6)
        ttk.Checkbutton(o2, text="--current-user",
                        variable=self.sqlmap_curuser).pack(side="left")
        ttk.Checkbutton(o2, text="--random-agent",
                        variable=self.sqlmap_randagent).pack(side="left", padx=6)
        o3 = ttk.Frame(tab)
        o3.grid(row=6, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        ttk.Label(o3, text="Extra args:").pack(side="left")
        self.sqlmap_extra = ttk.Entry(o3)
        self.sqlmap_extra.pack(side="left", fill="x", expand=True, padx=4)
        btn = ttk.Button(tab, text="Run SQLMap", command=self.start_sqlmap)
        btn.grid(row=7, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["sqlmap"] = self._make_output(tab)

    def start_sqlmap(self):
        reqfile = self.sqlmap_reqfile.get().strip()
        bulk = self.sqlmap_bulk.get().strip()
        url = self.sqlmap_url.get().strip()
        if not (reqfile or bulk or url):
            messagebox.showwarning("Input", "Provide a URL, a request file, or a bulk URL file.")
            return
        if reqfile and not os.path.isfile(reqfile):
            messagebox.showwarning("Input", "Request file not found.")
            return
        if bulk and not os.path.isfile(bulk):
            messagebox.showwarning("Input", "Bulk URL file not found.")
            return
        if url and not reqfile and not bulk and not is_url(url):
            messagebox.showwarning("Input", "Enter a valid target URL.")
            return
        self._launch(self.run_sqlmap, self.outputs["sqlmap"], ())

    def run_sqlmap(self):
        w = self.outputs["sqlmap"]
        if not self.require(w, "sqlmap"):
            return
        reqfile = self.sqlmap_reqfile.get().strip()
        bulk = self.sqlmap_bulk.get().strip()
        url = self.sqlmap_url.get().strip()
        data = self.sqlmap_data.get().strip()
        method = self.sqlmap_method.get()
        # Resolve an absolute URL + body for pre-analysis (params, WAF).
        an_url, an_data, host = "", data, ""
        if url:
            an_url = url if url.startswith("http") else "http://" + url
            host = urlsplit(an_url).hostname or ""
        elif reqfile:
            parsed = self._parse_request_file(reqfile)
            if parsed:
                an_url, an_data, host = parsed["url"], parsed["data"], parsed["host"]
        if host and not self._active_scope_ok(host, w):
            self.append(w, f"[scope] {host} is out of scope — aborting.\n")
            return
        outdir = self.state["outdir"] or self._new_outdir(host or "sqlmap")
        cmd = ["sqlmap", "--batch", "--disable-coloring"]
        if reqfile:
            cmd += ["-r", reqfile]
        elif bulk:
            cmd += ["-m", bulk]
        else:
            cmd += ["-u", an_url]
            if data:
                cmd += ["--data", data]
            elif method == "POST":
                self.append(w, "[!] POST selected but no data given; sqlmap will test as GET.\n")
        # Automatic SQL-parameter detection -> focus sqlmap with -p.
        if self.sqlmap_autoparam.get() and not bulk and (an_url or an_data):
            params = self._extract_params(an_url, an_data)
            if params:
                self.append(w, "[*] Parameters seen: "
                            + ", ".join(f"{n} ({wh})" for n, _v, wh in params) + "\n")
                likely = self._likely_sql_params(params)
                if likely:
                    self.append(w, f"[*] Likely-injectable -> testing with -p {','.join(likely)}\n")
                    cmd += ["-p", ",".join(likely)]
                else:
                    self.append(w, "[*] No stand-out params; letting sqlmap test them all.\n")
            else:
                self.append(w, "[*] No URL/body params found; sqlmap will auto-discover.\n")
        # WAF detection -> adapt tamper scripts to the detected WAF.
        waf = None
        if self.sqlmap_waf.get() and an_url.startswith("http"):
            waf = self._waf_detect(an_url, w)
        if waf:
            tamper = self.WAF_TAMPER.get(waf, self.WAF_TAMPER["Generic/Unknown WAF"])
            self.append(w, f"[+] {waf} -> --tamper={tamper} (+ --random-agent --delay 1)\n")
            cmd += ["--tamper", tamper, "--random-agent", "--delay", "1"]
        elif self.sqlmap_randagent.get():
            cmd += ["--random-agent"]
        cmd += ["--level", str(self.sqlmap_level.get()),
                "--risk", str(self.sqlmap_risk.get())]
        if self.sqlmap_dbs.get():
            cmd += ["--dbs"]
        if self.sqlmap_banner.get():
            cmd += ["--banner"]
        if self.sqlmap_curuser.get():
            cmd += ["--current-user"]
        cmd += ["--output-dir", outdir]
        extra = self.sqlmap_extra.get().strip()
        if extra:
            try:
                cmd += shlex.split(extra)
            except ValueError:
                cmd += extra.split()
        cmd = self.augment(cmd, "sqlmap")
        self.update_status("sqlmap running ...")
        self.run_stream(cmd, w)
        self.append(w, f"\n[+] sqlmap finished -> {outdir}\n")
        self.update_status("sqlmap done.")

    # ---- LFImap ---- #
    def _build_lfimap_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="LFImap")
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="Target URL (mark the test point with PWN, e.g. "
                            ".../page.php?file=PWN):").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=4, pady=(4, 0))
        self.lfi_url = ttk.Entry(tab)
        self.lfi_url.grid(row=1, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        mrow = ttk.Frame(tab)
        mrow.grid(row=2, column=0, columnspan=3, sticky="ew", padx=4)
        ttk.Label(mrow, text="Method:").pack(side="left")
        self.lfi_method = ttk.Combobox(mrow, state="readonly", width=7,
                                       values=["GET", "POST"])
        self.lfi_method.set("GET")
        self.lfi_method.pack(side="left", padx=4)
        ttk.Label(mrow, text="POST data:").pack(side="left", padx=(8, 2))
        self.lfi_data = ttk.Entry(mrow)
        self.lfi_data.pack(side="left", fill="x", expand=True)
        frow = ttk.LabelFrame(tab, text="…or load from file", padding=6)
        frow.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=4)
        frow.columnconfigure(1, weight=1)
        ttk.Label(frow, text="Request file (-R):").grid(row=0, column=0, sticky="w")
        self.lfi_reqfile = tk.StringVar()
        ttk.Entry(frow, textvariable=self.lfi_reqfile).grid(row=0, column=1,
                                                            sticky="ew", padx=4)
        ttk.Button(frow, text="Browse…", command=lambda: self._choose_file(
            self.lfi_reqfile, [("HTTP request", "*.txt *.req *.http"),
                               ("All files", "*")],
            "Choose a saved HTTP request")).grid(row=0, column=2)
        ttk.Label(frow, text="URL list (-F):").grid(row=1, column=0, sticky="w")
        self.lfi_urlfile = tk.StringVar()
        ttk.Entry(frow, textvariable=self.lfi_urlfile).grid(row=1, column=1,
                                                            sticky="ew", padx=4)
        ttk.Button(frow, text="Browse…", command=lambda: self._choose_file(
            self.lfi_urlfile, [("URL list", "*.txt"), ("All files", "*")],
            "Choose a URL list")).grid(row=1, column=2)
        tech = ttk.LabelFrame(tab, text="Local inclusion techniques (no callbacks)",
                              padding=6)
        tech.grid(row=4, column=0, columnspan=3, sticky="ew", padx=4, pady=4)
        self.lfi_tech = {}
        for code, (_flag, label, default) in self.LFI_LOCAL_TECHNIQUES.items():
            var = tk.BooleanVar(value=default)
            self.lfi_tech[code] = var
            ttk.Checkbutton(tech, text=label, variable=var).pack(side="left", padx=3)
        cbf = ttk.LabelFrame(tab, text="External callback vectors "
                                       "(require Settings opt-in)", padding=6)
        cbf.grid(row=5, column=0, columnspan=3, sticky="ew", padx=4, pady=4)
        cbf.columnconfigure(2, weight=1)
        self.lfi_rfi = tk.BooleanVar(value=False)
        self.lfi_revshell = tk.BooleanVar(value=False)
        self.lfi_cb_rfi = ttk.Checkbutton(cbf, text="RFI (-r)", variable=self.lfi_rfi)
        self.lfi_cb_rfi.grid(row=0, column=0, sticky="w")
        self.lfi_cb_rev = ttk.Checkbutton(cbf, text="Reverse shell (-x)",
                                          variable=self.lfi_revshell)
        self.lfi_cb_rev.grid(row=0, column=1, sticky="w", padx=8)
        lh = ttk.Frame(cbf)
        lh.grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))
        ttk.Label(lh, text="lhost:").pack(side="left")
        self.lfi_lhost = ttk.Entry(lh, width=16)
        self.lfi_lhost.pack(side="left", padx=3)
        ttk.Label(lh, text="lport:").pack(side="left")
        self.lfi_lport = ttk.Entry(lh, width=7)
        self.lfi_lport.pack(side="left", padx=3)
        self.lfi_cb_status = ttk.Label(cbf, text="", wraplength=640, justify="left")
        self.lfi_cb_status.grid(row=2, column=0, columnspan=3, sticky="w", pady=(3, 0))
        o3 = ttk.Frame(tab)
        o3.grid(row=6, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        ttk.Label(o3, text="Extra args:").pack(side="left")
        self.lfi_extra = ttk.Entry(o3)
        self.lfi_extra.pack(side="left", fill="x", expand=True, padx=4)
        self.lfi_quick = tk.BooleanVar(value=False)
        ttk.Checkbutton(o3, text="Quick (-q)",
                        variable=self.lfi_quick).pack(side="left", padx=4)
        btn = ttk.Button(tab, text="Run LFImap", command=self.start_lfimap)
        btn.grid(row=7, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["lfimap"] = self._make_output(tab)
        self._refresh_lfi_callback_ui()

    def _refresh_lfi_callback_ui(self):
        """Enable the callback widgets only when settings permit it; keep the
        status line and the checkboxes honest otherwise."""
        if not hasattr(self, "lfi_cb_status"):
            return
        allowed = self.gopts.get("lfi_allow_callbacks", False)
        state = "normal" if allowed else "disabled"
        for wdg in (self.lfi_cb_rfi, self.lfi_cb_rev, self.lfi_lhost, self.lfi_lport):
            try:
                wdg.configure(state=state)
            except tk.TclError:
                pass
        if allowed:
            host = self.gopts.get("oob_host", "").strip()
            txt = "Callbacks ENABLED in settings. " + (
                f"Callback host: {host}" if host else
                "Set a Callback host in Settings for RFI payloads.")
        else:
            self.lfi_rfi.set(False)
            self.lfi_revshell.set(False)
            txt = ("Callbacks DISABLED — only local techniques run; no out-of-band "
                   "traffic. Enable in Settings → Global request settings.")
        self.lfi_cb_status.configure(text=txt)

    def _scrub_lfi_callbacks(self, args, w):
        """Strip any out-of-band LFImap flag (and its value) unless callbacks are
        allowed in settings. This is the hard guarantee, independent of the UI."""
        if self.gopts.get("lfi_allow_callbacks", False):
            return args, False
        with_val = {"--lhost", "--lport", "--callback"}
        bare = {"-r", "--rfi", "-x", "--exploit", "-a", "--all"}
        out, removed, skip = [], [], False
        for a in args:
            if skip:
                skip = False
                removed.append(a)
                continue
            key = a.split("=", 1)[0]
            if key in with_val:
                removed.append(a)
                if "=" not in a:
                    skip = True
                continue
            if key in bare:
                removed.append(a)
                continue
            out.append(a)
        if removed:
            self.append(w, f"[safety] LFImap callbacks disabled — removed: "
                           f"{' '.join(removed)}\n")
        return out, bool(removed)

    def start_lfimap(self):
        reqfile = self.lfi_reqfile.get().strip()
        urlfile = self.lfi_urlfile.get().strip()
        url = self.lfi_url.get().strip()
        if not (reqfile or urlfile or url):
            messagebox.showwarning("Input", "Provide a URL, a request file, or a URL list.")
            return
        if reqfile and not os.path.isfile(reqfile):
            messagebox.showwarning("Input", "Request file not found.")
            return
        if urlfile and not os.path.isfile(urlfile):
            messagebox.showwarning("Input", "URL list file not found.")
            return
        if url and not reqfile and not urlfile and not is_url(url.replace("PWN", "1")):
            messagebox.showwarning("Input", "Enter a valid target URL.")
            return
        self._launch(self.run_lfimap, self.outputs["lfimap"], ())

    def run_lfimap(self):
        w = self.outputs["lfimap"]
        if not self.require(w, "lfimap"):
            return
        allowed = self.gopts.get("lfi_allow_callbacks", False)
        reqfile = self.lfi_reqfile.get().strip()
        urlfile = self.lfi_urlfile.get().strip()
        url = self.lfi_url.get().strip()
        host = ""
        cmd = ["lfimap"]
        if reqfile:
            cmd += ["-R", reqfile]
            parsed = self._parse_request_file(reqfile)
            if parsed:
                host = parsed["host"]
        elif urlfile:
            cmd += ["-F", urlfile]
        else:
            tgt = url if url.startswith("http") else "http://" + url
            cmd += ["-U", tgt]
            host = urlsplit(tgt.replace("PWN", "1")).hostname or ""
            data = self.lfi_data.get().strip()
            if data:
                cmd += ["-D", data]
            if self.lfi_method.get() != "GET":
                cmd += ["-M", self.lfi_method.get()]
        if host and not self._active_scope_ok(host, w):
            self.append(w, f"[scope] {host} is out of scope — aborting.\n")
            return
        techs = [flag for code, (flag, _l, _d) in self.LFI_LOCAL_TECHNIQUES.items()
                 if self.lfi_tech[code].get()]
        callback_req = []
        if self.lfi_rfi.get():
            callback_req += ["-r"]
        if self.lfi_revshell.get():
            callback_req += ["-x"]
            if self.lfi_lhost.get().strip():
                callback_req += ["--lhost", self.lfi_lhost.get().strip()]
            if self.lfi_lport.get().strip():
                callback_req += ["--lport", self.lfi_lport.get().strip()]
        cb_host = self.gopts.get("oob_host", "").strip()
        if allowed and self.lfi_rfi.get() and cb_host:
            callback_req += ["--callback", cb_host]
        callback_clean, _ = self._scrub_lfi_callbacks(callback_req, w)
        if not allowed and not techs:
            self.append(w, "[!] No local technique selected; defaulting to "
                           "heuristics + PHP filter.\n")
            techs = ["-heur", "-f"]
        cmd += techs + callback_clean
        if self.gopts["cookie"].strip():
            cmd += ["-C", self.gopts["cookie"].strip()]
        if self._proxy_url():
            cmd += ["-P", self._proxy_url()]
        for h in self._all_headers():
            if h.lower().startswith("cookie:"):
                continue   # already sent via -C
            cmd += ["-H", h]
        if self.lfi_quick.get():
            cmd += ["-q"]
        extra = self.lfi_extra.get().strip()
        if extra:
            try:
                extra_tokens = shlex.split(extra)
            except ValueError:
                extra_tokens = extra.split()
            extra_tokens, _ = self._scrub_lfi_callbacks(extra_tokens, w)
            cmd += extra_tokens
        self.append(w, f"[*] Callbacks: "
                    f"{'ALLOWED' if allowed else 'DISABLED (local techniques only)'}\n")
        self.update_status("lfimap running ...")
        self.run_stream(cmd, w)
        self.append(w, "\n[+] lfimap finished.\n")
        self.update_status("lfimap done.")

    # ---- Dalfox ---- #
    def _build_dalfox_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Dalfox")
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="Target URL (XSS; include params, e.g. "
                            "https://site/search?q=test):").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=4, pady=(4, 0))
        self.dalfox_url = ttk.Entry(tab)
        self.dalfox_url.grid(row=1, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        mrow = ttk.Frame(tab)
        mrow.grid(row=2, column=0, columnspan=3, sticky="ew", padx=4)
        ttk.Label(mrow, text="Method:").pack(side="left")
        self.dalfox_method = ttk.Combobox(mrow, state="readonly", width=7,
                                          values=["GET", "POST"])
        self.dalfox_method.set("GET")
        self.dalfox_method.pack(side="left", padx=4)
        ttk.Label(mrow, text="POST data:").pack(side="left", padx=(8, 2))
        self.dalfox_data = ttk.Entry(mrow)
        self.dalfox_data.pack(side="left", fill="x", expand=True)
        frow = ttk.LabelFrame(tab, text="…or load a URL list file (dalfox file)",
                              padding=6)
        frow.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=4)
        frow.columnconfigure(1, weight=1)
        ttk.Label(frow, text="URL list:").grid(row=0, column=0, sticky="w")
        self.dalfox_file = tk.StringVar()
        ttk.Entry(frow, textvariable=self.dalfox_file).grid(row=0, column=1,
                                                            sticky="ew", padx=4)
        ttk.Button(frow, text="Browse…", command=lambda: self._choose_file(
            self.dalfox_file, [("URL list", "*.txt"), ("All files", "*")],
            "Choose a URL list")).grid(row=0, column=2)
        o1 = ttk.Frame(tab)
        o1.grid(row=4, column=0, columnspan=3, sticky="w", padx=4, pady=2)
        ttk.Label(o1, text="Workers:").pack(side="left")
        self.dalfox_workers = tk.IntVar(value=40)
        ttk.Spinbox(o1, from_=1, to=200, width=5,
                    textvariable=self.dalfox_workers).pack(side="left", padx=4)
        self.dalfox_wafevasion = tk.BooleanVar(value=True)
        ttk.Checkbutton(o1, text="--waf-evasion",
                        variable=self.dalfox_wafevasion).pack(side="left", padx=6)
        self.dalfox_followredirect = tk.BooleanVar(value=False)
        ttk.Checkbutton(o1, text="--follow-redirects",
                        variable=self.dalfox_followredirect).pack(side="left")
        bl = ttk.Frame(tab)
        bl.grid(row=5, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        ttk.Label(bl, text="Blind XSS callback (optional, -b):").pack(side="left")
        self.dalfox_blind = ttk.Entry(bl)
        self.dalfox_blind.pack(side="left", fill="x", expand=True, padx=4)
        o3 = ttk.Frame(tab)
        o3.grid(row=6, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        ttk.Label(o3, text="Extra args:").pack(side="left")
        self.dalfox_extra = ttk.Entry(o3)
        self.dalfox_extra.pack(side="left", fill="x", expand=True, padx=4)
        btn = ttk.Button(tab, text="Run Dalfox", command=self.start_dalfox)
        btn.grid(row=7, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["dalfox"] = self._make_output(tab)

    def start_dalfox(self):
        f = self.dalfox_file.get().strip()
        url = self.dalfox_url.get().strip()
        if not (f or url):
            messagebox.showwarning("Input", "Provide a URL or a URL list file.")
            return
        if f and not os.path.isfile(f):
            messagebox.showwarning("Input", "URL list file not found.")
            return
        if url and not f and not is_url(url):
            messagebox.showwarning("Input", "Enter a valid target URL.")
            return
        self._launch(self.run_dalfox, self.outputs["dalfox"], ())

    def run_dalfox(self):
        w = self.outputs["dalfox"]
        if not self.require(w, "dalfox"):
            return
        f = self.dalfox_file.get().strip()
        url = self.dalfox_url.get().strip()
        host = ""
        cmd = ["dalfox"]
        if f:
            cmd += ["file", f]
        else:
            tgt = url if url.startswith("http") else "http://" + url
            cmd += ["url", tgt]
            host = urlsplit(tgt).hostname or ""
        if host and not self._active_scope_ok(host, w):
            self.append(w, f"[scope] {host} is out of scope — aborting.\n")
            return
        outdir = self.state["outdir"] or self._new_outdir(host or "dalfox")
        out = os.path.join(outdir, "dalfox.txt")
        cmd += ["-w", str(self.dalfox_workers.get()), "--no-color", "-o", out]
        if self.dalfox_method.get() == "POST":
            cmd += ["-X", "POST"]
        data = self.dalfox_data.get().strip()
        if data:
            cmd += ["-d", data]
        if self.dalfox_wafevasion.get():
            cmd += ["--waf-evasion"]
        if self.dalfox_followredirect.get():
            cmd += ["--follow-redirects"]
        blind = self.dalfox_blind.get().strip()
        if blind:
            cmd += ["-b", blind]
        extra = self.dalfox_extra.get().strip()
        if extra:
            try:
                cmd += shlex.split(extra)
            except ValueError:
                cmd += extra.split()
        cmd = self.augment(cmd, "dalfox")
        self.update_status("dalfox running ...")
        self.run_stream(cmd, w)
        self.append(w, f"\n[+] dalfox finished -> {out}\n")
        self.update_status("dalfox done.")

    # ================================================================== #
    # Vuln Scan tab (CORS · CRLF · Open Redirect · SSRF · Secrets · Exposure)
    # ================================================================== #
    # Common redirect-sink parameter names, used when a URL carries no params.
    REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_url", "redir", "return",
                       "returnUrl", "return_url", "dest", "destination", "target",
                       "goto", "continue", "r", "u", "link", "out", "view", "to"]
    # Common SSRF-sink parameter names.
    SSRF_PARAMS = ["url", "uri", "u", "path", "dest", "redirect", "next", "data",
                   "file", "host", "port", "to", "out", "view", "dir", "show",
                   "site", "callback", "target", "domain", "feed", "page", "proxy",
                   "fetch", "resource", "load", "image", "img", "api", "endpoint"]
    # Sensitive paths probed by the Exposure module. value = substrings that must
    # appear in a 200 body to count as a real hit (empty = any non-soft-404 200).
    EXPOSURE_PATHS = {
        ".env": ["="], ".env.local": ["="], ".env.bak": ["="], ".env.prod": ["="],
        ".git/config": ["[core]"], ".git/HEAD": ["ref:"], ".gitignore": [],
        ".svn/entries": [], ".hg/hgrc": [], ".DS_Store": [],
        "config.php.bak": ["<?php"], "config.php~": ["<?php"],
        "wp-config.php.bak": ["<?php"], "configuration.php.bak": ["<?php"],
        "backup.zip": ["PK"], "backup.tar.gz": [], "backup.sql": [], "db.sql": [],
        "dump.sql": [], "database.sql": [], ".htpasswd": [":"], ".htaccess": [],
        "phpinfo.php": ["phpinfo"], "info.php": ["phpinfo"], "server-status": [],
        "web.config": ["<configuration"], ".aws/credentials": ["aws_"],
        "id_rsa": ["PRIVATE KEY"], ".ssh/id_rsa": ["PRIVATE KEY"],
        ".npmrc": [], ".dockerenv": [], "docker-compose.yml": ["services:"],
        ".vscode/sftp.json": ["host"], "sftp-config.json": ["host"],
        ".gitlab-ci.yml": [], ".travis.yml": [], ".bash_history": [],
        "composer.lock": [], "package-lock.json": [], "yarn.lock": [],
    }

    def _build_vulnscan_tab(self):
        outer = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(outer, text="10. Vuln Scan")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        inner = ttk.Notebook(outer)
        inner.grid(row=0, column=0, sticky="nsew")
        self._build_cors_subtab(inner)
        self._build_crlf_subtab(inner)
        self._build_openredirect_subtab(inner)
        self._build_ssrf_subtab(inner)
        self._build_secrets_subtab(inner)
        self._build_exposure_subtab(inner)

    # ---- shared helpers ---- #
    def _tmp_list(self, lines, suffix=".txt"):
        f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
        f.write("\n".join(lines) + "\n")
        f.close()
        return f.name

    def _rand_token(self, n=10):
        return "gr" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def _set_param(self, url, key, value):
        """Return url with query param `key` set to `value` (added if absent)."""
        parts = urlsplit(url if url.startswith("http") else "http://" + url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if any(k == key for k, _ in params):
            newp = [(k, value if k == key else v) for k, v in params]
        else:
            newp = params + [(key, value)]
        q = urlencode(newp)
        return f"{parts.scheme}://{parts.netloc}{parts.path}" + (f"?{q}" if q else "")

    def _vuln_url_input(self, nb, title, label):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text=title)
        box = self._mini_targets(
            tab, label,
            [("Load URLs (stage 3)", lambda: self._fill(box, self.state["urls"])),
             ("Load live URLs",
              lambda: self._fill(box, self.state.get("live_urls", [])))])
        return tab, box

    # ---- CORS (corsy) ---- #
    def _build_cors_subtab(self, nb):
        tab, self.cors_input = self._vuln_url_input(
            nb, "CORS", "URLs to test for CORS misconfiguration (corsy):")
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Threads:").pack(side="left")
        self.cors_threads = tk.IntVar(value=5)
        ttk.Spinbox(opt, from_=1, to=50, width=5,
                    textvariable=self.cors_threads).pack(side="left", padx=4)
        btn = ttk.Button(tab, text="Scan CORS", command=self.start_cors)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["cors"] = self._make_output(tab)

    def start_cors(self):
        urls = [u for u in self._lines_from(self.cors_input) if is_url(u)]
        urls = self.scope_filter(urls, self.outputs["cors"])
        if not urls:
            messagebox.showwarning("Input", "No valid in-scope URLs.")
            return
        self._launch(self.run_cors, self.outputs["cors"], (urls,))

    def run_cors(self, urls):
        w = self.outputs["cors"]
        if not self.require(w, "corsy"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', urls[0]).split("/")[0])
        infile = self._tmp_list(urls)
        out = os.path.join(outdir, "corsy_cors.txt")
        # corsy reads its input file (-i) only when stdin is a TTY; under a
        # subprocess it reads URLs from stdin, so feed them that way.
        cmd = f"corsy -t {int(self.cors_threads.get())} < {shlex.quote(infile)}"
        self.update_status(f"corsy: {len(urls)} URL(s) ...")
        self.run_stream(cmd, w, shell=True, outfile=out)
        self.append(w, f"\n[+] CORS scan done -> {out}\n")
        self.update_status("CORS scan done.")
        try:
            os.unlink(infile)
        except OSError:
            pass

    # ---- CRLF (crlfuzz) ---- #
    def _build_crlf_subtab(self, nb):
        tab, self.crlf_input = self._vuln_url_input(
            nb, "CRLF", "URLs to test for CRLF injection (crlfuzz):")
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Concurrency:").pack(side="left")
        self.crlf_conc = tk.IntVar(value=20)
        ttk.Spinbox(opt, from_=1, to=100, width=5,
                    textvariable=self.crlf_conc).pack(side="left", padx=4)
        ttk.Label(opt, text="Method:").pack(side="left")
        self.crlf_method = ttk.Combobox(opt, state="readonly", width=7,
                                        values=["GET", "POST"])
        self.crlf_method.set("GET")
        self.crlf_method.pack(side="left", padx=4)
        btn = ttk.Button(tab, text="Scan CRLF", command=self.start_crlf)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["crlf"] = self._make_output(tab)

    def start_crlf(self):
        urls = [u for u in self._lines_from(self.crlf_input) if is_url(u)]
        urls = self.scope_filter(urls, self.outputs["crlf"])
        if not urls:
            messagebox.showwarning("Input", "No valid in-scope URLs.")
            return
        self._launch(self.run_crlf, self.outputs["crlf"], (urls,))

    def run_crlf(self, urls):
        w = self.outputs["crlf"]
        if not self.require(w, "crlfuzz"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', urls[0]).split("/")[0])
        infile = self._tmp_list(urls)
        out = os.path.join(outdir, "crlfuzz.txt")
        cmd = ["crlfuzz", "-l", infile, "-c", str(self.crlf_conc.get()), "-o", out]
        if self.crlf_method.get() == "POST":
            cmd += ["-X", "POST"]
        cmd = self.augment(cmd, "crlfuzz")
        self.update_status(f"crlfuzz: {len(urls)} URL(s) ...")
        self.run_stream(cmd, w)
        self.append(w, f"\n[+] CRLF scan done -> {out}\n")
        self.update_status("CRLF scan done.")
        try:
            os.unlink(infile)
        except OSError:
            pass

    # ---- Open Redirect (openredirex) ---- #
    def _build_openredirect_subtab(self, nb):
        tab, self.oredir_input = self._vuln_url_input(
            nb, "Open Redirect",
            "URLs to test for open redirect (openredirex). "
            "Params are auto-fuzzed; or put FUZZ yourself:")
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Concurrency:").pack(side="left")
        self.oredir_conc = tk.IntVar(value=30)
        ttk.Spinbox(opt, from_=1, to=200, width=5,
                    textvariable=self.oredir_conc).pack(side="left", padx=4)
        btn = ttk.Button(tab, text="Scan Open Redirect",
                         command=self.start_openredirect)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["openredirect"] = self._make_output(tab)

    def _fuzzify_urls(self, urls):
        """Produce FUZZ-marked URLs: one per existing param, else per common
        redirect param. openredirex swaps FUZZ for each payload."""
        out = []
        for u in urls:
            if "FUZZ" in u:
                out.append(u)
                continue
            parts = urlsplit(u if u.startswith("http") else "http://" + u)
            params = parse_qsl(parts.query, keep_blank_values=True)
            base = f"{parts.scheme}://{parts.netloc}{parts.path}"
            if params:
                for i in range(len(params)):
                    q = urlencode([(k, "FUZZ" if j == i else v)
                                   for j, (k, v) in enumerate(params)], safe="")
                    out.append(f"{base}?{q}")
            else:
                for p in self.REDIRECT_PARAMS[:6]:
                    out.append(f"{base}?{p}=FUZZ")
        return sorted(set(out))

    def start_openredirect(self):
        urls = [u for u in self._lines_from(self.oredir_input) if is_url(u)]
        urls = self.scope_filter(urls, self.outputs["openredirect"])
        if not urls:
            messagebox.showwarning("Input", "No valid in-scope URLs.")
            return
        self._launch(self.run_openredirect, self.outputs["openredirect"], (urls,))

    def run_openredirect(self, urls):
        w = self.outputs["openredirect"]
        if not self.require(w, "openredirex"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', urls[0]).split("/")[0])
        fuzzed = self._fuzzify_urls(urls)
        infile = self._tmp_list(fuzzed)
        out = os.path.join(outdir, "openredirect.txt")
        # openredirex reads target URLs from stdin and swaps the FUZZ keyword.
        cmd = (f"openredirex -k FUZZ -c {int(self.oredir_conc.get())} "
               f"< {shlex.quote(infile)}")
        self.append(w, f"[*] {len(fuzzed)} fuzz-URL(s) from {len(urls)} input(s)\n")
        self.update_status("openredirex running ...")
        self.run_stream(cmd, w, shell=True, outfile=out)
        self.append(w, f"\n[+] Open redirect scan done -> {out}\n")
        self.update_status("Open redirect scan done.")
        try:
            os.unlink(infile)
        except OSError:
            pass

    # ---- SSRF (custom callback-injection module) ---- #
    def _build_ssrf_subtab(self, nb):
        tab, self.ssrf_input = self._vuln_url_input(
            nb, "SSRF", "URLs to test for SSRF (params injected with a callback):")
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text="Callback:").pack(side="left")
        self.ssrf_mode = ttk.Combobox(opt, state="readonly", width=22,
                                      values=["Built-in listener",
                                              "OAST host (from settings)"])
        self.ssrf_mode.set("Built-in listener")
        self.ssrf_mode.pack(side="left", padx=4)
        ttk.Label(opt, text="Listener host:").pack(side="left")
        self.ssrf_host = ttk.Entry(opt, width=14)
        self.ssrf_host.insert(0, "127.0.0.1")
        self.ssrf_host.pack(side="left", padx=4)
        ttk.Label(opt, text="port:").pack(side="left")
        self.ssrf_port = tk.IntVar(value=8749)
        ttk.Spinbox(opt, from_=1024, to=65535, width=7,
                    textvariable=self.ssrf_port).pack(side="left", padx=4)
        opt2 = ttk.Frame(tab)
        opt2.grid(row=4, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        self.ssrf_metadata = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt2, text="Also test cloud metadata in-band "
                                   "(169.254.169.254)", variable=self.ssrf_metadata
                        ).pack(side="left")
        ttk.Label(opt2, text="   Listener host must be reachable from the target "
                            "(set your IP for external targets).",
                  foreground="#888").pack(side="left")
        btn = ttk.Button(tab, text="Scan SSRF", command=self.start_ssrf)
        btn.grid(row=5, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["ssrf"] = self._make_output(tab)

    def start_ssrf(self):
        urls = [u for u in self._lines_from(self.ssrf_input) if is_url(u)]
        urls = self.scope_filter(urls, self.outputs["ssrf"])
        if not urls:
            messagebox.showwarning("Input", "No valid in-scope URLs.")
            return
        self._launch(self.run_ssrf, self.outputs["ssrf"], (urls,))

    def _start_ssrf_listener(self, port, w):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hits = set()

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _hit(self):
                tok = self.path.strip("/").split("/")[0].split("?")[0]
                if tok:
                    hits.add(tok)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
            do_GET = _hit
            do_POST = _hit
            do_HEAD = _hit

        try:
            srv = ThreadingHTTPServer(("0.0.0.0", port), H)
        except OSError as e:
            self.append(w, f"[!] Could not bind callback listener on :{port}: {e}\n")
            return None, hits
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.append(w, f"[*] Callback listener bound on 0.0.0.0:{port}\n")
        return srv, hits

    def run_ssrf(self, urls):
        w = self.outputs["ssrf"]
        if not self.require(w, "curl"):
            return
        mode = self.ssrf_mode.get()
        srv, hits = None, set()
        if mode.startswith("Built-in"):
            srv, hits = self._start_ssrf_listener(self.ssrf_port.get(), w)
            if srv is None:
                return
            cb_base = f"http://{self.ssrf_host.get().strip() or '127.0.0.1'}:{self.ssrf_port.get()}"
            oast = False
        else:
            host = self.gopts.get("oob_host", "").strip()
            if not host:
                self.append(w, "[!] No OAST callback host set (Settings → Global "
                               "request settings → Callback host).\n")
                return
            cb_base = host
            oast = True
        token_map = {}      # token -> (url, param)
        probes = 0
        for u in urls:
            if self.stop_requested:
                break
            params = self._extract_params(u)
            names = [k for k, _v, _wh in params] or self.SSRF_PARAMS
            for k in names:
                if self.stop_requested:
                    break
                tok = self._rand_token()
                payload = (f"http://{tok}.{cb_base}" if oast
                           else f"{cb_base}/{tok}")
                token_map[tok] = (u, k)
                test = self._set_param(u, k, payload)
                self._curl_probe(test)   # fire-and-forget blind probe
                probes += 1
                # in-band cloud-metadata check
                if self.ssrf_metadata.get():
                    meta = self._set_param(
                        u, k, "http://169.254.169.254/latest/meta-data/")
                    _status, blob = self._http_capture(meta, timeout=6)
                    if any(s in blob for s in ("ami-id", "instance-id",
                                               "iam/security-credentials",
                                               "computemetadata", "meta-data/")):
                        self.append(w, f"  [SSRF/metadata] {u} param '{k}' "
                                       f"returned cloud metadata!\n")
        self.append(w, f"[*] Sent {probes} injected probe(s); waiting for callbacks ...\n")
        for _ in range(12):      # ~6s grace, interruptible
            if self.stop_requested or (srv and hits):
                pass
            time.sleep(0.5)
        confirmed = []
        for tok in sorted(hits):
            u, k = token_map.get(tok, ("?", "?"))
            confirmed.append((u, k))
            self.append(w, f"  [SSRF CONFIRMED] {u}  param '{k}'  (callback {tok})\n")
        if srv:
            srv.shutdown()
        if not confirmed:
            self.append(w, "[*] No blind callbacks received.\n")
            if oast:
                self.append(w, "    (OAST mode: also check your interactsh/"
                               "collaborator client for the tokens above.)\n")
        self.append(w, f"\n[+] SSRF scan done — {len(confirmed)} confirmed, "
                       f"{probes} probe(s).\n")
        self.update_status(f"SSRF done: {len(confirmed)} confirmed.")

    # ---- Secrets (gitleaks + trufflehog) ---- #
    def _build_secrets_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Secrets")
        tab.columnconfigure(0, weight=1)
        ttk.Label(tab, text="Local path (git repo or directory) to scan:").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=4, pady=(4, 0))
        prow = ttk.Frame(tab)
        prow.grid(row=1, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        prow.columnconfigure(0, weight=1)
        self.secrets_path = tk.StringVar()
        ttk.Entry(prow, textvariable=self.secrets_path).grid(row=0, column=0, sticky="ew")
        ttk.Button(prow, text="Browse dir…", command=lambda: self._choose_dir(
            self.secrets_path)).grid(row=0, column=1, padx=4)
        ttk.Button(prow, text="Browse file…", command=lambda: self._choose_file(
            self.secrets_path, [("All files", "*")],
            "Choose a file to scan")).grid(row=0, column=2)
        ttk.Label(tab, text="…or a git URL to clone & scan:").grid(
            row=2, column=0, columnspan=3, sticky="w", padx=4, pady=(6, 0))
        self.secrets_giturl = ttk.Entry(tab)
        self.secrets_giturl.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
        opt = ttk.Frame(tab)
        opt.grid(row=4, column=0, columnspan=3, sticky="w", padx=4, pady=2)
        self.secrets_gitleaks = tk.BooleanVar(value=True)
        self.secrets_trufflehog = tk.BooleanVar(value=True)
        self.secrets_verified = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="gitleaks",
                        variable=self.secrets_gitleaks).pack(side="left")
        ttk.Checkbutton(opt, text="trufflehog",
                        variable=self.secrets_trufflehog).pack(side="left", padx=6)
        ttk.Checkbutton(opt, text="trufflehog: only verified",
                        variable=self.secrets_verified).pack(side="left")
        btn = ttk.Button(tab, text="Scan for secrets", command=self.start_secrets)
        btn.grid(row=5, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["secrets"] = self._make_output(tab)

    def _choose_dir(self, var):
        path = filedialog.askdirectory(title="Choose a directory")
        if path:
            var.set(path)

    def start_secrets(self):
        path = self.secrets_path.get().strip()
        giturl = self.secrets_giturl.get().strip()
        if not path and not giturl:
            messagebox.showwarning("Input", "Provide a local path or a git URL.")
            return
        if path and not os.path.exists(path):
            messagebox.showwarning("Input", "Path not found.")
            return
        self._launch(self.run_secrets, self.outputs["secrets"], ())

    def run_secrets(self):
        w = self.outputs["secrets"]
        path = self.secrets_path.get().strip()
        giturl = self.secrets_giturl.get().strip()
        cleanup = None
        if giturl and not path:
            if not self.require(w, "git"):
                return
            cleanup = tempfile.mkdtemp(prefix="gr-secrets-")
            path = cleanup
            self.append(w, f"[*] Cloning {giturl} ...\n")
            self.run_stream(["git", "clone", giturl, path], w)
        if not path or not os.path.exists(path):
            self.append(w, "[!] Nothing to scan.\n")
            return
        name = os.path.basename(path.rstrip("/")) or "secrets"
        outdir = self.state["outdir"] or self._new_outdir(name)
        is_git = os.path.isdir(os.path.join(path, ".git"))
        self.append(w, f"[*] Scanning {'git repo' if is_git else 'directory/file'}: {path}\n")
        if self.secrets_gitleaks.get() and self.require(w, "gitleaks"):
            self.append(w, "\n=== gitleaks ===\n")
            out = os.path.join(outdir, "gitleaks.json")
            cmd = ["gitleaks", "detect", "--source", path, "--no-banner", "-v",
                   "--report-path", out]
            if not is_git:
                cmd.append("--no-git")
            self.run_stream(cmd, w)
        if self.secrets_trufflehog.get() and self.require(w, "trufflehog"):
            self.append(w, "\n=== trufflehog ===\n")
            results = "verified" if self.secrets_verified.get() \
                else "verified,unknown,unverified"
            if is_git:
                cmd = ["trufflehog", "git", "file://" + os.path.abspath(path),
                       "--results=" + results, "--no-update"]
            else:
                cmd = ["trufflehog", "filesystem", path,
                       "--results=" + results, "--no-update"]
            self.run_stream(cmd, w)
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)
        self.append(w, f"\n[+] Secret scan done -> {outdir}\n")
        self.update_status("Secret scan done.")

    # ---- Exposure (.env / backups / VCS metadata) ---- #
    def _build_exposure_subtab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Exposure")
        self.exposure_input = self._mini_targets(
            tab, "Base URLs / hosts to check for exposed sensitive files:",
            [("Load live URLs",
              lambda: self._fill(self.exposure_input,
                                 self.state.get("live_urls")
                                 or self.state["live_hosts"]))])
        opt = ttk.Frame(tab)
        opt.grid(row=3, column=0, columnspan=4, sticky="w", padx=4, pady=2)
        ttk.Label(opt, text=f"{len(self.EXPOSURE_PATHS)} paths per host "
                            "(.env, .git, backups, configs). Soft-404 aware.",
                  foreground="#888").pack(side="left")
        btn = ttk.Button(tab, text="Check exposure", command=self.start_exposure)
        btn.grid(row=4, column=0, sticky="w", padx=4, pady=4)
        self.run_buttons.append(btn)
        self.outputs["exposure"] = self._make_output(tab)

    def start_exposure(self):
        targets = [t for t in self._lines_from(self.exposure_input)
                   if is_url(t) or is_host(t)]
        targets = self.scope_filter(targets, self.outputs["exposure"])
        if not targets:
            messagebox.showwarning("Input", "No valid in-scope targets.")
            return
        self._launch(self.run_exposure, self.outputs["exposure"], (targets,))

    def run_exposure(self, targets):
        w = self.outputs["exposure"]
        if not self.require(w, "curl"):
            return
        outdir = self.state["outdir"] or self._new_outdir(
            re.sub(r'^https?://', '', targets[0]).split("/")[0])
        found = []
        for base in targets:
            if self.stop_requested:
                break
            base = base.rstrip("/")
            if not base.startswith("http"):
                base = "http://" + base
            # soft-404 baseline: a random path that should not exist
            b_code, b_size = self._curl_probe(f"{base}/{self._rand_token()}.html")
            soft404 = (b_code == "200")
            self.append(w, f"\n=== {base}  (baseline {b_code}/{b_size}B"
                           f"{', soft-404!' if soft404 else ''}) ===\n")
            for path, sigs in self.EXPOSURE_PATHS.items():
                if self.stop_requested:
                    break
                url = f"{base}/{path}"
                code, size = self._curl_probe(url)
                if code != "200":
                    continue
                if soft404 and size == b_size:
                    continue      # identical to the catch-all 200 page
                if sigs:          # confirm content signature when we have one
                    _st, blob = self._http_capture(url, timeout=8)
                    if not any(s.lower() in blob for s in sigs):
                        continue
                self.append(w, f"  [EXPOSED] {url}  ({size}B)\n")
                found.append(url)
        out = os.path.join(outdir, "exposure.txt")
        with open(out, "w") as f:
            f.write("\n".join(found) + ("\n" if found else ""))
        self.append(w, f"\n[+] Exposure check done — {len(found)} hit(s) -> {out}\n")
        self.update_status(f"Exposure done: {len(found)} hit(s).")

if __name__ == "__main__":
    root = tk.Tk()
    app = GhostReconGUI(root)
    root.mainloop()
