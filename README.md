# 👻 GhostRecon

A GUI reconnaissance toolkit by [@TitoSantana00](https://github.com/TitoSantana609). GhostRecon chains passive and active recon tools into a single tabbed workflow — scope, subdomains, live hosts, URLs, ports, vulnerabilities, directory busting, JavaScript analysis, takeovers, parameters, virtual hosts and web scanners — streaming live output and saving every result to disk.

> ⚠️ **Authorized use only.** Run GhostRecon only against assets you own or are explicitly permitted to test (e.g. a bug-bounty scope or a signed pentest engagement). You are responsible for how you use it.

## The pipeline

```
          ┌─ Scope (load .txt/.csv/.json, tick targets, enforce everywhere)
          ▼
1. Subdomains ──> 2. Live Hosts ──┬──> 4. Ports (naabu / nmap)
   (subfinder,         (httpx:       ├──> 5. Vulnerabilities (nuclei)
    subfaster,          alive +      ├──> 6. Dir Busting (dirb + ffuf, merged results)
    crt.sh / crt.name)  title + tech)├──> 3. URLs (gau + waybackurls + katana) ─> gf ─> uro
                                     │
                                     ├──> 7. Recon+ : JS & secrets · takeover · params · vhosts · screenshots
                                     └──> 8. Web Scan : 403 bypass · wpscan · nikto
```

Each stage can load its input from the previous one (or from the Scope picker), so a full sweep flows from a single domain down to filtered vulnerability candidates. Every tool's traffic can be routed through **Burp** and carries your global headers (see **Global request settings**).

## Features

- **Tabbed interface** — one tab per pipeline stage.
- **Scope management (first tab)** — load a program's scope from a **`.txt`, `.csv` or `.json`** file (including HackerOne-style exports with `identifier` / `eligible_for_submission` columns, and `{in_scope: […], out_of_scope: […]}` JSON). GhostRecon reduces each entry to a scannable host/wildcard, drops app package IDs and non-web assets, and shows them in a **checklist**: tick exactly the targets you want to test (one at a time or in batches — out-of-scope rows are locked), then **Send checked to** any stage. With **Enforce scope** on (default), every active stage silently drops out-of-scope targets and logs it, so you can't wander outside the program.
- **Notes (per-asset notebook)** — every asset from a loaded scope file is added automatically (grouped by program, named after the scope file), and you can add more by hand (**Add asset…**) or pull in in-scope subdomains you've discovered (**Import found subs**). Each asset gets a **status** (untested · in progress · interesting · finding · reported · done · ignore), **tags**, and free-form notes that **autosave** as you type (Ctrl+S forces a save; there's an **Insert timestamp** button). Filter by program, status, or search across hosts/tags/note text, and **Export .md** writes a Markdown report. Stored in SQLite at `~/.config/ghostrecon/notes.db` (chmod 600), so notes persist across sessions; reloading a scope file never overwrites existing notes.
- **Global request settings (Settings menu)** — one place to set an upstream **Burp/HTTP(S)/SOCKS proxy** (so httpx, katana, nuclei, ffuf, naabu, dnsx, wpscan and nikto all show up in Burp's history), **custom headers**, a **cookie**, an optional **bug-bounty identification header** (e.g. `X-Bug-Bounty: <your-handle>`), a **browser User-Agent**, and a **global max requests/sec**. Saved to `~/.config/ghostrecon/settings.json` (chmod 600) and reused on every run.
- **Out-of-band / OAST callback server** — in the same settings dialog, point OAST at your **own interactsh server** (`-iserver`) with its **token** (`-itoken`), as some programs require (e.g. a self-hosted `interact.sh`), and nuclei uses it automatically. A free-form **callback host** field (with a **Copy** button) holds your Collaborator/payload domain for manual out-of-band payloads. A **Disable OAST** toggle (`nuclei -ni`) is there for programs that forbid out-of-band testing.
- **Subdomain enumeration** from `subfinder`, `subfaster`, and `crt.sh` (JSON API), with `crt.name` as a no-install fallback. `amass` is **opt-in** via an "Also run amass" checkbox (Subdomains tab and One-Stop) — it takes several minutes and mostly overlaps subfinder (e.g. 68 names in ~6 min vs subfinder's 137 in 6 s, 2 unique). Note for amass v5: `amass enum` doesn't print names (GhostRecon reads them back with `amass subs -names`), and passing `-dir` makes enumeration end early with only the apex.
- **Live host probing** with `httpx` (status code, page title, tech detection).
- **URL discovery** from `gau`, `waybackurls`, and `katana`, merged and deduped, then filtered through a chosen **`gf` pattern** (xss, ssrf, lfi, sqli, redirect, rce, idor, ssti) and cleaned with `uro`.
- **Port scanning** via `naabu` (fast) or `nmap` (`-sV`).
- **Vulnerability scanning** with `nuclei` and a severity selector.
- **Directory busting** with `dirb` (its standard `common.txt`) and `ffuf` (auto-picks SecLists `raft-medium-directories.txt`, falling back to DirBuster medium, then dirb's list; both overridable). Findings from both tools are merged and de-duplicated into one sortable results table showing status, size and which tool found each path (`dirb`, `ffuf` or `both`), saved to `dirbust_combined.txt`.
  - **File extensions:** for sites where pages are files rather than directories (IIS/ASP.NET, static sites), enter extensions like `.aspx,.asp,.html` and every wordlist word is also tried with each one appended (`login` → `login.aspx`, `login.html`). "Also try bare words" (on by default) keeps the plain word too; entries ending in `/` stay bare. The expanded list is saved to the run folder and used by both dirb and ffuf. ffuf auto-calibration also probes each extension, since IIS usually returns a different not-found page for `.aspx` than for a bare path. The same field appears on the **One-Stop** tab (it's one shared setting), so the One-Stop dir-busting stage uses it too.
  - **ffuf filter checkboxes:** auto-calibrate, match codes (`-mc`), filter codes/size/words/lines/regex (`-fc`/`-fs`/`-fw`/`-fl`/`-fr`).
  - **Live request feed:** every word tested scrolls by with its response code and size (color-coded, hits in bold), under a status line showing tested/total, %, req/s, hit count and elapsed time — so you can tell a slow, throttled scan from a stalled one.
  - **Throttling** so you don't overload the server or trip a WAF: presets (Aggressive / Normal / Polite / Stealth) or custom threads + max requests/sec, random delay jitter, and a browser User-Agent. The rate cap applies to dirb too (converted to its `-z` delay).
- **Recon+ tab** (grouped sub-tabs):
  - **JS & Secrets** — crawls hosts with `katana` to collect `.js` files (or takes `.js` URLs directly), fetches each one, and extracts **endpoints/API paths** and **likely secrets** (Google/AWS/Slack/Stripe/GitHub keys, JWTs, authorization headers, generic `apiKey`/`secret`/`token` assignments). Works with a built-in Python extractor, and uses **`jsluice`** too when installed. A **Beautify (unminify)** option reformats minified one-liners into readable, indented code (via the pure-Python `jsbeautifier`, or the `js-beautify` CLI) and saves a readable copy of each file under `js_beautified/` — note this reflows the code, it doesn't rename mangled variables.
  - **Takeover** — maps dangling CNAMEs with `dnsx` and checks for **subdomain takeover** with `nuclei` takeover templates and, when installed, **`subzy`**.
  - **Params** — hidden-parameter discovery with **`arjun`** (GET/POST/JSON/XML, threads, honouring your global headers and rate).
  - **Vhosts** — virtual-host fuzzing with `ffuf` (`Host: FUZZ.<domain>`). Instead of ffuf's `-ac` (which on vhost fuzzing both lets noise through and hides real vhosts), GhostRecon first probes random vhosts and models the server's default response per status code — including catch-all pages that echo the Host header (size grows with the name), redirects to `https://<same host>/`, and dynamic pages whose size jitters. Over HTTPS it connects by IP so no SNI is sent (with SNI set to the target name, Apache answers `421` to every other Host). Hits stream in live with progress, unreachable targets / wrong protocol are reported explicitly, and results are saved to `vhosts_<domain>.txt`.
  - **API Routes** — API endpoint discovery with **`kiterunner`** (`kr scan`). Point it at a local `.kite`/`.txt` wordlist or a named **Assetnote** wordlist (`-A`, auto-downloaded), set preflight depth and connections/host, and it honours the global Burp proxy, headers and rate (converted to `--delay`). A **Download kite wordlists** button fetches Assetnote's `routes-small.kite` (and optionally `routes-large.kite`) into `~/.cache/kiterunner/` and uses it as the default — these method-aware route lists are what make kiterunner better than a generic brute-forcer for APIs.
  - **Screenshots** — visual triage with **`gowitness`** (headless Chromium): load live hosts or subdomains, set threads/timeout/delay, full-page, or only screenshot certain status codes. Each run saves screenshots plus a SQLite DB and JSONL under the run's results folder, and prints a per-page summary (status, title, detected tech). **Open gallery** serves gowitness' report UI on a random localhost port (browse/filter all pages, similar pages grouped by perceptual hash); it stops when GhostRecon closes. Honours the global Burp proxy, headers/cookie/bug-bounty header and browser User-Agent. Also available as an opt-in **One-Stop** stage. Uses gowitness' `gorod` driver — the default `chromedp` driver intermittently hung on the capture step with current Chromium.
- **Web Scan tab** (grouped sub-tabs):
  - **403 Bypass** — tries path mutations (`/.`, `//`, `/..;/`, `%2e`, trailing slash, extensions…), header tricks (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, …) and alternate methods against a forbidden URL, flagging anything that turns a 401/403 into 2xx. Can load the 401/403 rows straight from Dir Busting.
  - **WPScan** — WordPress scan with enumeration of vulnerable plugins/themes/users, config backups, `--stealthy`, and an optional API token for CVE data.
  - **Nikto** — classic web-server scan with optional tuning and forced SSL.
- **Live streaming log + progress bar + Stop button** — no frozen window on long scans.
- **Organized output** — every run is saved to `results/<target>/<timestamp>/<tool>.txt`.
- **Dark / light theme** toggle (View menu).
- **Settings → Install missing tools** — detects which required tools are missing and installs the Go/pip-based ones for you (each via its own pinned install command).
- **Settings → Update installed tools** — checks every installed tool against its latest version and updates the ones you tick (out-of-date ones are pre-selected). Each tool is updated **the same way it was installed**, detected from where its binary actually lives: apt packages via `apt-get install --only-upgrade` (one graphical password prompt for all of them, lists refreshed first), Go builds via `go install …@latest` in place (versions read from the binary with `go version -m`, latest from proxy.golang.org), pipx via `pipx upgrade`, GhostRecon's venv via `pip install -U`, git-cloned tools via `git pull`, and trufflehog by re-downloading the latest release. Shows how stale apt's package lists are, with a **Refresh apt lists** button.
- **Settings → Update nuclei engine / templates** — templates (`nuclei -ut`) need no root. The engine update follows how nuclei was installed: Kali's apt package via `pkexec apt` (graphical password prompt, since distro builds lack `-up`), Go installs via `go install …@latest`, and release binaries via `nuclei -up`.

## Requirements

- Python 3 with Tkinter (`sudo apt install python3-tk` on Debian/Kali).
- Optional: `pip install pyfiglet` for the startup banner.
- The recon tools below. Missing tools are skipped gracefully; use **Settings → Install missing tools** or install manually.

| Tool | Install |
|------|---------|
| amass *(optional, opt-in)* | `sudo apt install amass` |
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| subfaster | `go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` (see note) |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gf | `go install github.com/tomnomnom/gf@latest` (see note) |
| uro | `pipx install uro` |
| naabu | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nmap | `sudo apt install nmap` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dirb | `sudo apt install dirb` |
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` |
| dnsx | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| subzy *(optional)* | `go install -v github.com/PentestPad/subzy@latest` |
| jsluice *(optional)* | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| arjun | `pipx install arjun` |
| js-beautify *(optional)* | `pip3 install --user jsbeautifier` |
| kiterunner (`kr`) | `go install github.com/assetnote/kiterunner/cmd/kr@latest` (or a [release binary](https://github.com/assetnote/kiterunner/releases)) |
| wpscan | `sudo apt install wpscan` |
| nikto | `sudo apt install nikto` |
| gowitness | `go install github.com/sensepost/gowitness@latest` (or `sudo apt install gowitness`); needs Chromium (`sudo apt install chromium`) |
| curl | `sudo apt install curl` (used by JS fetch + 403 bypass) |
| SecLists (wordlists) | `sudo apt install seclists` |

> **Burp tip:** set the proxy in **Settings → Global request settings** to `http://127.0.0.1:8080` (Burp's default) and leave it on while you work — recon hits land in Burp's HTTP history ready for Repeater. Turn it off (or point it elsewhere) for fast unproxied sweeps.

> **httpx note:** the name `httpx` collides with the Python HTTP-client CLI (`python3-httpx`), which ships on some distros (e.g. Kali) at `/usr/bin/httpx`. GhostRecon detects ProjectDiscovery's httpx specifically and prefers `~/go/bin/httpx`, so both can coexist — just make sure the real one is installed.

> **gf note:** `gf` installs with zero patterns — `gf xss` etc. only work once pattern files exist in `~/.config/gf` or `~/.gf`. GhostRecon fetches a pattern set (from [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns)) into `~/.gf` automatically the first time the URLs stage runs `gf`. If that fails (no `git`, no network), install manually: `git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf`.

## Usage

```bash
python3 ghostrecon.py
```

Click **Start**, then work through the tabs. Results are written under `results/`.

## License

MIT
