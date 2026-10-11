# 👻 GhostRecon

A GUI reconnaissance toolkit by [@TitoSantana00](https://github.com/TitoSantana609). GhostRecon chains passive and active recon tools into a single tabbed workflow — subdomains, live hosts, URLs, ports, and vulnerabilities — streaming live output and saving every result to disk.

> ⚠️ **Authorized use only.** Run GhostRecon only against assets you own or are explicitly permitted to test (e.g. a bug-bounty scope or a signed pentest engagement). You are responsible for how you use it.

## The pipeline

```
1. Subdomains ──> 2. Live Hosts ──┬──> 4. Ports (naabu / nmap)
   (amass, subfinder,  (httpx:       ├──> 5. Vulnerabilities (nuclei)
    subfaster,          alive +      └──> 3. URLs (gau + waybackurls + katana)
    crt.sh / crt.name)  title + tech)        └──> gf patterns ──> uro
```

Each stage can load its input from the previous one, so a full sweep flows from a single domain down to filtered vulnerability candidates.

## Features

- **Tabbed interface** — one tab per pipeline stage.
- **Subdomain enumeration** from `amass` (passive), `subfinder`, `subfaster`, and `crt.sh` (JSON API), with `crt.name` as a no-install fallback.
- **Live host probing** with `httpx` (status code, page title, tech detection).
- **URL discovery** from `gau`, `waybackurls`, and `katana`, merged and deduped, then filtered through a chosen **`gf` pattern** (xss, ssrf, lfi, sqli, redirect, rce, idor, ssti) and cleaned with `uro`.
- **Port scanning** via `naabu` (fast) or `nmap` (`-sV`).
- **Vulnerability scanning** with `nuclei` and a severity selector.
- **Live streaming log + progress bar + Stop button** — no frozen window on long scans.
- **Organized output** — every run is saved to `results/<target>/<timestamp>/<tool>.txt`.
- **Dark / light theme** toggle (View menu).
- **Settings → Install missing tools** — detects which required tools are missing and installs the Go/pip-based ones for you (each via its own pinned install command).

## Requirements

- Python 3 with Tkinter (`sudo apt install python3-tk` on Debian/Kali).
- Optional: `pip install pyfiglet` for the startup banner.
- The recon tools below. Missing tools are skipped gracefully; use **Settings → Install missing tools** or install manually.

| Tool | Install |
|------|---------|
| amass | `sudo apt install amass` |
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| subfaster | `go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` (see note) |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gf | `go install github.com/tomnomnom/gf@latest` |
| uro | `pipx install uro` |
| naabu | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nmap | `sudo apt install nmap` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> **httpx note:** the name `httpx` collides with the Python HTTP-client CLI (`python3-httpx`), which ships on some distros (e.g. Kali) at `/usr/bin/httpx`. GhostRecon detects ProjectDiscovery's httpx specifically and prefers `~/go/bin/httpx`, so both can coexist — just make sure the real one is installed.

## Usage

```bash
python3 ghostrecon.py
```

Click **Start**, then work through the tabs. Results are written under `results/`.

## License

MIT
