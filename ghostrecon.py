#!/usr/bin/env python3
"""
GhostRecon
----------
@TitoSantana00's consolidated recon GUI (merge of recon_gui.py + SantanaScanner.py).

Pipeline:
    Subdomains -> Live Hosts (httpx) -> Ports / Vulns (nuclei) / URLs -> gf patterns

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
        master.geometry("1000x760")
        master.minsize(820, 620)

        self.theme_name = "dark"
        self.running = False
        self.run_buttons = []          # all buttons disabled during a scan
        self.active_output = None      # Text widget the current scan streams into
        self.current_proc = None       # running subprocess (for Stop)

        # shared pipeline state (results carried between tabs)
        self.state = {
            "target": None,
            "outdir": None,
            "subdomains": [],
            "live_hosts": [],
            "urls": [],
        }

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
                  text="Subdomains · Live Hosts · Ports · URLs · Vulnerabilities",
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
    def _build_menu(self):
        menubar = tk.Menu(self.master)
        view = tk.Menu(menubar, tearoff=0)
        view.add_command(label="Toggle dark/light", command=self.toggle_theme)
        menubar.add_cascade(label="View", menu=view)

        tools = tk.Menu(menubar, tearoff=0)
        tools.add_command(label="Check dependencies", command=self.check_dependencies)
        menubar.add_cascade(label="Tools", menu=tools)

        settings = tk.Menu(menubar, tearoff=0)
        settings.add_command(label="Install missing tools…",
                             command=self.open_install_dialog)
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

        self.outputs = {}  # tab name -> Text widget
        self._build_subdomain_tab()
        self._build_livehost_tab()
        self._build_url_tab()
        self._build_port_tab()
        self._build_vuln_tab()

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
        return text

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
        for widget in list(getattr(self, "outputs", {}).values()) + \
                [getattr(self, "hosts_input", None), getattr(self, "vuln_input", None)]:
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
        idx = self.notebook.index(self.notebook.select())
        return list(self.outputs.values())[idx]

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

    def run_stream(self, command, widget, shell=False, outfile=None, merge_stderr=True):
        """Run a command, stream output live into `widget`, return list of stdout lines.

        merge_stderr=False routes stderr to /dev/null so a tool's progress bars or
        logs (amass writes these to stderr) don't pollute the captured names.
        """
        shown = command if isinstance(command, str) else " ".join(command)
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
    }

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
    # Stage 1: Subdomains
    # ------------------------------------------------------------------ #
    def start_subdomain_recon(self):
        domain = self.domain_entry.get().strip().lower()
        if not is_domain(domain):
            messagebox.showwarning("Input", "Enter a valid domain, e.g. example.com")
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
        if not hosts:
            messagebox.showwarning("Input", "Enter at least one valid host.")
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
        self.run_stream([httpx_bin, "-l", infile, "-silent", "-status-code",
                         "-title", "-tech-detect", "-o", out], w)
        live = sorted(self._read_lines(out))
        # store bare hosts (strip http scheme + metadata) for downstream stages
        bare = sorted({re.sub(r'^https?://', '', ln.split(" ")[0]).split("/")[0]
                       for ln in live})
        self.state["live_hosts"] = bare
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
            self.run_stream(["katana", "-u", url, "-silent", "-jc"], w, outfile=out)
            all_urls |= self._read_lines(out)

        combined = os.path.join(outdir, "all_urls.txt")
        with open(combined, "w") as f:
            f.write("\n".join(sorted(all_urls)) + ("\n" if all_urls else ""))
        self.state["urls"] = sorted(all_urls)
        self.append(w, f"\n[+] {len(all_urls)} unique URLs -> {combined}\n")

        pattern = self.gf_pattern.get()
        if self.require(w, "gf", "uro"):
            self.update_status(f"Filtering for {pattern} ...")
            out = os.path.join(outdir, f"{pattern}.txt")
            cmd = f"cat {combined} | gf {pattern} | uro | tee {out}"
            self.append(w, f"\n--- gf {pattern} results ---\n")
            self.run_stream(cmd, w, shell=True)
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
            self.run_stream(["naabu", "-host", host, "-silent", "-o", out], w)
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
        if not targets:
            messagebox.showwarning("Input", "Enter at least one valid target.")
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
        self.update_status(f"Running nuclei on {len(targets)} targets ...")
        self.run_stream(cmd, w)
        self.append(w, f"\n[+] Saved to {out}\n")
        self.update_status(f"nuclei done -> {out}")


if __name__ == "__main__":
    root = tk.Tk()
    app = GhostReconGUI(root)
    root.mainloop()
