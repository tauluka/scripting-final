import os
import re
import csv
import json
import time
import socket
import hashlib
import threading
import datetime as dt
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from queue import Queue, Empty
from urllib.parse import urlparse
import ssl
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# LEVEL ZERO SECURITY TOOLKIT
# ============================================================
# What this project is:
# ------------------------------------------------------------
# This is a dark-themed desktop cybersecurity toolkit built with
# Python + Tkinter. It is designed as a portfolio project that
# demonstrates GUI development, text analysis, regex, networking,
# hashing, file handling, threading, and basic security logic.
#
# This version includes 11 major sections:
#
#   1. Dashboard
#      - Gives a summary of the most recent tool results
#      - Makes the app feel like a real analyst console
#
#   2. Phishing Analyzer
#      - Paste an email/message
#      - Detect suspicious keywords, links, and pressure tactics
#      - Return a simple risk score
#
#   3. Network Scanner
#      - Scan a host across a port range
#      - Report open ports and common services
#      - Attempt a small banner grab when possible
#
#   4. Log Analyzer
#      - Open a log file
#      - Search for suspicious patterns
#      - Spot repeated failed logins and likely brute-force behavior
#
#   5. File Hash Checker
#      - Select a file
#      - Generate MD5, SHA1, and SHA256
#      - Compare hashes against a small local sample of known-bad hashes
#
#   6. Threat Intel Lookup (Local Demo Version)
#      - Enter an IP, domain, or hash
#      - Compare against a local threat-intel sample database
#      - Useful as a safe demo of IOC lookup logic
#
#   7. Password Strength Checker
#      - Scores password strength and gives best-practice feedback
#
#   8. Security Header Scanner
#      - Checks HTTP response headers used to harden websites
#
#   9. Directory Scanner
#      - Safely tests common web paths on authorized targets
#
#   10. Subdomain Recon
#      - Resolves common subdomains for a domain
#
#   11. Weak Password Audit
#      - Compares usernames/passwords against a weak password wordlist
#
# Why this was built this way:
# ------------------------------------------------------------
# - Tkinter was chosen because it is built into Python and easy to run
# - ttk styling gives the app a cleaner, more modern look
# - Threading is used for network scans so the GUI does not freeze
# - Regex is used for pattern matching in phishing and logs
# - A dashboard helps tie the tools together into one suite
# - Exporting reports makes the project more portfolio-friendly
#
# IMPORTANT:
# ------------------------------------------------------------
# This is an educational / portfolio tool.
# Use network scanning only on systems you own or are authorized to test.
# ============================================================

# ------------------------------
# Window settings
# ------------------------------
APP_TITLE = "Level Zero Security Toolkit"
APP_GEOMETRY = "1240x820"

# ------------------------------
# Theme colors
# ------------------------------
# These colors are reused throughout the interface.
BG = "#0d1117"
PANEL = "#161b22"
PANEL_2 = "#1f2937"
TEXT = "#c9d1d9"
MUTED = "#8b949e"
ACCENT = "#58a6ff"
SAFE = "#3fb950"
WARN = "#ffb86b"
DANGER = "#ff5c5c"
PURPLE = "#bc8cff"
BLACKISH = "#010409"

# ------------------------------
# Common port labels
# ------------------------------
# If an open port is found, we can label it with a likely service name.
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 587: "SMTP Submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}

# ------------------------------
# Suspicious phishing keywords
# ------------------------------
# Each keyword adds a number of points to the phishing score.
# A higher number means the phrase is treated as more suspicious.
PHISHING_KEYWORDS = {
    "urgent": 8, "immediately": 8, "asap": 7, "action required": 9,
    "account suspended": 12, "account locked": 12, "verify": 6,
    "verification": 6, "confirm": 5, "security alert": 10,
    "unauthorized": 8, "suspicious activity": 10, "password": 8,
    "username": 6, "login": 6, "signin": 6, "credentials": 10,
    "reset password": 10, "credit card": 12, "bank": 9, "payment": 7,
    "invoice": 6, "refund": 7, "wire": 8, "transfer": 8,
    "click here": 10, "click below": 10, "open link": 10,
    "download": 7, "attachment": 6, "install": 8, "access now": 10,
    "ssn": 14, "social security": 14, "dob": 10, "pin": 10,
    "otp": 12, "verification code": 12, "security code": 12,
    "winner": 10, "prize": 10, "lottery": 12, "free": 5,
    "claim now": 10, "limited offer": 8, "dear user": 8,
    "dear customer": 8, "official notice": 7, "final warning": 9,
    "virus detected": 12, "malware": 11, "system infected": 12,
    "technical support": 10, "remote access": 11, "support team": 6
}

# ------------------------------
# Log patterns for simple detection
# ------------------------------
# Each entry is:
#   (regex pattern, human description, severity score)
LOG_PATTERNS = [
    (re.compile(r"failed password", re.I), "Failed password attempt", 8),
    (re.compile(r"authentication failure", re.I), "Authentication failure", 8),
    (re.compile(r"invalid user", re.I), "Invalid user", 7),
    (re.compile(r"accepted password", re.I), "Successful login", 2),
    (re.compile(r"sudo", re.I), "Privilege escalation / sudo event", 4),
    (re.compile(r"error", re.I), "Generic error", 3),
    (re.compile(r"denied", re.I), "Access denied", 5),
    (re.compile(r"blocked", re.I), "Blocked action", 4),
    (re.compile(r"malware|trojan|ransomware", re.I), "Malware indicator", 12),
    (re.compile(r"powershell", re.I), "PowerShell activity", 5),
    (re.compile(r"cmd.exe", re.I), "Command shell activity", 5),
    (re.compile(r"nmap", re.I), "Recon tool reference", 6),
    (re.compile(r"sql injection|union select", re.I), "Possible SQLi", 10),
    (re.compile(r"/etc/passwd", re.I), "Sensitive file reference", 8),
    (re.compile(r"admin", re.I), "Admin account mention", 2),
]

# ------------------------------
# Local threat-intel demo data
# ------------------------------
# This is NOT a live feed. It is a local sample data set used to show
# how IOC lookups can work without requiring an API key or internet.
LOCAL_THREAT_DB = {
    "ips": {
        "185.220.101.1": {"severity": "high", "reason": "Known malicious relay / suspicious source in demo dataset"},
        "45.9.148.12": {"severity": "medium", "reason": "Repeated brute-force activity in demo dataset"},
        "203.0.113.77": {"severity": "low", "reason": "Example documentation IP included for testing lookups"}
    },
    "domains": {
        "verify-account-update.com": {"severity": "high", "reason": "Phishing-style domain name in demo dataset"},
        "secure-paypal-alerts.com": {"severity": "high", "reason": "Impersonation-style domain in demo dataset"},
        "bit.ly": {"severity": "medium", "reason": "URL shortener requiring extra review"}
    },
    "hashes": {
        "44d88612fea8a8f36de82e1278abb02f": {"severity": "high", "reason": "Demo known-bad MD5 entry"},
        "3395856ce81f2b7382dee72602f798b642f14140": {"severity": "high", "reason": "Demo known-bad SHA1 entry"},
        "275a021bbfb6485c240a0c38f2f5f8d0d42a2b6503ec6e7f1f3e6f1dca8a1d7d": {"severity": "high", "reason": "Demo known-bad SHA256 entry"}
    }
}

# ------------------------------
# Regex patterns
# ------------------------------
# These are used throughout the toolkit.
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s\]\[\)\(<>\"']+", re.I)
EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_REGEX = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,}$")


class DarkStyle:
    """
    Centralized ttk styling.

    Why this exists:
    - Keeps all style choices in one place
    - Makes the UI look consistent
    - Easier to update the color theme later
    """

    @staticmethod
    def apply(root: tk.Tk):
        style = ttk.Style(root)
        style.theme_use("clam")
        root.configure(bg=BG)

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT, padding=(18, 8))
        style.map("TNotebook.Tab", background=[("selected", PANEL_2)], foreground=[("selected", ACCENT)])

        style.configure("Dark.TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)

        style.configure("Dark.TLabel", background=BG, foreground=TEXT, font=("Consolas", 10))
        style.configure("Title.TLabel", background=BG, foreground=ACCENT, font=("Consolas", 18, "bold"))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED, font=("Consolas", 10))
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT, font=("Consolas", 10))
        style.configure("CardTitle.TLabel", background=PANEL, foreground=ACCENT, font=("Consolas", 12, "bold"))
        style.configure("Metric.TLabel", background=PANEL, foreground=TEXT, font=("Consolas", 18, "bold"))
        style.configure("MetricSub.TLabel", background=PANEL, foreground=MUTED, font=("Consolas", 10))

        style.configure("Dark.TButton", background=PANEL_2, foreground=TEXT, font=("Consolas", 10, "bold"), borderwidth=0)
        style.map("Dark.TButton", background=[("active", ACCENT)], foreground=[("active", "#000000")])

        style.configure("Accent.TButton", background=ACCENT, foreground="#000000", font=("Consolas", 10, "bold"), borderwidth=0)
        style.map("Accent.TButton", background=[("active", PURPLE)])


def make_scrolled_text(parent, height=14):
    """
    Creates a Text widget with a vertical scrollbar.

    Why use a helper function:
    - avoids repeating the same setup code in every tab
    - keeps styling consistent
    - preloads color tags for output formatting
    """
    frame = ttk.Frame(parent, style="Panel.TFrame")

    text = tk.Text(
        frame,
        wrap="word",
        bg=BLACKISH,
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        font=("Consolas", 10),
        height=height,
        padx=8,
        pady=8
    )

    scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scroll.set)

    text.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")

    text.tag_config("safe", foreground=SAFE)
    text.tag_config("warn", foreground=WARN)
    text.tag_config("danger", foreground=DANGER)
    text.tag_config("accent", foreground=ACCENT)
    text.tag_config("muted", foreground=MUTED)
    text.tag_config("title", foreground=ACCENT, font=("Consolas", 12, "bold"))

    return frame, text


class ToolkitApp:
    """
    Main app controller.

    This class owns:
    - all tabs
    - most widgets
    - scanning / analysis logic
    - dashboard summary state
    - report export logic
    """

    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_GEOMETRY)
        DarkStyle.apply(root)

        # Queue is used to safely pass messages from background threads
        # back to Tkinter's main thread.
        self.scan_queue = Queue()

        # Keep track of selected file paths
        self.log_path = ""
        self.hash_path = ""

        # Latest results are stored here so the dashboard can show a summary.
        self.state = {
            "last_phish_score": None,
            "last_phish_verdict": "N/A",
            "last_open_ports": 0,
            "last_scan_target": "N/A",
            "last_log_flagged": 0,
            "last_log_bruteforce": False,
            "last_hash_match": "None",
            "last_threat_lookup": "N/A",
            "last_password_score": "N/A",
            "last_header_score": "N/A",
            "last_dirs_found": 0,
            "last_recon_found": 0,
            "last_audit_findings": 0,
        }

        self.build_ui()
        self.update_dashboard()
        self.root.after(120, self.process_queue)

    # ============================================================
    # UI BUILD
    # ============================================================
    def build_ui(self):
        """Build the overall application window, header, toolbar, and tabs."""
        header = ttk.Frame(self.root, style="Dark.TFrame")
        header.pack(fill="x", padx=14, pady=(12, 8))

        ttk.Label(header, text="Level Zero Security Toolkit", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Dashboard  •  Phishing  •  Network  •  Logs  •  Hashes  •  Threat Intel  •  Passwords  •  Headers  •  Directories  •  Recon  •  Audit",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(3, 0))

        toolbar = ttk.Frame(self.root, style="Dark.TFrame")
        toolbar.pack(fill="x", padx=12, pady=(0, 8))

        ttk.Button(toolbar, text="Export Report", style="Accent.TButton", command=self.export_report).pack(side="left")
        ttk.Button(toolbar, text="Save Local IOC DB", style="Dark.TButton", command=self.save_local_threat_db).pack(side="left", padx=8)
        ttk.Button(toolbar, text="About", style="Dark.TButton", command=self.show_about).pack(side="left")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=8)

        self.dashboard_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.phishing_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.network_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.log_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.hash_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.threat_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.password_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.headers_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.directory_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.recon_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.audit_tab = ttk.Frame(self.notebook, style="Dark.TFrame")

        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.phishing_tab, text="Phishing Analyzer")
        self.notebook.add(self.network_tab, text="Network Scanner")
        self.notebook.add(self.log_tab, text="Log Analyzer")
        self.notebook.add(self.hash_tab, text="File Hash Checker")
        self.notebook.add(self.threat_tab, text="Threat Intel Lookup")
        self.notebook.add(self.password_tab, text="Password Strength")
        self.notebook.add(self.headers_tab, text="Security Headers")
        self.notebook.add(self.directory_tab, text="Directory Scanner")
        self.notebook.add(self.recon_tab, text="Subdomain Recon")
        self.notebook.add(self.audit_tab, text="Password Audit")

        self.build_dashboard_tab()
        self.build_phishing_tab()
        self.build_network_tab()
        self.build_log_tab()
        self.build_hash_tab()
        self.build_threat_tab()
        self.build_password_tab()
        self.build_headers_tab()
        self.build_directory_tab()
        self.build_recon_tab()
        self.build_audit_tab()

    # ============================================================
    # DASHBOARD TAB
    # ============================================================
    def build_dashboard_tab(self):
        """
        The dashboard exists to make the project feel like a unified suite.
        It shows summary values from the other tools.
        """
        container = ttk.Frame(self.dashboard_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        top_row = ttk.Frame(container, style="Dark.TFrame")
        top_row.pack(fill="x", pady=(0, 8))

        self.card_phish = self.make_metric_card(top_row, "Last Phishing Verdict", "N/A", "No analysis yet")
        self.card_scan = self.make_metric_card(top_row, "Open Ports Found", "0", "No scan yet")
        self.card_log = self.make_metric_card(top_row, "Flagged Log Events", "0", "No log analysis yet")
        self.card_hash = self.make_metric_card(top_row, "Hash Match", "None", "No hash check yet")

        self.card_phish.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.card_scan.pack(side="left", fill="both", expand=True, padx=6)
        self.card_log.pack(side="left", fill="both", expand=True, padx=6)
        self.card_hash.pack(side="left", fill="both", expand=True, padx=(6, 0))

        bottom = ttk.Frame(container, style="Panel.TFrame", padding=12)
        bottom.pack(fill="both", expand=True, pady=(10, 0))

        ttk.Label(bottom, text="Toolkit Summary", style="CardTitle.TLabel").pack(anchor="w")
        summary_frame, self.dashboard_output = make_scrolled_text(bottom, height=24)
        summary_frame.pack(fill="both", expand=True, pady=(8, 0))

    def make_metric_card(self, parent, title, value, subtitle):
        """Creates a small dashboard card used for high-level summary values."""
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        title_label = ttk.Label(frame, text=title, style="CardTitle.TLabel")
        title_label.pack(anchor="w")

        value_label = ttk.Label(frame, text=value, style="Metric.TLabel")
        value_label.pack(anchor="w", pady=(10, 4))

        subtitle_label = ttk.Label(frame, text=subtitle, style="MetricSub.TLabel")
        subtitle_label.pack(anchor="w")

        # Store references on the frame so we can update them later
        frame.value_label = value_label
        frame.subtitle_label = subtitle_label
        return frame

    def update_dashboard(self):
        """
        Refreshes all summary cards and dashboard text.
        This is called after each tool finishes an analysis.
        """
        self.card_phish.value_label.config(text=self.state["last_phish_verdict"])
        self.card_phish.subtitle_label.config(text=f"Score: {self.state['last_phish_score'] if self.state['last_phish_score'] is not None else 'N/A'}")

        self.card_scan.value_label.config(text=str(self.state["last_open_ports"]))
        self.card_scan.subtitle_label.config(text=f"Target: {self.state['last_scan_target']}")

        log_sub = "Brute force suspected" if self.state["last_log_bruteforce"] else "No brute force flag"
        self.card_log.value_label.config(text=str(self.state["last_log_flagged"]))
        self.card_log.subtitle_label.config(text=log_sub)

        self.card_hash.value_label.config(text=self.state["last_hash_match"])
        self.card_hash.subtitle_label.config(text=f"Threat lookup: {self.state['last_threat_lookup']}")

        self.dashboard_output.delete("1.0", tk.END)
        self.dashboard_output.insert(tk.END, "Level Zero Security Toolkit - Current Summary\n\n", "title")
        self.dashboard_output.insert(tk.END, f"Phishing Analyzer:\n", "accent")
        self.dashboard_output.insert(tk.END, f"  • Last verdict: {self.state['last_phish_verdict']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Last score: {self.state['last_phish_score'] if self.state['last_phish_score'] is not None else 'N/A'}\n\n", "muted")

        self.dashboard_output.insert(tk.END, f"Network Scanner:\n", "accent")
        self.dashboard_output.insert(tk.END, f"  • Last target: {self.state['last_scan_target']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Open ports found: {self.state['last_open_ports']}\n\n", "muted")

        self.dashboard_output.insert(tk.END, f"Log Analyzer:\n", "accent")
        self.dashboard_output.insert(tk.END, f"  • Flagged events: {self.state['last_log_flagged']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Brute-force suspected: {self.state['last_log_bruteforce']}\n\n", "muted")

        self.dashboard_output.insert(tk.END, f"Hash Checker:\n", "accent")
        self.dashboard_output.insert(tk.END, f"  • Hash match result: {self.state['last_hash_match']}\n\n", "muted")

        self.dashboard_output.insert(tk.END, f"Threat Intel:\n", "accent")
        self.dashboard_output.insert(tk.END, f"  • Last lookup: {self.state['last_threat_lookup']}\n\n", "muted")

        self.dashboard_output.insert(tk.END, f"Additional Features Added:\n", "accent")
        self.dashboard_output.insert(tk.END, f"  • Password strength score: {self.state['last_password_score']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Security header score: {self.state['last_header_score']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Directories found: {self.state['last_dirs_found']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Subdomains found: {self.state['last_recon_found']}\n", "muted")
        self.dashboard_output.insert(tk.END, f"  • Weak password findings: {self.state['last_audit_findings']}\n", "muted")

    # ============================================================
    # PHISHING ANALYZER TAB
    # ============================================================
    def build_phishing_tab(self):
        container = ttk.Frame(self.phishing_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(container, style="Panel.TFrame", padding=12)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))

        right = ttk.Frame(container, style="Panel.TFrame", padding=12)
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))

        ttk.Label(left, text="Paste email body / message text", style="Panel.TLabel").pack(anchor="w")
        in_frame, self.phish_input = make_scrolled_text(left, height=24)
        in_frame.pack(fill="both", expand=True, pady=(8, 10))

        btn_row = ttk.Frame(left, style="Panel.TFrame")
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Analyze Message", style="Accent.TButton", command=self.analyze_phishing).pack(side="left")
        ttk.Button(btn_row, text="Load Text File", style="Dark.TButton", command=self.load_email_text).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.phish_input, self.phish_output)).pack(side="left")

        ttk.Label(right, text="Analysis Results", style="Panel.TLabel").pack(anchor="w")
        out_frame, self.phish_output = make_scrolled_text(right, height=24)
        out_frame.pack(fill="both", expand=True, pady=(8, 10))

    def load_email_text(self):
        """Load a text file into the phishing input box."""
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            self.phish_input.delete("1.0", tk.END)
            self.phish_input.insert(tk.END, data)
        except Exception as e:
            messagebox.showerror("Load Error", f"Could not read file:\n{e}")

    def analyze_phishing(self):
        """
        How this analyzer works:
        ------------------------------------------------------------
        1. Read the message text
        2. Lowercase it for easier keyword matching
        3. Add points for suspicious keywords
        4. Extract and evaluate URLs
        5. Add points for pressure tactics like ALL CAPS or !!!
        6. Assign a LOW / MEDIUM / HIGH verdict

        Why score-based detection was chosen:
        - easier to understand than advanced ML
        - transparent for class demos
        - simple to tune as you improve the tool
        """
        text = self.phish_input.get("1.0", tk.END).strip()
        self.phish_output.delete("1.0", tk.END)

        if not text:
            self.phish_output.insert(tk.END, "Paste or load a message first.\n", "warn")
            return

        lowered = text.lower()
        score = 0
        findings = []

        matched_keywords = []
        for word, points in PHISHING_KEYWORDS.items():
            if word in lowered:
                score += points
                matched_keywords.append(word)

        if matched_keywords:
            findings.append(("Suspicious wording", matched_keywords[:25], "warn"))

        urls = URL_REGEX.findall(text)
        suspicious_urls = []
        for url in urls:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            reasons = []

            # A URL containing @ can hide the real destination from casual readers.
            if "@" in url:
                reasons.append("contains @")
                score += 10

            # Shortened links require extra caution because the destination is hidden.
            if any(short in host for short in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]):
                reasons.append("shortened URL")
                score += 12

            # Direct IP addresses in links can be suspicious.
            if re.search(r"\d+\.\d+\.\d+\.\d+", host):
                reasons.append("raw IP in URL")
                score += 10

            # Lots of hyphens and deep subdomains can be a phishing clue.
            if host.count("-") >= 2:
                reasons.append("many hyphens")
                score += 5
            if host.count(".") >= 3:
                reasons.append("deep subdomain")
                score += 4

            # Check against our local threat-intel domain DB as another signal.
            if host in LOCAL_THREAT_DB["domains"]:
                reasons.append("domain appears in local IOC demo DB")
                score += 15

            if reasons:
                suspicious_urls.append(f"{url} -> {', '.join(reasons)}")

        if suspicious_urls:
            findings.append(("Suspicious URLs", suspicious_urls, "danger"))

        exclamations = text.count("!")
        if exclamations >= 3:
            score += 5
            findings.append(("Pressure / tone", [f"High exclamation use: {exclamations}"], "warn"))

        all_caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
        if len(all_caps_words) >= 3:
            score += 5
            findings.append(("Pressure / tone", [f"Many ALL CAPS words: {', '.join(all_caps_words[:10])}"], "warn"))

        emails = EMAIL_REGEX.findall(text)
        if emails:
            suspicious_domains = [e for e in emails if any(x in e.lower() for x in ["support", "secure", "verify", "billing"])]
            if suspicious_domains:
                score += 4
                findings.append(("Sender clues", suspicious_domains[:10], "warn"))

        if len(text) < 40:
            score += 2

        score = min(score, 100)

        if score >= 60:
            verdict = "HIGH RISK"
            tag = "danger"
        elif score >= 30:
            verdict = "MEDIUM RISK"
            tag = "warn"
        else:
            verdict = "LOW RISK"
            tag = "safe"

        self.phish_output.insert(tk.END, f"Risk Score: {score}/100\n", tag)
        self.phish_output.insert(tk.END, f"Verdict: {verdict}\n\n", tag)

        if findings:
            for section, items, item_tag in findings:
                self.phish_output.insert(tk.END, f"[+] {section}\n", "accent")
                for item in items:
                    self.phish_output.insert(tk.END, f"  • {item}\n", item_tag)
                self.phish_output.insert(tk.END, "\n")
        else:
            self.phish_output.insert(tk.END, "No strong phishing indicators were detected.\n", "safe")

        self.phish_output.insert(tk.END, "Recommended action:\n", "accent")
        if score >= 60:
            self.phish_output.insert(tk.END, "  • Do not click links or open attachments.\n  • Verify the sender through a trusted channel.\n  • Report the message for review.\n", "danger")
        elif score >= 30:
            self.phish_output.insert(tk.END, "  • Treat with caution.\n  • Verify requests for login, payment, or personal info.\n", "warn")
        else:
            self.phish_output.insert(tk.END, "  • Still verify unexpected requests before responding.\n", "safe")

        self.state["last_phish_score"] = score
        self.state["last_phish_verdict"] = verdict
        self.update_dashboard()

    # ============================================================
    # NETWORK SCANNER TAB
    # ============================================================
    def build_network_tab(self):
        container = ttk.Frame(self.network_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        controls = ttk.Frame(container, style="Panel.TFrame", padding=12)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="Target IP / Host:", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=4)
        self.target_entry = tk.Entry(controls, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=24)
        self.target_entry.grid(row=0, column=1, sticky="w", pady=4)
        self.target_entry.insert(0, "127.0.0.1")

        ttk.Label(controls, text="Start Port:", style="Panel.TLabel").grid(row=0, column=2, sticky="w", padx=(16, 6), pady=4)
        self.start_port_entry = tk.Entry(controls, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=10)
        self.start_port_entry.grid(row=0, column=3, sticky="w", pady=4)
        self.start_port_entry.insert(0, "1")

        ttk.Label(controls, text="End Port:", style="Panel.TLabel").grid(row=0, column=4, sticky="w", padx=(16, 6), pady=4)
        self.end_port_entry = tk.Entry(controls, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=10)
        self.end_port_entry.grid(row=0, column=5, sticky="w", pady=4)
        self.end_port_entry.insert(0, "1024")

        ttk.Button(controls, text="Start Scan", style="Accent.TButton", command=self.start_scan).grid(row=0, column=6, padx=(18, 8))
        ttk.Button(controls, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.net_output)).grid(row=0, column=7)

        ttk.Label(controls, text="Use only on systems you own or are authorized to assess.", style="Panel.TLabel").grid(row=1, column=0, columnspan=8, sticky="w", pady=(10, 0))

        out_wrap, self.net_output = make_scrolled_text(container, height=28)
        out_wrap.pack(fill="both", expand=True)

    def start_scan(self):
        """
        Why threading is used here:
        ------------------------------------------------------------
        Port scanning can take time. If we ran the scan directly in the GUI
        thread, the whole window would freeze until the scan finished.

        Instead:
        - the scan runs in a background thread
        - results are pushed into a queue
        - the main Tkinter loop reads from the queue and updates safely
        """
        target = self.target_entry.get().strip()
        self.net_output.delete("1.0", tk.END)

        try:
            start_port = int(self.start_port_entry.get().strip())
            end_port = int(self.end_port_entry.get().strip())
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except ValueError:
            self.net_output.insert(tk.END, "Invalid port range. Use values between 1 and 65535.\n", "danger")
            return

        self.net_output.insert(tk.END, f"Starting scan against {target} from port {start_port} to {end_port}\n\n", "accent")
        self.state["last_scan_target"] = target
        self.state["last_open_ports"] = 0
        self.update_dashboard()

        thread = threading.Thread(target=self.scan_ports_thread, args=(target, start_port, end_port), daemon=True)
        thread.start()

    def scan_ports_thread(self, target, start_port, end_port):
        """
        Actual scanning logic.

        connect_ex() returns:
        - 0 if connection succeeds (port likely open)
        - non-zero if the port is closed or unreachable
        """
        open_ports = []

        try:
            resolved_ip = socket.gethostbyname(target)
            self.scan_queue.put(("net", f"Resolved target: {resolved_ip}\n", "muted"))
        except socket.gaierror:
            self.scan_queue.put(("net", "Could not resolve the host name.\n", "danger"))
            return

        for port in range(start_port, end_port + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.35)
                result = s.connect_ex((target, port))

                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    banner = self.try_banner_grab(target, port)
                    open_ports.append((port, service, banner))

                    line = f"[OPEN] {port:<5}  Service: {service}"
                    if banner:
                        line += f"  | Banner: {banner[:80]}"
                    line += "\n"
                    self.scan_queue.put(("net", line, "safe"))

                s.close()
            except Exception:
                continue

        if not open_ports:
            self.scan_queue.put(("net", "\nNo open ports found in the selected range.\n", "warn"))
            self.scan_queue.put(("net_summary", {"count": 0}, None))
        else:
            self.scan_queue.put(("net", f"\nScan complete. Open ports found: {len(open_ports)}\n", "accent"))
            self.scan_queue.put(("net", self.generate_port_advice(open_ports), "muted"))
            self.scan_queue.put(("net_summary", {"count": len(open_ports)}, None))

    def try_banner_grab(self, target, port):
        """
        Banner grabbing tries to read back a little service information.
        This is optional and will not work on every port.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target, port))

            if port in (80, 8080, 8000, 443, 8443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")

            data = s.recv(128)
            s.close()
            return data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")
        except Exception:
            return ""

    def generate_port_advice(self, open_ports):
        """Provides educational review notes based on discovered ports."""
        lines = ["\nQuick Review Notes:\n"]
        for port, service, _ in open_ports:
            if port == 21:
                lines.append("  • FTP (21): legacy protocol; avoid anonymous access and plaintext credentials.\n")
            elif port == 22:
                lines.append("  • SSH (22): verify strong authentication, patching, and key management.\n")
            elif port == 23:
                lines.append("  • Telnet (23): insecure plaintext management; replace with SSH.\n")
            elif port in (80, 8080):
                lines.append("  • HTTP (80/8080): consider HTTPS and web hardening review.\n")
            elif port == 445:
                lines.append("  • SMB (445): validate exposure, patch level, and segmentation.\n")
            elif port == 3389:
                lines.append("  • RDP (3389): restrict exposure, MFA, and monitor brute-force attempts.\n")
            elif port == 3306:
                lines.append("  • MySQL (3306): do not expose publicly unless absolutely necessary.\n")
            elif port == 1433:
                lines.append("  • MSSQL (1433): verify source restrictions and strong credentials.\n")
        if len(lines) == 1:
            lines.append("  • No notable review notes generated.\n")
        return "".join(lines)

    # ============================================================
    # LOG ANALYZER TAB
    # ============================================================
    def build_log_tab(self):
        container = ttk.Frame(self.log_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        controls = ttk.Frame(container, style="Panel.TFrame", padding=12)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Button(controls, text="Load Log File", style="Accent.TButton", command=self.load_log_file).pack(side="left")
        ttk.Button(controls, text="Analyze", style="Dark.TButton", command=self.analyze_log).pack(side="left", padx=8)
        ttk.Button(controls, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.log_output)).pack(side="left")

        self.log_path_label = ttk.Label(controls, text="No log file selected", style="Panel.TLabel")
        self.log_path_label.pack(side="left", padx=14)

        out_wrap, self.log_output = make_scrolled_text(container, height=28)
        out_wrap.pack(fill="both", expand=True)

    def load_log_file(self):
        path = filedialog.askopenfilename(filetypes=[("Log/Text files", "*.log *.txt"), ("All files", "*.*")])
        if not path:
            return
        self.log_path = path
        self.log_path_label.config(text=os.path.basename(path))

    def analyze_log(self):
        """
        How the log analyzer works:
        ------------------------------------------------------------
        1. Open the selected log file
        2. Read it line by line
        3. Check each line against known regex patterns
        4. Score suspicious lines
        5. Count IP appearances
        6. Guess whether repeated failed logins may indicate brute force

        Why regex was used:
        - security logs are basically text
        - regex is great for finding patterns quickly
        - it is transparent and easy to explain in class
        """
        self.log_output.delete("1.0", tk.END)

        if not self.log_path:
            self.log_output.insert(tk.END, "Select a log file first.\n", "warn")
            return

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            self.log_output.insert(tk.END, f"Error reading log: {e}\n", "danger")
            return

        findings = []
        ip_counts = {}
        total_score = 0

        for idx, line in enumerate(lines, start=1):
            line_score = 0
            matched = []

            for pattern, desc, score in LOG_PATTERNS:
                if pattern.search(line):
                    matched.append(desc)
                    line_score += score

            if matched:
                findings.append((idx, line.strip(), matched, line_score))
                total_score += line_score

            for ip in IP_REGEX.findall(line):
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        self.log_output.insert(tk.END, f"Analyzed file: {os.path.basename(self.log_path)}\n", "accent")
        self.log_output.insert(tk.END, f"Total lines: {len(lines)}\n", "muted")
        self.log_output.insert(tk.END, f"Flagged events: {len(findings)}\n", "muted")
        self.log_output.insert(tk.END, f"Aggregate event score: {total_score}\n\n", "muted")

        if ip_counts:
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            self.log_output.insert(tk.END, "Top IPs in file:\n", "accent")
            for ip, count in top_ips:
                tag = "danger" if count >= 10 else "warn" if count >= 5 else "safe"
                self.log_output.insert(tk.END, f"  • {ip} -> {count} occurrences\n", tag)
            self.log_output.insert(tk.END, "\n")

        if not findings:
            self.log_output.insert(tk.END, "No matching suspicious patterns were found.\n", "safe")
            self.state["last_log_flagged"] = 0
            self.state["last_log_bruteforce"] = False
            self.update_dashboard()
            return

        repeated_failed = [
            f for f in findings
            if any("Failed password attempt" in x or "Authentication failure" in x for x in f[2])
        ]
        bruteforce_flag = len(repeated_failed) >= 5
        if bruteforce_flag:
            self.log_output.insert(tk.END, "Possible brute-force pattern detected due to repeated authentication failures.\n\n", "danger")

        self.log_output.insert(tk.END, "Flagged Events:\n", "accent")
        for idx, raw, matched, score in findings[:60]:
            tag = "danger" if score >= 10 else "warn"
            self.log_output.insert(tk.END, f"[Line {idx}] Score {score} | {', '.join(matched)}\n", tag)
            self.log_output.insert(tk.END, f"  {raw[:220]}\n\n", "muted")

        if len(findings) > 60:
            self.log_output.insert(tk.END, f"Showing first 60 of {len(findings)} flagged events.\n", "warn")

        self.state["last_log_flagged"] = len(findings)
        self.state["last_log_bruteforce"] = bruteforce_flag
        self.update_dashboard()

    # ============================================================
    # FILE HASH CHECKER TAB
    # ============================================================
    def build_hash_tab(self):
        container = ttk.Frame(self.hash_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        controls = ttk.Frame(container, style="Panel.TFrame", padding=12)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Button(controls, text="Select File", style="Accent.TButton", command=self.load_hash_file).pack(side="left")
        ttk.Button(controls, text="Calculate Hashes", style="Dark.TButton", command=self.analyze_hash_file).pack(side="left", padx=8)
        ttk.Button(controls, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.hash_output)).pack(side="left")

        self.hash_path_label = ttk.Label(controls, text="No file selected", style="Panel.TLabel")
        self.hash_path_label.pack(side="left", padx=14)

        out_wrap, self.hash_output = make_scrolled_text(container, height=28)
        out_wrap.pack(fill="both", expand=True)

    def load_hash_file(self):
        """Choose a file whose hashes will be calculated."""
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if not path:
            return
        self.hash_path = path
        self.hash_path_label.config(text=os.path.basename(path))

    def analyze_hash_file(self):
        """
        Hashing is useful because:
        - it gives a unique fingerprint of a file
        - analysts use hashes to compare files across systems
        - known-bad hashes can indicate malware or suspicious files

        This function computes:
        - MD5
        - SHA1
        - SHA256
        and checks them against a local sample IOC list
        """
        self.hash_output.delete("1.0", tk.END)

        if not self.hash_path:
            self.hash_output.insert(tk.END, "Select a file first.\n", "warn")
            return

        try:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()

            with open(self.hash_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)

            md5_val = md5_hash.hexdigest()
            sha1_val = sha1_hash.hexdigest()
            sha256_val = sha256_hash.hexdigest()

            self.hash_output.insert(tk.END, f"File: {os.path.basename(self.hash_path)}\n\n", "accent")
            self.hash_output.insert(tk.END, f"MD5:    {md5_val}\n", "muted")
            self.hash_output.insert(tk.END, f"SHA1:   {sha1_val}\n", "muted")
            self.hash_output.insert(tk.END, f"SHA256: {sha256_val}\n\n", "muted")

            match_results = []
            for label, value in [("MD5", md5_val), ("SHA1", sha1_val), ("SHA256", sha256_val)]:
                if value in LOCAL_THREAT_DB["hashes"]:
                    info = LOCAL_THREAT_DB["hashes"][value]
                    match_results.append((label, value, info))

            if match_results:
                self.hash_output.insert(tk.END, "Hash Match Results:\n", "danger")
                for label, value, info in match_results:
                    self.hash_output.insert(tk.END, f"  • {label} matched local IOC DB\n", "danger")
                    self.hash_output.insert(tk.END, f"    Severity: {info['severity']}\n", "warn")
                    self.hash_output.insert(tk.END, f"    Reason: {info['reason']}\n\n", "muted")
                self.state["last_hash_match"] = "MATCH FOUND"
            else:
                self.hash_output.insert(tk.END, "No matches found in the local IOC DB.\n", "safe")
                self.state["last_hash_match"] = "No match"

            self.update_dashboard()

        except Exception as e:
            self.hash_output.insert(tk.END, f"Error reading file: {e}\n", "danger")

    # ============================================================
    # THREAT INTEL LOOKUP TAB
    # ============================================================
    def build_threat_tab(self):
        container = ttk.Frame(self.threat_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        top = ttk.Frame(container, style="Panel.TFrame", padding=12)
        top.pack(fill="x", pady=(0, 8))

        ttk.Label(top, text="IOC / Indicator to look up (IP, domain, or hash):", style="Panel.TLabel").pack(anchor="w")
        self.threat_entry = tk.Entry(top, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=60)
        self.threat_entry.pack(anchor="w", pady=(8, 10))

        btn_row = ttk.Frame(top, style="Panel.TFrame")
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Lookup", style="Accent.TButton", command=self.lookup_threat_indicator).pack(side="left")
        ttk.Button(btn_row, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.threat_output)).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Load from Hash Tab", style="Dark.TButton", command=self.load_last_hash_into_lookup).pack(side="left")

        bottom = ttk.Frame(container, style="Panel.TFrame", padding=12)
        bottom.pack(fill="both", expand=True)
        ttk.Label(bottom, text="Lookup Results", style="Panel.TLabel").pack(anchor="w")
        out_wrap, self.threat_output = make_scrolled_text(bottom, height=26)
        out_wrap.pack(fill="both", expand=True, pady=(8, 0))

    def load_last_hash_into_lookup(self):
        """Helper to prefill the threat lookup entry with the SHA256 of the selected file if available."""
        if not self.hash_path:
            messagebox.showinfo("No File", "Select and hash a file first.")
            return

        try:
            sha256_hash = hashlib.sha256()
            with open(self.hash_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
            self.threat_entry.delete(0, tk.END)
            self.threat_entry.insert(0, sha256_hash.hexdigest())
        except Exception as e:
            messagebox.showerror("Hash Error", f"Could not generate SHA256:\n{e}")

    def lookup_threat_indicator(self):
        """
        Demo IOC lookup logic.

        This tab simulates how a real threat-intel lookup tool behaves.
        In a production version, you would replace the local data set with:
        - VirusTotal API
        - AbuseIPDB
        - AlienVault OTX
        - internal IOC feeds

        For safety and simplicity, this version uses a local dictionary.
        """
        self.threat_output.delete("1.0", tk.END)
        indicator = self.threat_entry.get().strip().lower()

        if not indicator:
            self.threat_output.insert(tk.END, "Enter an IP, domain, or hash first.\n", "warn")
            return

        result = None
        kind = None

        if IP_REGEX.fullmatch(indicator):
            kind = "IP"
            result = LOCAL_THREAT_DB["ips"].get(indicator)
        elif DOMAIN_REGEX.fullmatch(indicator):
            kind = "Domain"
            result = LOCAL_THREAT_DB["domains"].get(indicator)
        else:
            # Very rough heuristic: if it's 32/40/64 hex chars, treat it as a hash.
            if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", indicator):
                kind = "Hash"
                result = LOCAL_THREAT_DB["hashes"].get(indicator)

        self.threat_output.insert(tk.END, f"Indicator: {indicator}\n", "accent")
        self.threat_output.insert(tk.END, f"Detected Type: {kind if kind else 'Unknown'}\n\n", "muted")

        if result:
            sev = result["severity"].lower()
            tag = "danger" if sev == "high" else "warn" if sev == "medium" else "safe"
            self.threat_output.insert(tk.END, "Match found in local IOC DB\n", tag)
            self.threat_output.insert(tk.END, f"Severity: {result['severity']}\n", tag)
            self.threat_output.insert(tk.END, f"Reason: {result['reason']}\n", "muted")
            self.state["last_threat_lookup"] = f"Match ({kind})"
        else:
            self.threat_output.insert(tk.END, "No match found in local IOC DB.\n", "safe")
            self.threat_output.insert(tk.END, "This does NOT prove the item is safe; it only means it is not present in the local demo dataset.\n", "warn")
            self.state["last_threat_lookup"] = f"No match ({kind if kind else 'Unknown'})"

        self.update_dashboard()


    # ============================================================
    # PASSWORD STRENGTH CHECKER TAB
    # ============================================================
    def build_password_tab(self):
        """Builds a password strength checker for defensive education."""
        container = ttk.Frame(self.password_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        top = ttk.Frame(container, style="Panel.TFrame", padding=12)
        top.pack(fill="x", pady=(0, 8))

        ttk.Label(top, text="Enter password to evaluate:", style="Panel.TLabel").pack(anchor="w")
        self.password_entry = tk.Entry(top, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=60, show="*")
        self.password_entry.pack(anchor="w", pady=(8, 10))

        btns = ttk.Frame(top, style="Panel.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Check Strength", style="Accent.TButton", command=self.check_password_strength).pack(side="left")
        ttk.Button(btns, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.password_output)).pack(side="left", padx=8)

        out_wrap, self.password_output = make_scrolled_text(container, height=28)
        out_wrap.pack(fill="both", expand=True)

    def check_password_strength(self):
        """
        Scores a password using simple, explainable rules.
        This is a defensive control because stronger passwords reduce brute-force risk.
        """
        password = self.password_entry.get()
        self.password_output.delete("1.0", tk.END)

        if not password:
            self.password_output.insert(tk.END, "Enter a password first.\n", "warn")
            return

        score = 0
        feedback = []

        length = len(password)
        if length >= 16:
            score += 35
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            feedback.append("Use at least 12 characters; 16+ is better.")

        checks = [
            (r"[a-z]", 10, "lowercase letters"),
            (r"[A-Z]", 10, "uppercase letters"),
            (r"\d", 10, "numbers"),
            (r"[^A-Za-z0-9]", 15, "symbols"),
        ]
        for pattern, points, label in checks:
            if re.search(pattern, password):
                score += points
            else:
                feedback.append(f"Add {label}.")

        common_bad = ["password", "admin", "qwerty", "letmein", "welcome", "football", "monkey", "dragon"]
        if any(word in password.lower() for word in common_bad):
            score -= 25
            feedback.append("Avoid common words like password, admin, qwerty, or welcome.")

        if re.search(r"(.)\1\1", password):
            score -= 10
            feedback.append("Avoid repeating the same character many times.")

        score = max(0, min(score, 100))
        if score >= 80:
            verdict, tag = "STRONG", "safe"
        elif score >= 50:
            verdict, tag = "MEDIUM", "warn"
        else:
            verdict, tag = "WEAK", "danger"

        self.password_output.insert(tk.END, f"Password Score: {score}/100\n", tag)
        self.password_output.insert(tk.END, f"Verdict: {verdict}\n\n", tag)
        self.password_output.insert(tk.END, "Why this matters:\n", "accent")
        self.password_output.insert(tk.END, "  • Weak passwords are easier to guess, spray, or brute-force.\n", "muted")
        self.password_output.insert(tk.END, "  • Longer passphrases are usually stronger and easier to remember.\n\n", "muted")
        if feedback:
            self.password_output.insert(tk.END, "Recommended improvements:\n", "accent")
            for item in feedback:
                self.password_output.insert(tk.END, f"  • {item}\n", "warn")
        else:
            self.password_output.insert(tk.END, "No major password issues detected.\n", "safe")

        self.state["last_password_score"] = f"{score}/100"
        self.update_dashboard()

    # ============================================================
    # SECURITY HEADER SCANNER TAB
    # ============================================================
    def build_headers_tab(self):
        container = ttk.Frame(self.headers_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        controls = ttk.Frame(container, style="Panel.TFrame", padding=12)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="Website URL:", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.header_url_entry = tk.Entry(controls, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=60)
        self.header_url_entry.grid(row=0, column=1, sticky="w")
        self.header_url_entry.insert(0, "https://example.com")
        ttk.Button(controls, text="Scan Headers", style="Accent.TButton", command=self.scan_security_headers).grid(row=0, column=2, padx=10)
        ttk.Button(controls, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.header_output)).grid(row=0, column=3)

        out_wrap, self.header_output = make_scrolled_text(container, height=28)
        out_wrap.pack(fill="both", expand=True)

    def scan_security_headers(self):
        """Checks common HTTP security headers that help protect websites."""
        url = self.header_url_entry.get().strip()
        self.header_output.delete("1.0", tk.END)

        if not url:
            self.header_output.insert(tk.END, "Enter a URL first.\n", "warn")
            return

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        required = {
            "strict-transport-security": "Forces browsers to use HTTPS.",
            "content-security-policy": "Limits where scripts, images, and other content can load from.",
            "x-frame-options": "Helps prevent clickjacking.",
            "x-content-type-options": "Helps prevent MIME sniffing.",
            "referrer-policy": "Controls how much referrer data is shared.",
            "permissions-policy": "Restricts browser features like camera, mic, and location.",
        }

        try:
            # Use GET instead of HEAD because some websites do not return all headers on HEAD requests
            req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0 LevelZeroToolkit/1.0"
                }
            )

            context = ssl.create_default_context()

            with urllib.request.urlopen(req, timeout=8, context=context) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                status = response.status
                final_url = response.geturl()

        except Exception as e:
            self.header_output.insert(tk.END, f"Could not scan URL: {e}\n", "danger")
            return

        present = 0

        self.header_output.insert(tk.END, f"Scanned: {url}\n", "accent")
        self.header_output.insert(tk.END, f"Final URL: {final_url}\n", "accent")
        self.header_output.insert(tk.END, f"HTTP Status: {status}\n\n", "muted")

        for header, reason in required.items():
            if header in headers:
                present += 1
                self.header_output.insert(tk.END, f"[FOUND] {header}\n", "safe")
                self.header_output.insert(tk.END, f"  Value: {headers[header][:180]}\n", "muted")
            else:
                self.header_output.insert(
                    tk.END,
                    f"[INFO] {header} not observed in this response\n",
                    "warn"
                )

            self.header_output.insert(tk.END, f"  Purpose: {reason}\n\n", "muted")

        score = round((present / len(required)) * 100)

        if score >= 80:
            rating = "Strong"
            tag = "safe"
        elif score >= 50:
            rating = "Moderate"
            tag = "warn"
        else:
            rating = "Needs Review"
            tag = "danger"

        self.header_output.insert(
            tk.END,
            f"Security Header Score: {score}/100 - {rating}\n",
            tag
        )

        self.state["last_header_score"] = f"{score}/100"
        self.update_dashboard()

    # ============================================================
    # DIRECTORY SCANNER TAB
    # ============================================================
    def build_directory_tab(self):
        container = ttk.Frame(self.directory_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        controls = ttk.Frame(container, style="Panel.TFrame", padding=12)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="Base URL:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.dir_url_entry = tk.Entry(
            controls,
            bg=BLACKISH,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Consolas", 10),
            width=50
        )
        self.dir_url_entry.grid(row=0, column=1, padx=8, sticky="w")
        self.dir_url_entry.insert(0, "http://testphp.vulnweb.com")

        ttk.Label(controls, text="Wordlist file:", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 0))

        self.dir_wordlist_label = ttk.Label(
            controls,
            text="Using built-in list",
            style="Panel.TLabel"
        )
        self.dir_wordlist_label.grid(row=1, column=1, sticky="w", pady=(8, 0))

        self.dir_wordlist_path = ""

        ttk.Button(
            controls,
            text="Load Wordlist",
            style="Dark.TButton",
            command=self.load_dir_wordlist
        ).grid(row=1, column=2, padx=8, pady=(8, 0))

        ttk.Button(
            controls,
            text="Start Directory Scan",
            style="Accent.TButton",
            command=self.start_directory_scan
        ).grid(row=0, column=2, padx=8)

        ttk.Button(
            controls,
            text="Clear",
            style="Dark.TButton",
            command=lambda: self.clear_text(self.dir_output)
        ).grid(row=0, column=3)

        ttk.Label(
            controls,
            text="Use only on websites you own or have permission to test.",
            style="Panel.TLabel"
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(10, 0))

        out_wrap, self.dir_output = make_scrolled_text(container, height=27)
        out_wrap.pack(fill="both", expand=True)

    def load_dir_wordlist(self):
        path = filedialog.askopenfilename(
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )

        if path:
            self.dir_wordlist_path = path
            self.dir_wordlist_label.config(text=os.path.basename(path))

    def start_directory_scan(self):
        base_url = self.dir_url_entry.get().strip().rstrip("/")
        self.dir_output.delete("1.0", tk.END)

        if not base_url:
            self.dir_output.insert(tk.END, "Enter a base URL first.\n", "warn")
            return

        if not base_url.startswith(("http://", "https://")):
            base_url = "http://" + base_url

        self.dir_output.insert(
            tk.END,
            f"Starting directory scan against {base_url}\n",
            "accent"
        )

        threading.Thread(
            target=self.directory_scan_thread,
            args=(base_url,),
            daemon=True
        ).start()

    def directory_scan_thread(self, base_url):
        built_in = [
            "admin",
            "login",
            "dashboard",
            "uploads",
            "backup",
            "backups",
            "config",
            "test",
            "dev",
            "api",
            "portal",
            "robots.txt",
            ".git",
            ".env"
        ]

        words = built_in

        if self.dir_wordlist_path:
            try:
                with open(self.dir_wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [x.strip().lstrip("/") for x in f if x.strip()]

            except Exception as e:
                self.scan_queue.put(("dir", f"Could not read wordlist: {e}\n", "danger"))
                return

        found = 0
        restricted = 0
        not_found = 0
        errors = 0

        self.scan_queue.put(("dir", "\n" + "=" * 70 + "\n", "accent"))
        self.scan_queue.put(("dir", "                 DIRECTORY SCAN REPORT\n", "accent"))
        self.scan_queue.put(("dir", "=" * 70 + "\n\n", "accent"))
        self.scan_queue.put(("dir", f"Target: {base_url}\n", "accent"))
        self.scan_queue.put(("dir", f"Paths Tested: {min(len(words), 500)}\n\n", "muted"))

        for word in words[:500]:
            url = f"{base_url}/{word}"

            try:
                req = urllib.request.Request(
                    url,
                    method="GET",
                    headers={"User-Agent": "LevelZeroToolkit/1.0"}
                )

                with urllib.request.urlopen(req, timeout=3) as response:
                    code = response.status

                    if code in (200, 204, 301, 302, 307, 308):
                        found += 1
                        self.scan_queue.put(
                            ("dir", f"[FOUND]      {code}  {url}\n", "safe")
                        )

                    elif code in (401, 403):
                        restricted += 1
                        self.scan_queue.put(
                            ("dir", f"[RESTRICTED] {code}  {url}\n", "warn")
                        )

                    else:
                        self.scan_queue.put(
                            ("dir", f"[INFO]       {code}  {url}\n", "muted")
                        )

            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    restricted += 1
                    self.scan_queue.put(
                        ("dir", f"[RESTRICTED] {e.code}  {url}\n", "warn")
                    )

                elif e.code == 404:
                    not_found += 1

                else:
                    errors += 1

            except Exception:
                errors += 1

        interesting_total = found + restricted

        self.scan_queue.put(("dir", "\n" + "-" * 70 + "\n", "muted"))
        self.scan_queue.put(("dir", "SCAN SUMMARY\n", "accent"))
        self.scan_queue.put(("dir", "-" * 70 + "\n", "muted"))
        self.scan_queue.put(("dir", f"Found Paths           : {found}\n", "safe"))
        self.scan_queue.put(("dir", f"Restricted Paths      : {restricted}\n", "warn"))
        self.scan_queue.put(("dir", f"Interesting Total     : {interesting_total}\n", "accent"))
        self.scan_queue.put(("dir", f"Not Found             : {not_found}\n", "muted"))
        self.scan_queue.put(("dir", f"Errors/Timeouts       : {errors}\n", "muted"))
        self.scan_queue.put(("dir", "-" * 70 + "\n", "muted"))

        if interesting_total > 0:
            self.scan_queue.put(
                ("dir", "\n[NOTE] Found or restricted paths may indicate exposed web resources worth reviewing.\n",
                 "warn")
            )
        else:
            self.scan_queue.put(
                ("dir", "\n[NOTE] No interesting paths were discovered using this wordlist.\n", "muted")
            )

        self.scan_queue.put(("dir", "\nDirectory scan complete.\n", "accent"))
        self.scan_queue.put(("dir_summary", {"count": interesting_total}, None))

    # ============================================================
    # SUBDOMAIN RECON TAB
    # ============================================================
    def build_recon_tab(self):
        container = ttk.Frame(self.recon_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        controls = ttk.Frame(container, style="Panel.TFrame", padding=12)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="Domain:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.recon_domain_entry = tk.Entry(controls, bg=BLACKISH, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10), width=45)
        self.recon_domain_entry.grid(row=0, column=1, padx=8, sticky="w")
        self.recon_domain_entry.insert(0, "example.com")

        ttk.Button(controls, text="Run Recon", style="Accent.TButton", command=self.start_subdomain_recon).grid(row=0, column=2, padx=8)
        ttk.Button(controls, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.recon_output)).grid(row=0, column=3)
        ttk.Label(controls, text="Passive-style DNS resolution demo. Use responsibly.", style="Panel.TLabel").grid(row=1, column=0, columnspan=4, sticky="w", pady=(10,0))

        out_wrap, self.recon_output = make_scrolled_text(container, height=28)
        out_wrap.pack(fill="both", expand=True)

    def start_subdomain_recon(self):
        domain = self.recon_domain_entry.get().strip().lower()
        self.recon_output.delete("1.0", tk.END)
        if not DOMAIN_REGEX.fullmatch(domain):
            self.recon_output.insert(tk.END, "Enter a valid domain such as example.com.\n", "warn")
            return
        self.recon_output.insert(tk.END, f"Resolving common subdomains for {domain}\n\n", "accent")
        threading.Thread(target=self.subdomain_recon_thread, args=(domain,), daemon=True).start()

    def subdomain_recon_thread(self, domain):
        prefixes = ["www", "mail", "remote", "vpn", "portal", "admin", "dev", "test", "staging", "api", "blog", "shop", "support", "docs", "ftp"]
        found = 0
        for prefix in prefixes:
            host = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(host)
                found += 1
                self.scan_queue.put(("recon", f"[FOUND] {host:<35} -> {ip}\n", "safe"))
            except Exception:
                self.scan_queue.put(("recon", f"[MISS]  {host}\n", "muted"))
        self.scan_queue.put(("recon", f"\nRecon complete. Subdomains found: {found}\n", "accent"))
        self.scan_queue.put(("recon_summary", {"count": found}, None))

    # ============================================================
    # WEAK PASSWORD AUDIT TAB
    # ============================================================
    def build_audit_tab(self):
        container = ttk.Frame(self.audit_tab, style="Dark.TFrame")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(container, style="Panel.TFrame", padding=12)
        left.pack(side="left", fill="both", expand=True, padx=(0,6))
        right = ttk.Frame(container, style="Panel.TFrame", padding=12)
        right.pack(side="left", fill="both", expand=True, padx=(6,0))

        ttk.Label(left, text="Paste username,password pairs, one per line:", style="Panel.TLabel").pack(anchor="w")
        in_wrap, self.audit_input = make_scrolled_text(left, height=24)
        in_wrap.pack(fill="both", expand=True, pady=(8,10))
        sample = "admin,admin123\nstudent,Password1\nanalyst,Summer2024!\n"
        self.audit_input.insert(tk.END, sample)

        btns = ttk.Frame(left, style="Panel.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Run Audit", style="Accent.TButton", command=self.run_password_audit).pack(side="left")
        ttk.Button(btns, text="Clear", style="Dark.TButton", command=lambda: self.clear_text(self.audit_input, self.audit_output)).pack(side="left", padx=8)

        ttk.Label(right, text="Audit Results", style="Panel.TLabel").pack(anchor="w")
        out_wrap, self.audit_output = make_scrolled_text(right, height=24)
        out_wrap.pack(fill="both", expand=True, pady=(8,0))

    def run_password_audit(self):
        """
        Safely audits a local list of sample credentials for weak passwords.
        This demonstrates password-spraying/brute-force risk without attacking a real service.
        """
        text = self.audit_input.get("1.0", tk.END).strip()
        self.audit_output.delete("1.0", tk.END)
        if not text:
            self.audit_output.insert(tk.END, "Paste username,password pairs first.\n", "warn")
            return

        weak_list = {"password", "password1", "password123", "admin", "admin123", "welcome", "welcome1", "qwerty", "letmein", "summer2024", "winter2024", "spring2024"}
        findings = 0
        total = 0
        self.audit_output.insert(tk.END, "Weak Password Audit Report\n\n", "title")
        for line in text.splitlines():
            if "," not in line:
                continue
            user, pwd = [x.strip() for x in line.split(",", 1)]
            if not user or not pwd:
                continue
            total += 1
            reasons = []
            if pwd.lower() in weak_list:
                reasons.append("password appears in weak/common list")
            if user.lower() in pwd.lower():
                reasons.append("password contains username")
            if len(pwd) < 10:
                reasons.append("password is shorter than 10 characters")
            if re.fullmatch(r"[A-Za-z]+\d{1,4}", pwd):
                reasons.append("simple word+number pattern")

            if reasons:
                findings += 1
                self.audit_output.insert(tk.END, f"[WEAK] {user}\n", "danger")
                for reason in reasons:
                    self.audit_output.insert(tk.END, f"  • {reason}\n", "warn")
            else:
                self.audit_output.insert(tk.END, f"[OK]   {user}\n", "safe")

        self.audit_output.insert(tk.END, f"\nAccounts checked: {total}\n", "muted")
        self.audit_output.insert(tk.END, f"Weak findings: {findings}\n\n", "danger" if findings else "safe")
        self.audit_output.insert(tk.END, "Defensive recommendation:\n", "accent")
        self.audit_output.insert(tk.END, "  • Enforce longer passphrases, MFA, account lockout, and password blocklists.\n", "muted")
        self.state["last_audit_findings"] = findings
        self.update_dashboard()

    # ============================================================
    # EXPORT / UTILITIES
    # ============================================================
    def export_report(self):
        """
        Exports a simple CSV report containing the latest high-level results.

        Why this is useful:
        - adds a reporting feature to the project
        - makes the app feel more realistic
        - gives you something concrete to show in a portfolio demo
        """
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="level_zero_report.csv"
        )
        if not path:
            return

        rows = [
            ["Timestamp", dt.datetime.now().isoformat(timespec="seconds")],
            ["Last Phishing Score", self.state["last_phish_score"]],
            ["Last Phishing Verdict", self.state["last_phish_verdict"]],
            ["Last Scan Target", self.state["last_scan_target"]],
            ["Open Ports Found", self.state["last_open_ports"]],
            ["Flagged Log Events", self.state["last_log_flagged"]],
            ["Brute Force Suspected", self.state["last_log_bruteforce"]],
            ["Hash Match", self.state["last_hash_match"]],
            ["Last Threat Lookup", self.state["last_threat_lookup"]],
            ["Last Password Score", self.state["last_password_score"]],
            ["Last Security Header Score", self.state["last_header_score"]],
            ["Directories Found", self.state["last_dirs_found"]],
            ["Subdomains Found", self.state["last_recon_found"]],
            ["Weak Password Findings", self.state["last_audit_findings"]],
        ]

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Metric", "Value"])
                writer.writerows(rows)
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not save report:\n{e}")

    def save_local_threat_db(self):
        """Saves the built-in demo IOC database to a JSON file for inspection."""
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="local_ioc_demo_db.json"
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(LOCAL_THREAT_DB, f, indent=4)
            messagebox.showinfo("Saved", f"Local IOC demo DB saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save DB:\n{e}")

    def show_about(self):
        """Small About dialog explaining what the tool is."""
        messagebox.showinfo(
            "About Level Zero Security Toolkit",
            "Level Zero Security Toolkit\n\n"
            "A portfolio-focused Python/Tkinter cybersecurity suite with:\n"
            "- Dashboard\n"
            "- Phishing Analyzer\n"
            "- Network Scanner\n"
            "- Log Analyzer\n"
            "- File Hash Checker\n"
            "- Threat Intel Lookup\n"
            "- Password Strength Checker\n"
            "- Security Header Scanner\n"
            "- Directory Scanner\n"
            "- Subdomain Recon\n"
            "- Weak Password Audit\n\n"
            "Built for education, demos, and learning core cyber concepts."
        )

    def clear_text(self, *widgets):
        """Clear one or more Text widgets."""
        for widget in widgets:
            widget.delete("1.0", tk.END)

    def process_queue(self):
        """
        This method safely updates the GUI using messages from worker threads.

        Why this matters:
        - Tkinter widgets should be updated from the main thread
        - background threads should not touch widgets directly
        - queues are a safe way to pass results back to the GUI
        """
        try:
            while True:
                source, message, tag = self.scan_queue.get_nowait()

                if source == "net":
                    self.net_output.insert(tk.END, message, tag)
                    self.net_output.see(tk.END)

                elif source == "net_summary":
                    self.state["last_open_ports"] = message["count"]
                    self.update_dashboard()

                elif source == "dir":
                    self.dir_output.insert(tk.END, message, tag)
                    self.dir_output.see(tk.END)

                elif source == "dir_summary":
                    self.state["last_dirs_found"] = message["count"]
                    self.update_dashboard()

                elif source == "recon":
                    self.recon_output.insert(tk.END, message, tag)
                    self.recon_output.see(tk.END)

                elif source == "recon_summary":
                    self.state["last_recon_found"] = message["count"]
                    self.update_dashboard()

        except Empty:
            pass

        self.root.after(120, self.process_queue)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================
# This section runs only when the file is executed directly.
# It creates the root Tkinter window and starts the program loop.
if __name__ == "__main__":
    root = tk.Tk()
    app = ToolkitApp(root)
    root.mainloop()
