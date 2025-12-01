# app_gui.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import json
import time
import re
from urllib.parse import urlparse

from extractor import extract_cookies_and_storage
from report_html import generate_html_report


def _sanitize_filename(name: str) -> str:
    """
    Sanitize a string for safe use as a filename.
    Keeps alphanumerics, dot, dash and underscore; replaces others with underscore.
    """
    name = name.strip() or "output"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _pretty_json(data) -> str:
    try:
        return json.dumps(data, indent=2, ensure_ascii=False)
    except TypeError:
        # Fallback for non-serializable objects
        return str(data)


class CookieExtractorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cookie & Storage Extractor")
        self.minsize(840, 540)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.result_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self.current_result = None
        self.worker_thread: threading.Thread | None = None

        # Raw cookie objects from Selenium
        self.cookies_data = []
        # Per-cookie analysis entries (aligned with cookies_data by index)
        self.cookie_analysis = []

        self._create_widgets()

    # ---------- UI construction ----------

    def _create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Top: URL + options + buttons
        top = ttk.Frame(frm)
        top.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(top, text="URL:").pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(top, textvariable=self.url_var, width=60)
        url_entry.pack(side=tk.LEFT, padx=(4, 8))
        url_entry.focus_set()

        self.headless_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Headless", variable=self.headless_var).pack(side=tk.LEFT, padx=(0, 8))

        self.consent_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Try consent click", variable=self.consent_var).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(top, text="Wait (s)").pack(side=tk.LEFT)
        self.wait_var = tk.StringVar(value="8")
        ttk.Entry(top, textvariable=self.wait_var, width=4).pack(side=tk.LEFT, padx=(4, 12))

        self.start_btn = ttk.Button(top, text="Start", command=self.start_extraction)
        self.start_btn.pack(side=tk.LEFT)

        self.save_btn = ttk.Button(top, text="Save As...", command=self.save_as, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.html_btn = ttk.Button(top, text="Export HTML report...", command=self.export_html_report, state=tk.DISABLED)
        self.html_btn.pack(side=tk.LEFT, padx=(8, 0))

        # Counts summary under top
        counts_frame = ttk.Frame(frm, padding=(0, 4))
        counts_frame.pack(fill=tk.X)
        self.count_cookies_var = tk.StringVar(value="Cookies: 0")
        self.count_local_var = tk.StringVar(value="localStorage: 0")
        self.count_session_var = tk.StringVar(value="sessionStorage: 0")
        self.count_total_var = tk.StringVar(value="Total items: 0")

        ttk.Label(counts_frame, textvariable=self.count_cookies_var, width=18).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(counts_frame, textvariable=self.count_local_var, width=18).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(counts_frame, textvariable=self.count_session_var, width=18).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(counts_frame, textvariable=self.count_total_var, width=18).pack(side=tk.LEFT, padx=(0, 8))

        # Middle: panes for cookies / local / session / logs
        middle = ttk.Panedwindow(frm, orient=tk.HORIZONTAL)
        middle.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(middle, width=320)
        right_frame = ttk.Frame(middle)
        middle.add(left_frame, weight=1)
        middle.add(right_frame, weight=2)

        # Left side: cookie/local/session lists
        ttk.Label(left_frame, text="HTTP Cookies").pack(anchor=tk.W)
        self.cookies_list = tk.Listbox(left_frame, height=10)
        self.cookies_list.pack(fill=tk.BOTH, expand=False, pady=(4, 8))
        self.cookies_list.bind("<Double-Button-1>", self.on_cookie_double_click)

        ttk.Label(left_frame, text="localStorage (keys)").pack(anchor=tk.W)
        self.local_list = tk.Listbox(left_frame, height=8)
        self.local_list.pack(fill=tk.BOTH, expand=False, pady=(4, 8))

        ttk.Label(left_frame, text="sessionStorage (keys)").pack(anchor=tk.W)
        self.session_list = tk.Listbox(left_frame, height=6)
        self.session_list.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        # Right side: log / details (monospace for JSON readability)
        ttk.Label(right_frame, text="Activity / Details").pack(anchor=tk.W)

        log_container = ttk.Frame(right_frame)
        log_container.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        self.log_text = tk.Text(log_container, wrap=tk.WORD, height=20, font=("Courier", 10))
        log_scroll = ttk.Scrollbar(log_container, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom: status bar
        status_frame = ttk.Frame(frm)
        status_frame.pack(fill=tk.X, pady=(8, 0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

    # ---------- Thread management ----------

    def start_extraction(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Input error", "Please enter a URL.")
            return

        try:
            wait_time = max(1, int(self.wait_var.get()))
        except ValueError:
            messagebox.showerror("Input error", "Wait time must be an integer (seconds).")
            return

        headless = self.headless_var.get()
        try_consent = self.consent_var.get()

        # Clear previous lists/log/state BEFORE logging new run
        self.cookies_list.delete(0, tk.END)
        self.local_list.delete(0, tk.END)
        self.session_list.delete(0, tk.END)
        self.log_text.delete("1.0", tk.END)
        self._update_counts(0, 0, 0)

        self.current_result = None
        self.cookies_data = []
        self.cookie_analysis = []
        self.save_btn.config(state=tk.DISABLED)
        self.html_btn.config(state=tk.DISABLED)

        self.status_var.set("Starting extraction...")
        self.log(f"Starting extraction for: {url} (headless={headless}, wait={wait_time}s, try_consent={try_consent})")

        self.start_btn.config(state=tk.DISABLED)

        self.worker_thread = threading.Thread(
            target=self._worker,
            args=(url, headless, wait_time, try_consent),
            daemon=True,
        )
        self.worker_thread.start()
        self.after(200, self._poll_queue)

    def _worker(self, url: str, headless: bool, wait_time: int, try_consent: bool):
        self.result_queue.put(("log", f"Worker: launching browser (headless={headless}, try_consent={try_consent})..."))
        # include_analysis=True by default in extractor; GUI just uses whatever it gets
        res = extract_cookies_and_storage(url, headless=headless, wait_time=wait_time, try_consent=try_consent,)
        self.result_queue.put(("result", res))

    def _poll_queue(self):
        try:
            while True:
                typ, payload = self.result_queue.get_nowait()
                if typ == "log":
                    self.log(str(payload))
                elif typ == "result":
                    self._handle_result(payload)
        except queue.Empty:
            pass

        if self.worker_thread and self.worker_thread.is_alive():
            self.after(200, self._poll_queue)
        else:
            # Finished
            self.start_btn.config(state=tk.NORMAL)
            if self.current_result and self.current_result.get("success"):
                self.save_btn.config(state=tk.NORMAL)
                self.html_btn.config(state=tk.NORMAL)
                if self.status_var.get() == "Starting extraction...":
                    self.status_var.set("Finished successfully")
            else:
                if self.status_var.get().startswith("Starting"):
                    self.status_var.set("Ready")

    # ---------- Handling results ----------

    def _handle_result(self, res: dict):
        self.current_result = res

        if not res.get("success"):
            msg = f"Extraction failed: {res.get('error_type', 'Error')} - {res.get('error', '')}"
            self.log(msg)
            messagebox.showerror("Extraction failed", msg)
            self._update_counts(0, 0, 0)
            self.status_var.set("Ready")
            return

        url = res.get("url") or self.url_var.get()
        counts = res.get("counts") or {}

        self.log(f"Extraction complete for: {url}")
        self.log(
            f"Counts -> Cookies: {counts.get('http_cookies', 0)}, "
            f"localStorage: {counts.get('local_storage', 0)}, "
            f"sessionStorage: {counts.get('session_storage', 0)}, "
            f"Total: {counts.get('total', 0)}"
        )

        analysis = self.current_result.get("analysis", {})
        pre = (analysis.get("pre_consent", {})).get("totals", {})
        post = (analysis.get("post_consent", {})).get("totals", {})
        consent_info = analysis.get("consent_action", {})

        if pre and post:
            self.log(
                "Pre/post-consent cookie totals = "
                f"pre: {pre.get('count', 0)} (third-party: {pre.get('third_party', 0)}), "
                f"post: {post.get('count', 0)} (third-party: {post.get('third_party', 0)})"
            )

        if consent_info.get("attempted"):
            self.log(
                "Consent gathering attempted: "
                f"clicked={consent_info.get('clicked')}, "
                f"css={consent_info.get('clicked_css')}, "
                f"xpath={consent_info.get('clicked_xpath')}"
            )
        else:
            self.log("Consent gathering not attempted.")

        self.cookies_data = res.get("http_cookies", [])

        # Pull per-cookie analysis if available and align by index
        self.cookie_analysis = []
        analysis_block = res.get("analysis", {})
        cookie_analysis_group = analysis_block.get("cookies", {})
        per_cookie = cookie_analysis_group.get("cookies", []) if isinstance(cookie_analysis_group, dict) else []
        if len(per_cookie) == len(self.cookies_data):
            self.cookie_analysis = per_cookie
        else:
            # Fallback: lengths don't match; safer to ignore analysis
            self.cookie_analysis = [None] * len(self.cookies_data)

        # Populate lists
        self.cookies_list.delete(0, tk.END)
        self.local_list.delete(0, tk.END)
        self.session_list.delete(0, tk.END)

        for cookie in self.cookies_data:
            name = cookie.get("name", "<no-name>")
            domain = cookie.get("domain", "")
            self.cookies_list.insert(tk.END, f"{name} ({domain})")

        for k in res.get("local_storage", {}).keys():
            self.local_list.insert(tk.END, k)

        for k in res.get("session_storage", {}).keys():
            self.session_list.insert(tk.END, k)

        # Update counts visibly
        self._update_counts(
            counts.get("http_cookies", 0),
            counts.get("local_storage", 0),
            counts.get("session_storage", 0),
        )

        # Auto-save to domain-based filename (explicitly logged for transparency)
        parsed = urlparse(url)
        domain = _sanitize_filename(parsed.netloc or "site")
        filename = f"{domain}_storage.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2, ensure_ascii=False)
            self.log(
                f"Auto-saved full extraction (including cookie and storage values) to '{filename}'."
            )
        except OSError as e:
            self.log(f"Failed to auto-save results to '{filename}': {e}")

        self.status_var.set("Finished successfully")

    def _update_counts(self, cookies_count: int, local_count: int, session_count: int):
        self.count_cookies_var.set(f"Cookies: {cookies_count}")
        self.count_local_var.set(f"localStorage: {local_count}")
        self.count_session_var.set(f"sessionStorage: {session_count}")
        total = cookies_count + local_count + session_count
        self.count_total_var.set(f"Total items: {total}")

    # ---------- Actions ----------

    def save_as(self):
        if not self.current_result or not self.current_result.get("success"):
            messagebox.showwarning("Nothing to save", "There is no successful extraction to save yet.")
            return

        url = self.current_result.get("url") or self.url_var.get()
        parsed = urlparse(url)
        domain = _sanitize_filename(parsed.netloc or "site")
        default_name = f"{domain}_storage.json"

        filename = filedialog.asksaveasfilename(
            title="Save extraction results as...",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filename:
            return

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.current_result, f, indent=2, ensure_ascii=False)
            self.log(f"Saved extraction results to '{filename}'.")
        except OSError as e:
            messagebox.showerror("Save failed", f"Could not save file:\n{e}")
            self.log(f"Save failed for '{filename}': {e}")

    def export_html_report(self):
        if not self.current_result or not self.current_result.get("success"):
            messagebox.showwarning("Nothing to export", "There is no successful extraction to export yet.")
            return

        url = self.current_result.get("url") or self.url_var.get()
        parsed = urlparse(url)
        domain = _sanitize_filename(parsed.netloc or "site")
        default_name = f"{domain}_report.html"

        filename = filedialog.asksaveasfilename(
            title="Export HTML privacy report as...",
            defaultextension=".html",
            initialfile=default_name,
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
        )
        if not filename:
            return

        try:
            generate_html_report(self.current_result, filename)
            self.log(f"HTML report exported to '{filename}'.")
        except OSError as e:
            messagebox.showerror("Export failed", f"Could not save HTML report:\n{e}")
            self.log(f"Export failed for '{filename}': {e}")


    def on_cookie_double_click(self, event=None):
        selection = self.cookies_list.curselection()
        if not selection:
            return
        index = selection[0]
        if index < 0 or index >= len(self.cookies_data):
            return

        cookie = self.cookies_data[index]
        name = cookie.get("name", "<no-name>")
        domain = cookie.get("domain", "")

        analysis_entry = None
        if self.cookie_analysis and index < len(self.cookie_analysis):
            analysis_entry = self.cookie_analysis[index]

        lines = []
        lines.append(f"=== Cookie details: '{name}' ({domain}) ===")

        if analysis_entry:
            meta = analysis_entry.get("analysis", {}) if isinstance(analysis_entry, dict) else {}
            summary = analysis_entry.get("summary", "").strip() if isinstance(analysis_entry, dict) else ""

            category = meta.get("category", "unknown")
            first_party = meta.get("first_party")
            is_session = meta.get("is_session_cookie")
            expires_in_days = meta.get("expires_in_days")
            security_flags = meta.get("security_flags", {})
            risk_flags = meta.get("risk_flags", {})

            # Simple confidence heuristic:
            # - High: category != unknown and has a specific reason
            # - Medium: category != unknown but reason is generic
            # - Low: category == unknown
            reason = meta.get("reason", "")
            if category != "unknown" and reason and "No strong hints" not in reason:
                confidence = "High"
            elif category != "unknown":
                confidence = "Medium"
            else:
                confidence = "Low"

            party_label = (
                "First-party (set by this site)"
                if first_party
                else "Third-party (set by a different site)"
            )

            if is_session:
                lifetime_label = "Session cookie (lasts until you close your browser)"
            elif isinstance(expires_in_days, (int, float)):
                if expires_in_days <= 1:
                    lifetime_label = "Short-lived cookie (about 1 day)"
                elif expires_in_days <= 30:
                    lifetime_label = f"Persistent cookie (~{int(expires_in_days)} days)"
                elif expires_in_days <= 365:
                    lifetime_label = f"Persistent cookie (~{int(expires_in_days / 30)} months)"
                else:
                    lifetime_label = "Long-lived cookie (more than a year)"
            else:
                lifetime_label = "Lifetime not clearly specified"

            lines.append(f"Category        : {category.capitalize()}")
            lines.append(f"Who sets it     : {party_label}")
            lines.append(f"Lifetime        : {lifetime_label}")
            lines.append(f"Secure flag     : {security_flags.get('secure')}")
            lines.append(f"HttpOnly        : {security_flags.get('httpOnly')}")
            lines.append(f"SameSite        : {security_flags.get('sameSite')}")
            lines.append(f"Tracking risks  :")
            lines.append(f"  - Long-lived                : {risk_flags.get('long_lived')}")
            lines.append(f"  - Non-secure on HTTPS       : {risk_flags.get('non_secure_on_https')}")
            lines.append(f"  - JavaScript-readable       : {risk_flags.get('javascript_accessible')}")
            lines.append(f"Explanation src : heuristic analysis based on name and technical properties")
            lines.append(f"Confidence      : {confidence}")
            lines.append("")
            if summary:
                lines.append("Human-friendly summary:")
                lines.append(summary)
                lines.append("")
        else:
            lines.append("No analysis metadata available for this cookie.")
            lines.append("You may still inspect the raw cookie fields below.")
            lines.append("")

        lines.append("Raw cookie JSON:")
        lines.append(_pretty_json(cookie))

        self.log("\n".join(lines))

    # ---------- Logging & shutdown ----------

    def log(self, text: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {text}\n\n")
        self.log_text.see(tk.END)

    def on_close(self):
        if self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno(
                "Quit",
                "A browser extraction is still running. Quit anyway?",
            ):
                return
        self.destroy()


if __name__ == "__main__":
    app = CookieExtractorApp()
    app.mainloop()
