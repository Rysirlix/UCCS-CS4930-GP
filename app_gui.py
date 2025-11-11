# app_gui.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import json
import time
import re
from urllib.parse import urlparse
import undetected_chromedriver as uc

# ---------- Extraction logic (same as before) ----------
def _ensure_url_schema(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("Empty URL provided.")
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def _sanitize_filename(s: str) -> str:
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    return re.sub(r"[:<>\"/\\|?*\s]", "_", s).strip("_") or "output"

def extract_cookies_and_storage(url: str, headless: bool = True, wait_time: int = 8):
    """
    Extract cookies and storage using undetected-chromedriver.
    headless default True (browser hidden) unless user unchecks it.
    """
    url = _ensure_url_schema(url)
    driver = None

    options = uc.ChromeOptions()
    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
    else:
        options.add_argument("--window-position=-2400,-2400")

    try:
        driver = uc.Chrome(options=options)
        if not headless:
            try:
                driver.minimize_window()
            except Exception:
                pass

        driver.get(url)
        time.sleep(max(1, int(wait_time)))

        final_url = driver.current_url or url
        http_cookies = driver.get_cookies() or []

        # localStorage
        try:
            raw_local = driver.execute_script("return JSON.stringify(window.localStorage);")
            local_storage = json.loads(raw_local) if raw_local else {}
        except Exception:
            try:
                local_storage = driver.execute_script("""
                    var items = {};
                    for (var i = 0; i < localStorage.length; i++) {
                        var k = localStorage.key(i);
                        items[k] = localStorage.getItem(k);
                    }
                    return items;
                """) or {}
            except Exception:
                local_storage = {}

        # sessionStorage
        try:
            raw_session = driver.execute_script("return JSON.stringify(window.sessionStorage);")
            session_storage = json.loads(raw_session) if raw_session else {}
        except Exception:
            try:
                session_storage = driver.execute_script("""
                    var items = {};
                    for (var i = 0; i < sessionStorage.length; i++) {
                        var k = sessionStorage.key(i);
                        items[k] = sessionStorage.getItem(k);
                    }
                    return items;
                """) or {}
            except Exception:
                session_storage = {}

        result = {
            "success": True,
            "url": final_url,
            "http_cookies": http_cookies,
            "local_storage": local_storage,
            "session_storage": session_storage,
            "counts": {
                "http_cookies": len(http_cookies),
                "local_storage": len(local_storage),
                "session_storage": len(session_storage),
                "total": len(http_cookies) + len(local_storage) + len(session_storage)
            }
        }
        return result
    except Exception as e:
        return {"success": False, "error": str(e), "error_type": type(e).__name__}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

# ---------- GUI ----------
class CookieExtractorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cookie & Storage Extractor")
        self.minsize(840, 540)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._create_widgets()
        self.result_queue = queue.Queue()
        self.current_result = None
        self.worker_thread = None
        self.cookies_data = []  # keep cookie objects for details

    def _create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Top row: URL, headless, wait time, start
        top = ttk.Frame(frm)
        top.pack(fill=tk.X, pady=(0,8))

        ttk.Label(top, text="Website URL").pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=52)
        self.url_entry.pack(side=tk.LEFT, padx=(6,12))
        self.url_entry.insert(0, "https://example.com")

        # HEADLESS: default ON (checked)
        self.headless_var = tk.BooleanVar(value=True)
        # Label clarifies meaning: checked = headless ON (recommended)
        self.headless_chk = ttk.Checkbutton(top, text="Headless (checked = ON, browser hidden)", variable=self.headless_var)
        self.headless_chk.pack(side=tk.LEFT, padx=(0,12))

        ttk.Label(top, text="Wait (s)").pack(side=tk.LEFT)
        self.wait_var = tk.StringVar(value="8")
        ttk.Entry(top, textvariable=self.wait_var, width=4).pack(side=tk.LEFT, padx=(6,12))

        self.start_btn = ttk.Button(top, text="Start", command=self.start_extraction)
        self.start_btn.pack(side=tk.LEFT)

        self.save_btn = ttk.Button(top, text="Save As...", command=self.save_as, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=(8,0))

        # Counts summary under top
        counts_frame = ttk.Frame(frm, padding=(0,6))
        counts_frame.pack(fill=tk.X)
        self.count_cookies_var = tk.StringVar(value="Cookies: 0")
        self.count_local_var = tk.StringVar(value="LocalStorage: 0")
        self.count_session_var = tk.StringVar(value="SessionStorage: 0")
        self.count_total_var = tk.StringVar(value="Total items: 0")

        ttk.Label(counts_frame, textvariable=self.count_cookies_var, width=18).pack(side=tk.LEFT, padx=(0,8))
        ttk.Label(counts_frame, textvariable=self.count_local_var, width=18).pack(side=tk.LEFT, padx=(0,8))
        ttk.Label(counts_frame, textvariable=self.count_session_var, width=18).pack(side=tk.LEFT, padx=(0,8))
        ttk.Label(counts_frame, textvariable=self.count_total_var, width=18).pack(side=tk.LEFT, padx=(0,8))

        # Middle: panes for cookies / local / session / logs
        middle = ttk.Panedwindow(frm, orient=tk.HORIZONTAL)
        middle.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(middle, width=320)
        right_frame = ttk.Frame(middle)

        middle.add(left_frame, weight=1)
        middle.add(right_frame, weight=2)

        # Left: lists (bigger, easier to read)
        ttk.Label(left_frame, text="HTTP Cookies").pack(anchor=tk.W)
        self.cookies_list = tk.Listbox(left_frame, height=12, font=("Courier", 10))
        self.cookies_list.pack(fill=tk.BOTH, expand=False, pady=(4,8))
        self.cookies_list.bind("<Double-Button-1>", self.on_cookie_double_click)

        ttk.Label(left_frame, text="localStorage (keys)").pack(anchor=tk.W)
        self.local_list = tk.Listbox(left_frame, height=8)
        self.local_list.pack(fill=tk.BOTH, expand=False, pady=(4,8))

        ttk.Label(left_frame, text="sessionStorage (keys)").pack(anchor=tk.W)
        self.session_list = tk.Listbox(left_frame, height=6)
        self.session_list.pack(fill=tk.BOTH, expand=True, pady=(4,0))

        # Right: log / details (monospace for JSON readability)
        ttk.Label(right_frame, text="Activity / Details").pack(anchor=tk.W)
        self.log_text = tk.Text(right_frame, wrap=tk.WORD, height=20, font=("Courier", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(4,0))

        # Bottom: status bar
        status_frame = ttk.Frame(frm)
        status_frame.pack(fill=tk.X, pady=(8,0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

    # Thread management
    def start_extraction(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Input error", "Please enter a URL.")
            return
        try:
            wait_time = max(1, int(self.wait_var.get()))
        except Exception:
            wait_time = 8

        headless = bool(self.headless_var.get())

        # Disable UI controls
        self.start_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.status_var.set("Starting extraction...")
        self.log("Starting extraction for: " + url)

        # Clear previous lists/log
        self.cookies_list.delete(0, tk.END)
        self.local_list.delete(0, tk.END)
        self.session_list.delete(0, tk.END)
        self.log_text.delete(1.0, tk.END)
        self.current_result = None
        self.cookies_data = []

        # Reset counts
        self._update_counts(0, 0, 0)

        # Start worker thread
        self.worker_thread = threading.Thread(
            target=self._worker, args=(url, headless, wait_time), daemon=True
        )
        self.worker_thread.start()
        # Poll queue
        self.after(200, self._poll_queue)

    def _worker(self, url, headless, wait_time):
        self.result_queue.put(("log", f"Worker: launching browser (headless={headless})..."))
        res = extract_cookies_and_storage(url, headless=headless, wait_time=wait_time)
        self.result_queue.put(("result", res))

    def _poll_queue(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                typ, payload = item
                if typ == "log":
                    self.log(payload)
                elif typ == "result":
                    self._handle_result(payload)
        except queue.Empty:
            pass

        if self.worker_thread and self.worker_thread.is_alive():
            self.after(200, self._poll_queue)
        else:
            # finished
            self.start_btn.config(state=tk.NORMAL)
            if self.current_result and self.current_result.get("success"):
                self.save_btn.config(state=tk.NORMAL)
                self.status_var.set("Finished successfully")
            else:
                self.status_var.set("Ready")

    def _handle_result(self, res):
        if not isinstance(res, dict):
            self.log("Unexpected result type.")
            return

        if res.get("success"):
            self.current_result = res
            self.cookies_data = res.get("http_cookies", []) or []
            self.log("✓ Success")
            self.log(f"Final URL: {res.get('url')}")
            counts = res.get("counts", {})
            self.log(f"Counts: cookies={counts.get('http_cookies')} local={counts.get('local_storage')} session={counts.get('session_storage')} total={counts.get('total')}")

            # populate lists
            for c in self.cookies_data:
                name = c.get("name", "<no-name>")
                domain = c.get("domain", "")
                self.cookies_list.insert(tk.END, f"{name}  ({domain})")

            for k in res.get("local_storage", {}).keys():
                self.local_list.insert(tk.END, k)

            for k in res.get("session_storage", {}).keys():
                self.session_list.insert(tk.END, k)

            # update counts visibly
            self._update_counts(counts.get("http_cookies", 0), counts.get("local_storage", 0), counts.get("session_storage", 0))

            # Save automatically to default filename
            parsed = urlparse(res.get("url") or self.url_var.get())
            domain = _sanitize_filename(parsed.netloc)
            filename = f"{domain}_storage.json"
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(res, f, indent=2, ensure_ascii=False)
                self.log(f"Saved results to {filename}")
            except Exception as e:
                self.log(f"Failed to save automatically: {e}")
        else:
            self.current_result = res
            self.log("✗ ERROR")
            self.log(f"Type: {res.get('error_type')}")
            self.log(f"Details: {res.get('error')}")
            messagebox.showerror("Extraction error", f"{res.get('error_type')}: {res.get('error')}")

    def _update_counts(self, cookies_count: int, local_count: int, session_count: int):
        total = (cookies_count or 0) + (local_count or 0) + (session_count or 0)
        self.count_cookies_var.set(f"Cookies: {cookies_count}")
        self.count_local_var.set(f"LocalStorage: {local_count}")
        self.count_session_var.set(f"SessionStorage: {session_count}")
        self.count_total_var.set(f"Total items: {total}")

    def on_cookie_double_click(self, event):
        # Show JSON details of the selected cookie in the details pane
        sel = self.cookies_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < 0 or idx >= len(self.cookies_data):
            return
        cookie_obj = self.cookies_data[idx]
        pretty = json.dumps(cookie_obj, indent=2, ensure_ascii=False)
        self.log(f"Cookie detail (index {idx}):\n{pretty}")

    def save_as(self):
        if not self.current_result:
            messagebox.showinfo("No data", "No results to save yet.")
            return
        fpath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="storage.json"
        )
        if fpath:
            try:
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(self.current_result, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Saved", f"Saved to {fpath}")
            except Exception as e:
                messagebox.showerror("Save error", str(e))

    def log(self, text: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {text}\n\n")
        self.log_text.see(tk.END)

    def on_close(self):
        if self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("Quit", "A browser extraction is still running. Quit anyway?"):
                return
        self.destroy()

if __name__ == "__main__":
    app = CookieExtractorApp()
    app.mainloop()
