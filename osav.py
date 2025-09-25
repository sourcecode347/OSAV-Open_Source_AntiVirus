import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import tarfile
import gzip
import io
import tempfile
import threading
import concurrent.futures
import queue
import webbrowser
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class OSAV:
    def __init__(self, root):
        self.root = root
        self.root.title("OSAV - Open Source AntiVirus")
        self.root.geometry("600x600")  # Dimensions
        self.root.configure(bg='#1e1e1e')  # Dark background

        self.virus_hashes = set()  # Database of virus hashes (MD5)
        self.db_file = "virus_hashes.txt"  # Local file for hashes
        self.load_db()  # Load initial database

        # Style for dark theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', background='#333333', foreground='white', borderwidth=0)
        self.style.configure('TLabel', background='#1e1e1e', foreground='white')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TProgressbar', troughcolor='#2e2e2e', background='#4CAF50')
        self.style.map('TButton', background=[('active', '#444444')])

        # Main frame
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Top frame for links
        self.top_frame = ttk.Frame(self.frame)
        self.top_frame.pack(fill=tk.X, pady=5)

        # Update Virus Database link (top-left, blue text)
        self.update_link = ttk.Label(
            self.top_frame,
            text="Update Virus Database",
            font=('Arial', 8),
            foreground='#1E90FF',
            cursor="hand2"
        )
        self.update_link.pack(side=tk.LEFT)
        self.update_link.bind("<Button-1>", lambda e: webbrowser.open("https://clamwin.com/content/view/58/27/"))

        # Donate link (top-right, blue text)
        self.donate_link = ttk.Label(
            self.top_frame,
            text="Donate",
            font=('Arial', 8),
            foreground='#1E90FF',
            cursor="hand2"
        )
        self.donate_link.pack(side=tk.RIGHT)
        self.donate_link.bind("<Button-1>", lambda e: webbrowser.open("https://buy.stripe.com/bIY5o70SSfam8Qo7ss"))

        # Welcome label
        self.label = ttk.Label(self.frame, text="Welcome to OSAV", font=('Arial', 14))
        self.label.pack(pady=10)

        # Button to import database
        self.import_btn = ttk.Button(self.frame, text="Import Database File (CVD/TXT)", command=self.import_db)
        self.import_btn.pack(pady=5)

        # Button to scan folder
        self.scan_btn = ttk.Button(self.frame, text="Scan Folder", command=self.start_scan)
        self.scan_btn.pack(pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(self.frame, orient='horizontal', length=300, mode='determinate')
        self.progress.pack(pady=10)

        # Current file label
        self.current_label = ttk.Label(self.frame, text="", font=('Arial', 8))
        self.current_label.pack(pady=5)

        # Listbox for results
        self.results_list = tk.Listbox(self.frame, bg='#2e2e2e', fg='white', font=('Arial', 10), height=10)
        self.results_list.pack(fill=tk.BOTH, expand=True, pady=10)

        # Button to delete selected
        self.delete_btn = ttk.Button(self.frame, text="Delete Selected", command=self.delete_selected)
        self.delete_btn.pack(pady=5)

        self.scanning = False
        self.detected_queue = queue.Queue()

    def load_db(self):
        """Load hashes from local file."""
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                self.virus_hashes = set(line.strip().lower() for line in f if line.strip() and len(line.strip()) == 32)
            logging.debug(f"Loaded {len(self.virus_hashes)} hashes from {self.db_file}")
            if len(self.virus_hashes) == 0:
                logging.warning(f"No valid MD5 hashes found in {self.db_file}")
        self.save_db()  # Ensure saved without duplicates

    def save_db(self):
        """Save hashes to local file (set ensures no duplicates)."""
        with open(self.db_file, 'w') as f:
            for h in sorted(self.virus_hashes):
                f.write(h + '\n')
        logging.debug(f"Saved {len(self.virus_hashes)} hashes to {self.db_file}")

    def import_db(self):
        """Import hashes from CVD or TXT file."""
        file_path = filedialog.askopenfilename(title="Select Database File", filetypes=[("Database Files", "*.cvd *.txt")])
        if not file_path:
            return

        self.progress['value'] = 0
        self.root.update_idletasks()

        try:
            if file_path.lower().endswith('.txt'):
                self.import_txt(file_path)
            elif file_path.lower().endswith('.cvd'):
                self.import_cvd(file_path)
            else:
                messagebox.showerror("Error", "Unsupported file type. Use .cvd or .txt.")
                return

            self.save_db()
            messagebox.showinfo("Success", f"Database updated! Now has {len(self.virus_hashes)} hashes.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import: {str(e)}")
            logging.error(f"Import failed: {str(e)}")
        finally:
            self.progress['value'] = 100
            self.root.update_idletasks()

    def import_txt(self, file_path):
        """Import hashes from TXT file."""
        with open(file_path, 'r') as f:
            lines = f.readlines()
            total = len(lines)
            for i, line in enumerate(lines):
                hash_val = line.strip().lower()
                if len(hash_val) == 32:  # Assume MD5
                    self.virus_hashes.add(hash_val)
                else:
                    logging.warning(f"Invalid hash in {file_path}: {hash_val}")
                self.progress['value'] = (i + 1) / total * 100
                self.root.update_idletasks()
        logging.debug(f"Imported {len(self.virus_hashes)} hashes from {file_path}")

    def import_cvd(self, file_path):
        """Import hashes from CVD file by skipping header, decompressing, and parsing signature files."""
        with open(file_path, 'rb') as f:
            header = f.read(512)
            if len(header) < 512:
                raise ValueError("File too small to be a valid CVD.")
            header_str = header.decode('utf-8', errors='ignore').strip()
            if not header_str.startswith('ClamAV-VDB'):
                raise ValueError("Invalid CVD file header.")
            data = f.read()

        # Decompress gzip
        try:
            gz_data = gzip.decompress(data)
        except OSError as e:
            raise ValueError(f"Failed to decompress: {e}")

        # Extract tar
        with tempfile.TemporaryDirectory() as tmp_dir:
            try:
                tar_io = io.BytesIO(gz_data)
                with tarfile.open(fileobj=tar_io) as tar:
                    tar.extractall(path=tmp_dir, filter='data')  # Use 'data' filter for safe extraction
            except tarfile.TarError as e:
                raise ValueError(f"Failed to extract tar: {e}")

            # Find and parse hash database files (.hdb, .mdb)
            hash_files = [f for f in os.listdir(tmp_dir) if f.endswith(('.hdb', '.mdb'))]
            total_files = len(hash_files)
            if total_files == 0:
                raise ValueError("No hash database files (.hdb/.mdb) found in CVD.")

            added_count = 0
            for i, hf in enumerate(hash_files):
                hf_path = os.path.join(tmp_dir, hf)
                with open(hf_path, 'r', encoding='latin1', errors='ignore') as f:
                    lines = f.readlines()
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split(':', 1)
                        hash_val = parts[0].lower()
                        if len(hash_val) == 32:  # MD5 hash
                            if hash_val not in self.virus_hashes:
                                self.virus_hashes.add(hash_val)
                                added_count += 1
                        else:
                            logging.warning(f"Invalid hash in {hf_path}: {hash_val}")
                self.progress['value'] = (i + 1) / total_files * 100
                self.root.update_idletasks()

            logging.debug(f"Added {added_count} new hashes from {total_files} files in {file_path}")

    def compute_hash(self, file_path):
        """Compute MD5 hash of a file (to match ClamAV hashes)."""
        md5_hash = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    md5_hash.update(chunk)
            hash_val = md5_hash.hexdigest().lower()
            logging.debug(f"Computed hash for {file_path}: {hash_val}")
            return hash_val
        except Exception as e:
            logging.error(f"Failed to compute hash for {file_path}: {str(e)}")
            return None

    def start_scan(self):
        """Start scanning in a background thread."""
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress.")
            return
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return

        self.scanning = True
        self.results_list.delete(0, tk.END)
        self.progress['value'] = 0
        self.current_label.config(text="")
        self.root.update_idletasks()

        threading.Thread(target=self.scan_folder, args=(folder,), daemon=True).start()

    def scan_folder(self, folder):
        """Scan a folder for viruses using multi-threading."""
        try:
            # Collect all files
            file_list = []
            for root_dir, _, files in os.walk(folder):
                for file in files:
                    file_list.append(os.path.join(root_dir, file))

            total_files = len(file_list)
            if total_files == 0:
                self.root.after(0, lambda: messagebox.showinfo("Results", "No files found!"))
                return

            logging.debug(f"Scanning {total_files} files in {folder}")
            detected = []
            processed = 0
            lock = threading.Lock()

            def process_file(file_path):
                nonlocal processed
                self.root.after(0, lambda p=file_path: self.current_label.config(text=f"Scanning: {p}"))
                file_hash = self.compute_hash(file_path)
                if file_hash:
                    logging.debug(f"Checking {file_path} with hash {file_hash}")
                    if file_hash in self.virus_hashes:
                        logging.info(f"Detected virus in {file_path}: {file_hash}")
                        self.detected_queue.put((file_path, file_hash))
                with lock:
                    processed += 1
                    self.root.after(0, lambda: self.progress.config(value=processed / total_files * 100))

            max_workers = max(1, os.cpu_count() - 1)  # Leave one thread free
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(process_file, fp) for fp in file_list]
                concurrent.futures.wait(futures)

            # Collect detected from queue
            while not self.detected_queue.empty():
                file_path, file_hash = self.detected_queue.get()
                detected.append(file_path)
                self.root.after(0, lambda fp=file_path, fh=file_hash: self.results_list.insert(tk.END, f"Detected: {fp} (Hash: {fh})"))

            if detected:
                self.root.after(0, lambda: messagebox.showwarning("Results", f"Found {len(detected)} suspicious files. Recommend deletion."))
            else:
                self.root.after(0, lambda: messagebox.showinfo("Results", "No viruses found!"))

            self.root.after(0, lambda: self.current_label.config(text=""))
            logging.debug(f"Scan completed: {len(detected)} viruses found")
        finally:
            self.scanning = False

    def delete_selected(self):
        """Delete selected files."""
        selected = self.results_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select files from the list.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected files?")
        if not confirm:
            return

        # Delete in reverse to avoid index issues
        for idx in sorted(selected, reverse=True):
            entry = self.results_list.get(idx)
            file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
            try:
                os.remove(file_path)
                self.results_list.delete(idx)
                logging.info(f"Deleted file: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {file_path}: {str(e)}")
                logging.error(f"Failed to delete {file_path}: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = OSAV(root)
    root.mainloop()