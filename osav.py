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
import time

# Configure logging with timestamp, level, and message format
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class OSAV:
    def __init__(self, root):
        # Initialize main window
        self.root = root
        self.root.title("OSAV - Open Source AntiVirus")
        self.root.geometry("600x600")
        self.root.configure(bg='#1e1e1e')

        # Initialize set for virus hashes and database file
        self.virus_hashes = set()
        self.db_file = "virus_hashes.txt"
        self.load_db()

        # Configure dark theme styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', background='#333333', foreground='white', borderwidth=0)
        self.style.configure('TLabel', background='#1e1e1e', foreground='white')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TProgressbar', troughcolor='#2e2e2e', background='#4CAF50')
        self.style.map('TButton', background=[('active', '#444444')])

        # Create main frame
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Create top frame for links
        self.top_frame = ttk.Frame(self.frame)
        self.top_frame.pack(fill=tk.X, pady=5)

        # Add Update Virus Database link
        self.update_link = ttk.Label(
            self.top_frame,
            text="Update Virus Database",
            font=('Arial', 8),
            foreground='#1E90FF',
            cursor="hand2"
        )
        self.update_link.pack(side=tk.LEFT)
        self.update_link.bind("<Button-1>", lambda e: webbrowser.open("https://clamwin.com/content/view/58/27/"))

        # Add Donate link
        self.donate_link = ttk.Label(
            self.top_frame,
            text="Donate",
            font=('Arial', 8),
            foreground='#1E90FF',
            cursor="hand2"
        )
        self.donate_link.pack(side=tk.RIGHT)
        self.donate_link.bind("<Button-1>", lambda e: webbrowser.open("https://buy.stripe.com/bIY5o70SSfam8Qo7ss"))

        # Add welcome label
        self.label = ttk.Label(self.frame, text="Welcome to OSAV", font=('Arial', 14))
        self.label.pack(pady=10)

        # Add label to display number of loaded hashes
        self.db_count_label = ttk.Label(self.frame, text=f"Loaded hashes: {len(self.virus_hashes)}", font=('Arial', 10))
        self.db_count_label.pack(pady=5)

        # Add button to import database
        self.import_btn = ttk.Button(self.frame, text="Import Database File (CVD/TXT)", command=self.start_import_db)
        self.import_btn.pack(pady=5)

        # Add button to scan folder
        self.scan_btn = ttk.Button(self.frame, text="Scan Folder", command=self.start_scan)
        self.scan_btn.pack(pady=5)

        # Add progress bar
        self.progress = ttk.Progressbar(self.frame, orient='horizontal', length=300, mode='determinate')
        self.progress.pack(pady=10)

        # Add label for current file path
        self.current_label = ttk.Label(self.frame, text="", font=('Arial', 8))
        self.current_label.pack(pady=2)

        # Add label for file size
        self.size_label = ttk.Label(self.frame, text="", font=('Arial', 8))
        self.size_label.pack(pady=2)

        # Add listbox for scan results (height reduced by 1)
        self.results_list = tk.Listbox(self.frame, bg='#2e2e2e', fg='white', font=('Arial', 10), height=9)
        self.results_list.pack(fill=tk.BOTH, expand=True, pady=10)

        # Create frame for buttons below results list
        self.button_frame = ttk.Frame(self.frame)
        self.button_frame.pack(fill=tk.X, pady=5)

        # Add button to delete selected files
        self.delete_btn = ttk.Button(self.button_frame, text="Delete Selected", command=self.delete_selected)
        self.delete_btn.pack(side=tk.LEFT, padx=5)

        # Add button to extract detections
        self.extract_btn = ttk.Button(self.button_frame, text="Extract Detections", command=self.extract_detections)
        self.extract_btn.pack(side=tk.LEFT, padx=5)

        # Add button to delete all detections
        self.delete_all_btn = ttk.Button(self.button_frame, text="Delete All Detections", command=self.delete_all_detections)
        self.delete_all_btn.pack(side=tk.LEFT, padx=5)

        # Initialize state variables
        self.scanning = False
        self.importing = False
        self.detected_queue = queue.Queue()
        self.use_all_hashes = True  # Toggle to False to compute only MD5 for speed test

    def load_db(self):
        # Load hashes from virus_hashes.txt, accepting MD5 (32), SHA1 (40), or SHA256 (64) chars
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                self.virus_hashes = set(
                    line.strip().lower() 
                    for line in f 
                    if line.strip() and len(line.strip().lower()) in (32, 40, 64) and all(c in '0123456789abcdef' for c in line.strip().lower())
                )
            logging.debug(f"Loaded {len(self.virus_hashes)} hashes from {self.db_file}")
            if len(self.virus_hashes) == 0:
                logging.warning(f"No valid MD5/SHA1/SHA256 hashes found in {self.db_file}")
        self.save_db()

    def save_db(self):
        # Save unique hashes to virus_hashes.txt
        with open(self.db_file, 'w') as f:
            for h in sorted(self.virus_hashes):
                f.write(h + '\n')
        logging.debug(f"Saved {len(self.virus_hashes)} hashes to {self.db_file}")

    def start_import_db(self):
        # Start database import in a background thread
        if self.importing:
            messagebox.showwarning("Warning", "Import already in progress.")
            return
        file_path = filedialog.askopenfilename(title="Select Database File", filetypes=[("Database Files", "*.cvd *.txt")])
        if not file_path:
            return

        self.importing = True
        self.progress['value'] = 0
        self.current_label.config(text="Importing database...")
        self.size_label.config(text="")
        self.root.update_idletasks()

        threading.Thread(target=self.import_db, args=(file_path,), daemon=True).start()

    def import_db(self, file_path):
        # Import hashes from CVD or TXT file
        try:
            if file_path.lower().endswith('.txt'):
                self.import_txt(file_path)
            elif file_path.lower().endswith('.cvd'):
                self.import_cvd(file_path)
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Unsupported file type. Use .cvd or .txt."))
                return

            self.save_db()
            self.root.after(0, lambda: self.db_count_label.config(text=f"Loaded hashes: {len(self.virus_hashes)}"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Database updated! Now has {len(self.virus_hashes)} hashes."))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to import: {str(e)}"))
            logging.error(f"Import failed: {str(e)}")
        finally:
            self.importing = False
            self.root.after(0, lambda: self.progress.config(value=100))
            self.root.after(0, lambda: self.current_label.config(text=""))
            self.root.after(0, lambda: self.size_label.config(text=""))

    def import_txt(self, file_path):
        # Import hashes from TXT file, counting MD5, SHA1, SHA256
        with open(file_path, 'r') as f:
            lines = f.readlines()
            total = len(lines)
            invalid_count = 0
            invalid_samples = []
            md5_count = sha1_count = sha256_count = 0
            for i, line in enumerate(lines):
                hash_val = line.strip().lower()
                if len(hash_val) in (32, 40, 64) and all(c in '0123456789abcdef' for c in hash_val):
                    self.virus_hashes.add(hash_val)
                    if len(hash_val) == 32:
                        md5_count += 1
                    elif len(hash_val) == 40:
                        sha1_count += 1
                    elif len(hash_val) == 64:
                        sha256_count += 1
                else:
                    invalid_count += 1
                    if len(invalid_samples) < 5:
                        invalid_samples.append(hash_val)
                self.root.after(0, lambda val=(i + 1) / total * 100: self.progress.config(value=val))
            if invalid_count > 0:
                logging.warning(f"Skipped {invalid_count} invalid hashes in {file_path}. Sample invalid entries: {invalid_samples[:5]}")
            logging.debug(f"Imported from {file_path}: {md5_count} MD5, {sha1_count} SHA1, {sha256_count} SHA256 hashes")

    def import_cvd(self, file_path):
        # Import hashes from CVD file, processing .hdb, .hsb, .msb files
        with open(file_path, 'rb') as f:
            header = f.read(512)
            if len(header) < 512:
                raise ValueError("File too small to be a valid CVD.")
            header_str = header.decode('utf-8', errors='ignore').strip()
            if not header_str.startswith('ClamAV-VDB'):
                raise ValueError("Invalid CVD file header.")
            data = f.read()

        # Decompress gzip data
        try:
            gz_data = gzip.decompress(data)
        except OSError as e:
            raise ValueError(f"Failed to decompress: {e}")

        # Extract tar to temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            try:
                tar_io = io.BytesIO(gz_data)
                with tarfile.open(fileobj=tar_io) as tar:
                    tar.extractall(path=tmp_dir, filter='data')
            except tarfile.TarError as e:
                raise ValueError(f"Failed to extract tar: {e}")

            # Find hash database files
            hash_files = [f for f in os.listdir(tmp_dir) if f.endswith(('.hdb', '.hsb', '.msb'))]
            total_files = len(hash_files)
            if total_files == 0:
                raise ValueError("No hash database files (.hdb, .hsb, .msb) found in CVD.")

            # Process each hash file
            added_count = 0
            invalid_count = 0
            invalid_samples = []
            md5_count = sha1_count = sha256_count = 0
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
                        if len(hash_val) in (32, 40, 64) and all(c in '0123456789abcdef' for c in hash_val):
                            if hash_val not in self.virus_hashes:
                                self.virus_hashes.add(hash_val)
                                added_count += 1
                                if len(hash_val) == 32:
                                    md5_count += 1
                                elif len(hash_val) == 40:
                                    sha1_count += 1
                                elif len(hash_val) == 64:
                                    sha256_count += 1
                        else:
                            invalid_count += 1
                            if len(invalid_samples) < 5:
                                invalid_samples.append(hash_val)
                self.root.after(0, lambda val=(i + 1) / total_files * 100: self.progress.config(value=val))
            if invalid_count > 0:
                logging.warning(f"Skipped {invalid_count} invalid hashes in {file_path}. Sample invalid entries: {invalid_samples[:5]}")
            logging.debug(f"Imported from {file_path}: {md5_count} MD5, {sha1_count} SHA1, {sha256_count} SHA256 hashes, total added: {added_count}")

    def compute_hash(self, file_path):
        # Compute MD5, SHA1, and SHA256 hashes, or only MD5 if use_all_hashes is False
        if self.use_all_hashes:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        md5_hash.update(chunk)
                        sha1_hash.update(chunk)
                        sha256_hash.update(chunk)
                hashes = {
                    'md5': md5_hash.hexdigest().lower(),
                    'sha1': sha1_hash.hexdigest().lower(),
                    'sha256': sha256_hash.hexdigest().lower()
                }
                logging.debug(f"Computed hashes for {file_path}: MD5={hashes['md5']}, SHA1={hashes['sha1']}, SHA256={hashes['sha256']}")
                return hashes
            except Exception as e:
                logging.error(f"Failed to compute hashes for {file_path}: {str(e)}")
                return None
        else:
            md5_hash = hashlib.md5()
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        md5_hash.update(chunk)
                hash_val = md5_hash.hexdigest().lower()
                logging.debug(f"Computed MD5 hash for {file_path}: {hash_val}")
                return {'md5': hash_val}
            except Exception as e:
                logging.error(f"Failed to compute MD5 hash for {file_path}: {str(e)}")
                return None

    def start_scan(self):
        # Start folder scan in a background thread
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress.")
            return
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return

        logging.debug(f"Starting scan with {len(self.virus_hashes)} hashes in DB")
        self.scanning = True
        self.results_list.delete(0, tk.END)
        self.progress['value'] = 0
        self.current_label.config(text="")
        self.size_label.config(text="")
        self.root.update_idletasks()

        threading.Thread(target=self.scan_folder, args=(folder,), daemon=True).start()

    def scan_folder(self, folder):
        # Scan folder for viruses using multi-threading
        start_time = time.time()
        try:
            # Collect all files in folder
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
                # Get file size and update labels with full path and size
                try:
                    file_size = os.path.getsize(file_path)
                    size_str = f"Size: {file_size:,} bytes"
                except:
                    size_str = "Size: Unknown"
                self.root.after(0, lambda p=file_path, s=size_str: (self.current_label.config(text=f"Scanning: {p}"), self.size_label.config(text=s)))
                hashes = self.compute_hash(file_path)
                if hashes:
                    for hash_type, hash_val in hashes.items():
                        if hash_val in self.virus_hashes:
                            logging.info(f"Detected virus in {file_path}: {hash_type.upper()}={hash_val}")
                            self.detected_queue.put((file_path, hash_val, file_size))
                with lock:
                    processed += 1
                    self.root.after(0, lambda: self.progress.config(value=processed / total_files * 100))

            # Use multi-threading for scanning
            max_workers = max(1, os.cpu_count() - 1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(process_file, fp) for fp in file_list]
                concurrent.futures.wait(futures)

            # Collect detected files from queue
            while not self.detected_queue.empty():
                file_path, file_hash, file_size = self.detected_queue.get()
                detected.append(file_path)
                self.root.after(0, lambda fp=file_path, fh=file_hash: self.results_list.insert(tk.END, f"Detected: {fp} (Hash: {fh})"))

            # Show scan results
            if detected:
                self.root.after(0, lambda: messagebox.showwarning("Results", f"Found {len(detected)} suspicious files. Recommend deletion."))
            else:
                self.root.after(0, lambda: messagebox.showinfo("Results", "No viruses found!"))

            self.root.after(0, lambda: self.current_label.config(text=""))
            self.root.after(0, lambda: self.size_label.config(text=""))
            end_time = time.time()
            logging.debug(f"Scan completed: {len(detected)} viruses found in {end_time - start_time:.2f} seconds")
        finally:
            self.scanning = False

    def extract_detections(self):
        # Export detected files to detections.txt
        if not self.results_list.size():
            messagebox.showwarning("Warning", "No detections to export.")
            return

        detections_file = os.path.join(os.path.dirname(self.db_file), "detections.txt")
        try:
            with open(detections_file, 'w', encoding='utf-8') as f:
                for i in range(self.results_list.size()):
                    entry = self.results_list.get(i)
                    file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
                    file_hash = entry.split(" (Hash:")[1].rstrip(")")
                    try:
                        file_size = os.path.getsize(file_path)
                        size_str = f"{file_size:,} bytes"
                    except:
                        size_str = "Unknown"
                    f.write(f"File: {file_path}\nHash: {file_hash}\nSize: {size_str}\n\n")
            messagebox.showinfo("Success", f"Detections exported to {detections_file}")
            logging.info(f"Exported {self.results_list.size()} detections to {detections_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export detections: {str(e)}")
            logging.error(f"Failed to export detections to {detections_file}: {str(e)}")

    def delete_selected(self):
        # Delete selected files from results list
        selected = self.results_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select files from the list.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected files?")
        if not confirm:
            return

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

    def delete_all_detections(self):
        # Delete all files in the results list
        if not self.results_list.size():
            messagebox.showwarning("Warning", "No detections to delete.")
            return

        confirm = messagebox.askyesno("Confirmation", f"Are you sure you want to delete all {self.results_list.size()} detected files?")
        if not confirm:
            return

        for i in range(self.results_list.size() - 1, -1, -1):
            entry = self.results_list.get(i)
            file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
            try:
                os.remove(file_path)
                self.results_list.delete(i)
                logging.info(f"Deleted file: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {file_path}: {str(e)}")
                logging.error(f"Failed to delete {file_path}: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = OSAV(root)
    root.mainloop()