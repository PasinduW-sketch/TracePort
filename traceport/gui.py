"""Tkinter-based GUI for TracePort scanner."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Optional
import logging

from traceport.scanner import PortScanner
from traceport.models import ScanResult
from traceport.utils import is_valid_port_range, parse_port_range

logger = logging.getLogger(__name__)

class TracePortGUI:
    """Tkinter GUI application for port scanning."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("TracePort - Network Port Scanner")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        self.scanner: Optional[PortScanner] = None
        self.scan_result: Optional[ScanResult] = None
        self.scanning = False
        self._setup_styles()
        self._create_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

    def _create_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        title = ttk.Label(main_frame, text="TracePort Network Port Scanner", font=('Arial', 14, 'bold'))
        title.pack(pady=10)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Scan")
        self._create_scan_tab()

        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Results")
        self._create_results_tab()

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(10, 0))

    def _create_scan_tab(self):
        frame = ttk.Frame(self.scan_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Target Configuration", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=10)

        ttk.Label(frame, text="Target Host/IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(frame, textvariable=self.target_var, width=40)
        self.target_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.target_entry.insert(0, "localhost")

        ttk.Label(frame, text="Port Configuration", font=('Arial', 12, 'bold')).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(20, 10))

        self.port_mode_var = tk.StringVar(value="common")
        ttk.Radiobutton(frame, text="Scan Common Ports", variable=self.port_mode_var, value="common", command=self._port_mode_changed).grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Radiobutton(frame, text="Custom Port Range", variable=self.port_mode_var, value="custom", command=self._port_mode_changed).grid(row=4, column=0, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Port Range:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.port_var = tk.StringVar()
        self.port_entry = ttk.Entry(frame, textvariable=self.port_var, width=40)
        self.port_entry.grid(row=5, column=1, sticky=tk.EW, pady=5)
        self.port_entry.insert(0, "1-1000")
        self.port_entry.config(state=tk.DISABLED)

        ttk.Label(frame, text="Max Threads:", font=('Arial', 10)).grid(row=6, column=0, sticky=tk.W, pady=5)
        self.threads_var = tk.IntVar(value=100)
        ttk.Spinbox(frame, from_=1, to=500, textvariable=self.threads_var, width=10).grid(row=6, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Timeout (seconds):", font=('Arial', 10)).grid(row=7, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.IntVar(value=3)
        ttk.Spinbox(frame, from_=1, to=30, textvariable=self.timeout_var, width=10).grid(row=7, column=1, sticky=tk.W, pady=5)

        self.banner_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Enable Banner Grabbing", variable=self.banner_var).grid(row=8, column=0, columnspan=2, sticky=tk.W, pady=5)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=9, column=0, columnspan=2, sticky=tk.EW, pady=(20, 10))

        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self._stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Progress:", font=('Arial', 10)).grid(row=10, column=0, columnspan=2, sticky=tk.W, pady=(20, 10))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=11, column=0, columnspan=2, sticky=tk.EW, pady=5)

        self.progress_label = ttk.Label(frame, text="0/0 ports")
        self.progress_label.grid(row=12, column=0, columnspan=2, sticky=tk.W, pady=5)

        frame.columnconfigure(1, weight=1)

    def _create_results_tab(self):
        frame = ttk.Frame(self.results_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Scan Summary", font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=10)

        summary_frame = ttk.LabelFrame(frame, text="Target Information", padding=10)
        summary_frame.pack(fill=tk.X, pady=10)

        self.summary_text = tk.Text(summary_frame, height=6, width=60)
        self.summary_text.pack(fill=tk.X)
        self.summary_text.config(state=tk.DISABLED)

        ttk.Label(frame, text="Open Ports & Services", font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=10)

        columns = ('Port', 'Service', 'Version', 'Banner')
        self.results_tree = ttk.Treeview(frame, columns=columns, height=15, show='headings')

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)

        self.results_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        export_frame = ttk.Frame(frame)
        export_frame.pack(fill=tk.X, pady=10)

        ttk.Button(export_frame, text="Export JSON", command=self._export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Export CSV", command=self._export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Clear Results", command=self._clear_results).pack(side=tk.LEFT, padx=5)

    def _port_mode_changed(self):
        if self.port_mode_var.get() == "common":
            self.port_entry.config(state=tk.DISABLED)
        else:
            self.port_entry.config(state=tk.NORMAL)

    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target host or IP address")
            return

        ports = None
        if self.port_mode_var.get() == "custom":
            port_range = self.port_var.get().strip()
            if not is_valid_port_range(port_range):
                messagebox.showerror("Error", "Invalid port range format")
                return
            ports = parse_port_range(port_range)

        self.scanner = PortScanner(
            max_threads=self.threads_var.get(),
            timeout=self.timeout_var.get(),
            banner_grab=self.banner_var.get()
        )
        self.scanner.set_progress_callback(self._update_progress)

        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.target_entry.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.DISABLED)

        scan_thread = threading.Thread(target=self._scan_thread, args=(target, ports))
        scan_thread.daemon = True
        scan_thread.start()

    def _scan_thread(self, target: str, ports=None):
        try:
            self.status_var.set(f"Scanning {target}...")
            self.scan_result = self.scanner.scan(target, ports=ports)
            self._display_results()
            self.status_var.set("Scan completed")
        except Exception as e:
            self.status_var.set(f"Scan failed: {str(e)}")
            messagebox.showerror("Scan Error", str(e))
        finally:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.target_entry.config(state=tk.NORMAL)
            if self.port_mode_var.get() != "common":
                self.port_entry.config(state=tk.NORMAL)
            self.progress_var.set(0)

    def _stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.status_var.set("Scan stopped")

    def _update_progress(self, completed: int, total: int):
        if total > 0:
            progress = (completed / total) * 100
            self.progress_var.set(progress)
            self.progress_label.config(text=f"{completed}/{total} ports")
            self.root.update_idletasks()

    def _display_results(self):
        if not self.scan_result:
            return

        summary = f"""Target: {self.scan_result.target}
IP Address: {self.scan_result.ip_address or 'N/A'}
Hostname: {self.scan_result.hostname or 'N/A'}
Open Ports: {self.scan_result.open_ports_count}
Ports Scanned: {self.scan_result.total_ports_scanned}
Duration: {self.scan_result.scan_duration:.2f}s
Status: {self.scan_result.status}"""

        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, summary)
        self.summary_text.config(state=tk.DISABLED)

        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        for service in self.scan_result.services:
            values = (
                service.port,
                service.service_name or "unknown",
                service.version or "-",
                service.banner[:50] + "..." if service.banner and len(service.banner) > 50 else service.banner or "-"
            )
            self.results_tree.insert('', tk.END, values=values)

        self.notebook.select(self.results_tab)

    def _export_json(self):
        if not self.scan_result:
            messagebox.showwarning("Warning", "No results to export")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.scan_result.to_json())
            messagebox.showinfo("Success", f"Results exported to {file_path}")

    def _export_csv(self):
        if not self.scan_result:
            messagebox.showwarning("Warning", "No results to export")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write("Port,Service,Version,Banner\n")
                for service in self.scan_result.services:
                    banner = service.banner.replace('"', '""') if service.banner else ""
                    f.write(f'{service.port},"{service.service_name or "unknown"}","{service.version or ""}","{banner}"\n')
            messagebox.showinfo("Success", f"Results exported to {file_path}")

    def _clear_results(self):
        self.scan_result = None
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.config(state=tk.DISABLED)
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.status_var.set("Ready")

def main():
    root = tk.Tk()
    app = TracePortGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
