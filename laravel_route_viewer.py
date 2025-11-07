#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laravel Route Viewer – List & Secure Laravel Routes
Full standalone GUI application with CLI support
Author: T4Z4r | Date: 2025-11-07
"""

import os
import json
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import webbrowser
from datetime import datetime
import argparse
import csv
import sys

class LaravelRouteViewer:
    def __init__(self, root, dark_theme=False):
        self.root = root
        self.root.title("Laravel Route Viewer")
        self.root.geometry("1280x760")
        self.root.minsize(1000, 600)
        self.dark_theme = dark_theme
        self.root.configure(bg="#f5f5f5" if not dark_theme else "#2b2b2b")

        self.app_path = tk.StringVar()
        self.routes_data = []
        self.findings = []
        self.auto_refresh = False
        self.refresh_interval = 30000  # 30 seconds

        self.setup_ui()
        self.create_reports_dir()

    def create_reports_dir(self):
        Path("reports").mkdir(exist_ok=True)

    def get_route_methods(self, route):
        method_data = route.get("method", {})
        if isinstance(method_data, str):
            return [method_data] if method_data != "HEAD" else []
        elif isinstance(method_data, dict):
            return [m for m in method_data.get("methods", []) if m != "HEAD"]
        else:
            return []

    def setup_ui(self):
        # === Header ===
        header = ttk.Frame(self.root, padding="15")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Laravel Project Path:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Entry(header, textvariable=self.app_path, width=70).grid(row=0, column=1, padx=(8,8), sticky="ew")
        ttk.Button(header, text="Browse", command=self.browse_folder).grid(row=0, column=2, padx=(0,5))
        ttk.Button(header, text="View & Scan Routes", command=self.scan_routes, style="Accent.TButton").grid(row=0, column=3, padx=5)
        ttk.Button(header, text="Export Report", command=self.export_report).grid(row=0, column=4, padx=5)

        # Dark theme toggle
        self.theme_var = tk.BooleanVar(value=self.dark_theme)
        ttk.Checkbutton(header, text="Dark Theme", variable=self.theme_var, command=self.toggle_theme).grid(row=0, column=5, padx=5)

        # Auto-refresh toggle
        self.auto_refresh_var = tk.BooleanVar(value=self.auto_refresh)
        ttk.Checkbutton(header, text="Auto-refresh", variable=self.auto_refresh_var, command=self.toggle_auto_refresh).grid(row=0, column=6, padx=5)

        # === Notebook ===
        self.notebook = ttk.Notebook(self.root)
        self.tab_routes = ttk.Frame(self.notebook)
        self.tab_report = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_routes, text="Routes")
        self.notebook.add(self.tab_report, text="Security Report")
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=15, pady=10)
        self.root.rowconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)

        # === Routes Table ===
        self.setup_routes_table()

        # === Report View ===
        bg_color = "white" if not self.dark_theme else "#1e1e1e"
        fg_color = "black" if not self.dark_theme else "#ffffff"
        self.report_text = tk.Text(self.tab_report, wrap="word", font=("Consolas", 10), bg=bg_color, fg=fg_color)
        vsb = ttk.Scrollbar(self.tab_report, orient="vertical", command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=vsb.set)
        self.report_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.tab_report.rowconfigure(0, weight=1)
        self.tab_report.columnconfigure(0, weight=1)

        # === Status Bar ===
        self.status = ttk.Label(self.root, text="Ready. Select a Laravel project.", relief="sunken", anchor="w", padding=5)
        self.status.grid(row=2, column=0, sticky="ew")

        # Style
        style = ttk.Style()
        if self.dark_theme:
            style.configure("Accent.TButton", foreground="white", background="#1976d2")
            style.map("Accent.TButton", background=[("active", "#0d47a1")])
            style.configure("TFrame", background="#2b2b2b")
            style.configure("TLabel", background="#2b2b2b", foreground="#ffffff")
            style.configure("TCheckbutton", background="#2b2b2b", foreground="#ffffff")
            style.configure("Treeview", background="#1e1e1e", foreground="#ffffff", fieldbackground="#1e1e1e")
            style.configure("Treeview.Heading", background="#3c3c3c", foreground="#ffffff")
            style.configure("TNotebook", background="#2b2b2b")
            style.configure("TNotebook.Tab", background="#3c3c3c", foreground="#ffffff")
            style.map("TNotebook.Tab", background=[("selected", "#1e1e1e")])
        else:
            style.configure("Accent.TButton", foreground="black", background="#1976d2")
            style.map("Accent.TButton", background=[("active", "#0d47a1")])
            style.configure("TFrame", background="#f5f5f5")
            style.configure("TLabel", background="#f5f5f5", foreground="#000000")
            style.configure("TCheckbutton", background="#f5f5f5", foreground="#000000")
            style.configure("Treeview", background="#ffffff", foreground="#000000", fieldbackground="#ffffff")
            style.configure("Treeview.Heading", background="#f0f0f0", foreground="#000000")
            style.configure("TNotebook", background="#f5f5f5")
            style.configure("TNotebook.Tab", background="#e0e0e0", foreground="#000000")
            style.map("TNotebook.Tab", background=[("selected", "#ffffff")])

    def setup_routes_table(self):
        columns = ("risk", "method", "uri", "name", "action", "issue")
        self.tree = ttk.Treeview(self.tab_routes, columns=columns, show="headings", selectmode="browse")
        
        vsb = ttk.Scrollbar(self.tab_routes, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.tab_routes, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Headers
        self.tree.heading("risk", text="Risk", anchor="center")
        self.tree.heading("method", text="Method")
        self.tree.heading("uri", text="URI")
        self.tree.heading("name", text="Name")
        self.tree.heading("action", text="Action")
        self.tree.heading("issue", text="Security Issue")

        # Column widths
        self.tree.column("risk", width=70, anchor="center")
        self.tree.column("method", width=100)
        self.tree.column("uri", width=320)
        self.tree.column("name", width=220)
        self.tree.column("action", width=300)
        self.tree.column("issue", width=380)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.tab_routes.rowconfigure(0, weight=1)
        self.tab_routes.columnconfigure(0, weight=1)

        # Color tags
        if self.dark_theme:
            self.tree.tag_configure("high", background="#4a2c2c", foreground="#ff6b6b")
            self.tree.tag_configure("medium", background="#4a3c2c", foreground="#ffb74d")
            self.tree.tag_configure("low", background="#2c4a2c", foreground="#81c784")
            self.tree.tag_configure("safe", foreground="#4caf50")
        else:
            self.tree.tag_configure("high", background="#ffcdd2", foreground="#b71c1c")
            self.tree.tag_configure("medium", background="#fff8e1", foreground="#ff8f00")
            self.tree.tag_configure("low", background="#e8f5e9", foreground="#2e7d32")
            self.tree.tag_configure("safe", foreground="#1b5e20")

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Laravel Project Root")
        if folder:
            self.app_path.set(folder)
            self.validate_project(folder)

    def validate_project(self, path):
        artisan = Path(path) / "artisan"
        if artisan.exists():
            self.status.config(text=f"Valid Laravel project: {path}")
        else:
            self.status.config(text="Warning: 'artisan' not found! Not a Laravel app?")

    def scan_routes(self):
        path = self.app_path.get().strip()
        if not path:
            messagebox.showwarning("No Path", "Please select a Laravel project folder.")
            return
        artisan_path = Path(path) / "artisan"
        if not artisan_path.exists():
            messagebox.showerror("Invalid", "'artisan' not found. Select a valid Laravel project.")
            return

        self.status.config(text="Fetching routes via php artisan route:list --json...")
        self.root.update_idletasks()

        try:
            result = subprocess.run(
                ["php", "artisan", "route:list", "--json"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=45,
                check=False
            )

            if result.returncode != 0:
                self.status.config(text="Artisan failed, attempting manual crawl...")
                self.root.update_idletasks()
                self.manual_scan_routes(path)
                return

            try:
                self.routes_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                messagebox.showerror("JSON Parse Error", f"Invalid JSON:\n{e}\n\nFirst 300 chars:\n{result.stdout[:300]}")
                return

            self.findings = self.analyze_routes(self.routes_data)
            self.display_routes()
            self.generate_html_report()
            count = len(self.findings)
            self.status.config(text=f"Scan complete: {len(self.routes_data)} routes, {count} issue(s) found.")

        except FileNotFoundError:
            messagebox.showerror("PHP Missing", "PHP CLI not found. Install PHP and ensure 'php' is in PATH.")
        except subprocess.TimeoutExpired:
            messagebox.showerror("Timeout", "Artisan took too long. Check project boot.")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error:\n{e}")

    def manual_scan_routes(self, path):
        self.status.config(text="Performing manual route crawl...")
        self.root.update_idletasks()

        routes_dir = Path(path) / "routes"
        if not routes_dir.exists():
            messagebox.showerror("No Routes", "No 'routes' directory found. Cannot perform manual crawl.")
            self.status.config(text="Manual crawl failed: no routes directory.")
            return

        self.routes_data = []
        try:
            for route_file in routes_dir.glob("*.php"):
                if route_file.is_file():
                    self.parse_route_file(route_file)
        except Exception as e:
            messagebox.showerror("Manual Crawl Error", f"Error during manual crawl:\n{e}")
            self.status.config(text="Manual crawl failed.")
            return

        if not self.routes_data:
            messagebox.showwarning("No Routes", "No routes found in route files.")
            self.status.config(text="Manual crawl found no routes.")
            return

        self.findings = self.analyze_routes(self.routes_data)
        self.display_routes()
        self.generate_html_report()
        count = len(self.findings)
        self.status.config(text=f"Manual scan complete: {len(self.routes_data)} routes, {count} issue(s) found.")

    def parse_route_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return

        # Regex patterns for Laravel route definitions
        import re

        # Extract route group prefix if any
        prefix_match = re.search(r"Route::prefix\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*->\s*group\s*\(\s*function\s*\(\s*\)\s*\{", content, re.IGNORECASE | re.DOTALL)
        prefix = prefix_match.group(1) if prefix_match else ""

        # Split content into lines for better parsing
        lines = content.split('\n')
        route_definitions = []

        # Find route definitions with their line numbers
        for i, line in enumerate(lines):
            # Look for Route::method calls
            route_match = re.search(r"Route::(get|post|put|patch|delete|options|any)\s*\(\s*['\"]([^'\"]+)['\"]\s*,", line, re.IGNORECASE)
            if route_match:
                method, uri = route_match.groups()
                # Apply prefix if exists
                full_uri = f"{prefix}/{uri}".lstrip('/') if prefix else uri

                # Look for ->name() in the current line and subsequent lines
                name = ""
                # Check current line first
                name_match = re.search(r"->name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", line, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                else:
                    # Check next few lines for chained methods
                    for j in range(1, min(5, len(lines) - i)):  # Look up to 5 lines ahead
                        next_line = lines[i + j].strip()
                        name_match = re.search(r"->name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", next_line, re.IGNORECASE)
                        if name_match:
                            name = name_match.group(1)
                            break
                        # Stop if we hit a semicolon or another Route:: call
                        if ';' in next_line or re.search(r"Route::", next_line):
                            break

                # Create a basic route dict similar to artisan output
                route = {
                    "method": {"methods": [method.upper()]},
                    "uri": full_uri,
                    "name": name,
                    "action": "Closure",  # Default, could be improved
                    "middleware": []  # Default, could be improved
                }
                self.routes_data.append(route)

    def analyze_routes(self, routes):
        findings = []
        for route in routes:
            uri = route.get("uri", "").strip()
            methods = self.get_route_methods(route)
            name = route.get("name", "") or "(none)"
            action = route.get("action", "") or "Closure"
            middleware = [m.lower() for m in route.get("middleware", [])]

            issues = []
            severity = "safe"

            # 1. CSRF Missing
            if any(m in ["POST", "PUT", "PATCH", "DELETE"] for m in methods):
                if "web" not in middleware and "csrf" not in " ".join(middleware):
                    issues.append("CSRF protection missing (use web middleware)")
                    severity = "high"

            # 2. Debug Tools Exposed
            debug_paths = ["telescope", "horizon", "_ignition", "debugbar", "phpinfo"]
            if any(p in uri.lower() for p in debug_paths):
                issues.append("Debug/tool endpoint exposed in production")
                severity = "high"

            # 3. Unauthenticated API
            if uri.startswith("api/"):
                auth_missing = all(a not in " ".join(middleware) for a in ["auth", "sanctum", "jwt"])
                if auth_missing and any(m in ["POST", "PUT", "PATCH", "DELETE"] for m in methods):
                    issues.append("Unauthenticated API write access")
                    severity = "high"
                elif auth_missing and "GET" in methods:
                    issues.append("Unauthenticated API read access")
                    severity = "medium"

            # 4. Admin Panel Unprotected
            admin_keywords = ["admin", "panel", "dashboard", "cpanel"]
            if any(k in uri.lower() for k in admin_keywords) and "auth" not in " ".join(middleware):
                issues.append("Admin route lacks authentication")
                severity = "high"

            # 5. File Upload Risk
            if "upload" in uri.lower() and "POST" in methods:
                issues.append("File upload – enforce MIME, size, and storage validation")
                severity = "medium"

            # 6. Mass Assignment
            if "Controller" in action and any(m in ["POST", "PUT"] for m in methods):
                issues.append("Potential mass assignment – use $fillable/$guarded")
                severity = "medium"

            if issues:
                findings.append({
                    "route": route,
                    "methods": "|".join(methods),
                    "uri": uri,
                    "name": name,
                    "action": action.replace("App\\", "", 1) if action.startswith("App\\") else action,
                    "issues": "; ".join(issues),
                    "severity": severity
                })

        return findings

    def display_routes(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        for f in self.findings:
            r = f["route"]
            tag = f["severity"]
            risk_label = "HIGH" if tag == "high" else "MED" if tag == "medium" else "LOW"
            self.tree.insert("", "end", values=(
                risk_label,
                f["methods"],
                r["uri"],
                r["name"] or "(none)",
                f["action"],
                f["issues"]
            ), tags=(tag,))

        # Add safe routes
        risky_uris = {f["route"]["uri"]: True for f in self.findings}
        for route in self.routes_data:
            if route["uri"] not in risky_uris:
                methods = "|".join(self.get_route_methods(route))
                action = route["action"].replace("App\\", "", 1) if route["action"].startswith("App\\") else route["action"]
                self.tree.insert("", "end", values=(
                    "OK", methods, route["uri"], route["name"] or "(none)", action, "(secure)"
                ), tags=("safe",))

    def generate_html_report(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        high = [f for f in self.findings if f["severity"] == "high"]
        medium = [f for f in self.findings if f["severity"] == "medium"]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Laravel Route Viewer Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f9f9f9; }}
        h1 {{ color: #1976d2; }}
        .summary {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .high {{ background: #ffcdd2; border-left: 6px solid #f44336; }}
        .medium {{ background: #fff8e1; border-left: 6px solid #ff9800; }}
        .card {{ padding: 15px; margin: 10px 0; border-radius: 6px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #f5f5f5; }}
        .footer {{ margin-top: 50px; font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <h1>Laravel Route Viewer Report</h1>
    <div class="summary">
        <p><strong>Project:</strong> {self.app_path.get()}</p>
        <p><strong>Scanned:</strong> {len(self.routes_data)} routes</p>
        <p><strong>Issues:</strong> {len(high)} High, {len(medium)} Medium</p>
        <p><strong>Time:</strong> {timestamp}</p>
    </div>

    <h2>High Risk Findings</h2>
"""
        for f in high:
            html += f"<div class='card high'><strong>{f['methods']} {f['uri']}</strong><br>{f['issues']}</div>"

        html += "<h2>Medium Risk</h2>"
        for f in medium:
            html += f"<div class='card medium'><strong>{f['methods']} {f['uri']}</strong><br>{f['issues']}</div>"

        html += "<h2>All Findings</h2><table><tr><th>Risk</th><th>Method</th><th>URI</th><th>Name</th><th>Action</th><th>Issue</th></tr>"
        for f in self.findings:
            risk = "HIGH" if f["severity"] == "high" else "MEDIUM"
            html += f"<tr><td>{risk}</td><td>{f['methods']}</td><td>{f['uri']}</td><td>{f['name']}</td><td>{f['action']}</td><td>{f['issues']}</td></tr>"
        html += "</table><div class='footer'>Generated by <strong>Laravel Route Viewer</strong></div></body></html>"

        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, html)

    def toggle_theme(self):
        self.dark_theme = self.theme_var.get()
        self.apply_theme()

    def apply_theme(self):
        bg_color = "#f5f5f5" if not self.dark_theme else "#2b2b2b"
        self.root.configure(bg=bg_color)

        # Update status bar background
        status_bg = "#e0e0e0" if not self.dark_theme else "#1e1e1e"
        status_fg = "#000000" if not self.dark_theme else "#ffffff"
        self.status.configure(bg=status_bg, fg=status_fg)

        # Update report text colors
        bg_text = "white" if not self.dark_theme else "#1e1e1e"
        fg_text = "black" if not self.dark_theme else "#ffffff"
        self.report_text.configure(bg=bg_text, fg=fg_text)

        # Update tree colors
        if self.dark_theme:
            self.tree.tag_configure("high", background="#4a2c2c", foreground="#ff6b6b")
            self.tree.tag_configure("medium", background="#4a3c2c", foreground="#ffb74d")
            self.tree.tag_configure("low", background="#2c4a2c", foreground="#81c784")
            self.tree.tag_configure("safe", foreground="#4caf50")
        else:
            self.tree.tag_configure("high", background="#ffcdd2", foreground="#b71c1c")
            self.tree.tag_configure("medium", background="#fff8e1", foreground="#ff8f00")
            self.tree.tag_configure("low", background="#e8f5e9", foreground="#2e7d32")
            self.tree.tag_configure("safe", foreground="#1b5e20")

        # Update notebook tabs
        style = ttk.Style()
        if self.dark_theme:
            style.configure("TNotebook", background="#2b2b2b")
            style.configure("TNotebook.Tab", background="#3c3c3c", foreground="#ffffff")
            style.map("TNotebook.Tab", background=[("selected", "#1e1e1e")])
        else:
            style.configure("TNotebook", background="#f5f5f5")
            style.configure("TNotebook.Tab", background="#e0e0e0", foreground="#000000")
            style.map("TNotebook.Tab", background=[("selected", "#ffffff")])

        # Force redraw
        self.root.update_idletasks()

    def toggle_auto_refresh(self):
        self.auto_refresh = self.auto_refresh_var.get()
        if self.auto_refresh:
            self.schedule_refresh()
        else:
            if hasattr(self, 'refresh_job'):
                self.root.after_cancel(self.refresh_job)

    def schedule_refresh(self):
        if self.auto_refresh and self.app_path.get().strip():
            self.scan_routes()
            self.refresh_job = self.root.after(self.refresh_interval, self.schedule_refresh)

    def export_report(self):
        if not self.findings and not self.routes_data:
            messagebox.showinfo("No Data", "No routes found. Nothing to export.")
            return

        # Create export menu
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Options")
        export_window.geometry("300x200")
        export_window.resizable(False, False)

        ttk.Label(export_window, text="Choose export format:").pack(pady=10)

        def export_html():
            default_name = f"route-viewer-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
            file = filedialog.asksaveasfilename(
                initialfile=default_name,
                defaultextension=".html",
                filetypes=[("HTML Report", "*.html")],
                title="Export HTML Report"
            )
            if file:
                with open(file, "w", encoding="utf-8") as f:
                    f.write(self.report_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"HTML report saved!\n{file}")
                webbrowser.open(file)
            export_window.destroy()

        def export_csv():
            default_name = f"route-viewer-routes-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
            file = filedialog.asksaveasfilename(
                initialfile=default_name,
                defaultextension=".csv",
                filetypes=[("CSV File", "*.csv")],
                title="Export CSV"
            )
            if file:
                self.export_to_csv(file)
                messagebox.showinfo("Success", f"CSV exported!\n{file}")
            export_window.destroy()

        def export_json():
            default_name = f"route-viewer-data-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            file = filedialog.asksaveasfilename(
                initialfile=default_name,
                defaultextension=".json",
                filetypes=[("JSON File", "*.json")],
                title="Export JSON"
            )
            if file:
                self.export_to_json(file)
                messagebox.showinfo("Success", f"JSON exported!\n{file}")
            export_window.destroy()

        ttk.Button(export_window, text="HTML Report", command=export_html).pack(pady=5)
        ttk.Button(export_window, text="CSV Export", command=export_csv).pack(pady=5)
        ttk.Button(export_window, text="JSON Export", command=export_json).pack(pady=5)
        ttk.Button(export_window, text="Cancel", command=export_window.destroy).pack(pady=10)


    def export_to_csv(self, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Risk', 'Method', 'URI', 'Name', 'Action', 'Security Issue']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Write findings
            for f in self.findings:
                risk_label = "HIGH" if f["severity"] == "high" else "MEDIUM" if f["severity"] == "medium" else "LOW"
                writer.writerow({
                    'Risk': risk_label,
                    'Method': f['methods'],
                    'URI': f['uri'],
                    'Name': f['name'],
                    'Action': f['action'],
                    'Security Issue': f['issues']
                })

            # Write safe routes

    def export_to_json(self, filename):
        data = {
            "project": self.app_path.get(),
            "timestamp": datetime.now().isoformat(),
            "total_routes": len(self.routes_data),
            "findings_count": len(self.findings),
            "routes": self.routes_data,
            "findings": self.findings
        }
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=2, ensure_ascii=False)


def cli_main():
    parser = argparse.ArgumentParser(description="Laravel Route Viewer - CLI Mode")
    parser.add_argument("path", help="Path to Laravel project")
    parser.add_argument("-o", "--output", choices=["html", "csv", "json"], help="Output format")
    parser.add_argument("-f", "--file", help="Output file path")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't show GUI")

    args = parser.parse_args()

    # Create a headless scanner
    class CLIScanner:
        def __init__(self, path):
            self.app_path = path
            self.routes_data = []
            self.findings = []

        def scan(self):
            path = self.app_path
            artisan_path = Path(path) / "artisan"
            if not artisan_path.exists():
                print(f"Error: 'artisan' not found in {path}")
                return False

            print("Fetching routes via php artisan route:list --json...")
            try:
                result = subprocess.run(
                    ["php", "artisan", "route:list", "--json"],
                    cwd=path,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False
                )

                if result.returncode != 0:
                    print("Artisan failed, attempting manual crawl...")
                    return self.manual_scan_routes(path)

                self.routes_data = json.loads(result.stdout)
                self.findings = self.analyze_routes(self.routes_data)
                return True

            except Exception as e:
                print(f"Error: {e}")
                return False

        def manual_scan_routes(self, path):
            print("Performing manual route crawl...")
            routes_dir = Path(path) / "routes"
            if not routes_dir.exists():
                print("No 'routes' directory found.")
                return False

            self.routes_data = []
            try:
                for route_file in routes_dir.glob("*.php"):
                    if route_file.is_file():
                        self.parse_route_file(route_file)
            except Exception as e:
                print(f"Manual crawl error: {e}")
                return False

            if not self.routes_data:
                print("No routes found.")
                return False

            self.findings = self.analyze_routes(self.routes_data)
            return True

        def parse_route_file(self, file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                return

            import re
            prefix_match = re.search(r"Route::prefix\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*->\s*group\s*\(\s*function\s*\(\s*\)\s*\{", content, re.IGNORECASE | re.DOTALL)
            prefix = prefix_match.group(1) if prefix_match else ""

            # Split content into lines for better parsing
            lines = content.split('\n')
            route_definitions = []

            # Find route definitions with their line numbers
            for i, line in enumerate(lines):
                # Look for Route::method calls
                route_match = re.search(r"Route::(get|post|put|patch|delete|options|any)\s*\(\s*['\"]([^'\"]+)['\"]\s*,", line, re.IGNORECASE)
                if route_match:
                    method, uri = route_match.groups()
                    # Apply prefix if exists
                    full_uri = f"{prefix}/{uri}".lstrip('/') if prefix else uri

                    # Look for ->name() in the current line and subsequent lines
                    name = ""
                    # Check current line first
                    name_match = re.search(r"->name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", line, re.IGNORECASE)
                    if name_match:
                        name = name_match.group(1)
                    else:
                        # Check next few lines for chained methods
                        for j in range(1, min(5, len(lines) - i)):  # Look up to 5 lines ahead
                            next_line = lines[i + j].strip()
                            name_match = re.search(r"->name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", next_line, re.IGNORECASE)
                            if name_match:
                                name = name_match.group(1)
                                break
                            # Stop if we hit a semicolon or another Route:: call
                            if ';' in next_line or re.search(r"Route::", next_line):
                                break

                    route = {
                        "method": {"methods": [method.upper()]},
                        "uri": full_uri,
                        "name": name,
                        "action": "Closure",
                        "middleware": []
                    }
                    self.routes_data.append(route)

        def analyze_routes(self, routes):
            findings = []
            for route in routes:
                uri = route.get("uri", "").strip()
                methods = self.get_route_methods(route)
                name = route.get("name", "") or "(none)"
                action = route.get("action", "") or "Closure"
                middleware = [m.lower() for m in route.get("middleware", [])]

                issues = []
                severity = "safe"

                if any(m in ["POST", "PUT", "PATCH", "DELETE"] for m in methods):
                    if "web" not in middleware and "csrf" not in " ".join(middleware):
                        issues.append("CSRF protection missing (use web middleware)")
                        severity = "high"

                debug_paths = ["telescope", "horizon", "_ignition", "debugbar", "phpinfo"]
                if any(p in uri.lower() for p in debug_paths):
                    issues.append("Debug/tool endpoint exposed in production")
                    severity = "high"

                if uri.startswith("api/"):
                    auth_missing = all(a not in " ".join(middleware) for a in ["auth", "sanctum", "jwt"])
                    if auth_missing and any(m in ["POST", "PUT", "PATCH", "DELETE"] for m in methods):
                        issues.append("Unauthenticated API write access")
                        severity = "high"
                    elif auth_missing and "GET" in methods:
                        issues.append("Unauthenticated API read access")
                        severity = "medium"

                admin_keywords = ["admin", "panel", "dashboard", "cpanel"]
                if any(k in uri.lower() for k in admin_keywords) and "auth" not in " ".join(middleware):
                    issues.append("Admin route lacks authentication")
                    severity = "high"

                if "upload" in uri.lower() and "POST" in methods:
                    issues.append("File upload – enforce MIME, size, and storage validation")
                    severity = "medium"

                if "Controller" in action and any(m in ["POST", "PUT"] for m in methods):
                    issues.append("Potential mass assignment – use $fillable/$guarded")
                    severity = "medium"

                if issues:
                    findings.append({
                        "route": route,
                        "methods": "|".join(methods),
                        "uri": uri,
                        "name": name,
                        "action": action.replace("App\\", "", 1) if action.startswith("App\\") else action,
                        "issues": "; ".join(issues),
                        "severity": severity
                    })

            return findings

        def export_html(self, filename):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            high = [f for f in self.findings if f["severity"] == "high"]
            medium = [f for f in self.findings if f["severity"] == "medium"]

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Laravel Route Viewer Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f9f9f9; }}
        h1 {{ color: #1976d2; }}
        .summary {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .high {{ background: #ffcdd2; border-left: 6px solid #f44336; }}
        .medium {{ background: #fff8e1; border-left: 6px solid #ff9800; }}
        .card {{ padding: 15px; margin: 10px 0; border-radius: 6px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #f5f5f5; }}
        .footer {{ margin-top: 50px; font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <h1>Laravel Route Viewer Report</h1>
    <div class="summary">
        <p><strong>Project:</strong> {self.app_path}</p>
        <p><strong>Scanned:</strong> {len(self.routes_data)} routes</p>
        <p><strong>Issues:</strong> {len(high)} High, {len(medium)} Medium</p>
        <p><strong>Time:</strong> {timestamp}</p>
    </div>

    <h2>High Risk Findings</h2>
"""
            for f in high:
                html += f"<div class='card high'><strong>{f['methods']} {f['uri']}</strong><br>{f['issues']}</div>"

            html += "<h2>Medium Risk</h2>"
            for f in medium:
                html += f"<div class='card medium'><strong>{f['methods']} {f['uri']}</strong><br>{f['issues']}</div>"

            html += "<h2>All Findings</h2><table><tr><th>Risk</th><th>Method</th><th>URI</th><th>Name</th><th>Action</th><th>Issue</th></tr>"
            for f in self.findings:
                risk = "HIGH" if f["severity"] == "high" else "MEDIUM"
                html += f"<tr><td>{risk}</td><td>{f['methods']}</td><td>{f['uri']}</td><td>{f['name']}</td><td>{f['action']}</td><td>{f['issues']}</td></tr>"
            html += "</table><div class='footer'>Generated by <strong>Laravel Route Viewer</strong></div></body></html>"

            with open(filename, "w", encoding="utf-8") as f:
                f.write(html)

        def export_csv(self, filename):
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Risk', 'Method', 'URI', 'Name', 'Action', 'Security Issue']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for f in self.findings:
                    risk_label = "HIGH" if f["severity"] == "high" else "MEDIUM" if f["severity"] == "medium" else "LOW"
                    writer.writerow({
                        'Risk': risk_label,
                        'Method': f['methods'],
                        'URI': f['uri'],
                        'Name': f['name'],
                        'Action': f['action'],
                        'Security Issue': f['issues']
                    })
        

        def export_json(self, filename):
            data = {
                "project": self.app_path,
                "timestamp": datetime.now().isoformat(),
                "total_routes": len(self.routes_data),
                "findings_count": len(self.findings),
                "routes": self.routes_data,
                "findings": self.findings
            }
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, ensure_ascii=False)

    scanner = CLIScanner(args.path)
    if not scanner.scan():
        sys.exit(1)

    count = len(scanner.findings)
    print(f"Scan complete: {len(scanner.routes_data)} routes, {count} issue(s) found.")

    if args.output:
        if not args.file:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            if args.output == "html":
                args.file = f"route-viewer-report-{timestamp}.html"
            elif args.output == "csv":
                args.file = f"route-viewer-routes-{timestamp}.csv"
            elif args.output == "json":
                args.file = f"route-viewer-data-{timestamp}.json"

        if args.output == "html":
            scanner.export_html(args.file)
            print(f"HTML report saved: {args.file}")
        elif args.output == "csv":
            scanner.export_csv(args.file)
            print(f"CSV exported: {args.file}")
        elif args.output == "json":
            scanner.export_json(args.file)
            print(f"JSON exported: {args.file}")

    if not args.scan_only:
        # Launch GUI
        root = tk.Tk()
        app = LaravelRouteViewer(root)
        app.app_path.set(args.path)
        app.routes_data = scanner.routes_data
        app.findings = scanner.findings
        app.display_routes()
        app.generate_html_report()
        root.mainloop()


# === RUN APP ===
if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_main()
    else:
        root = tk.Tk()
        app = LaravelRouteViewer(root)
        root.mainloop()