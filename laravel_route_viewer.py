#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laravel Route Viewer – List & Secure Laravel Routes
Full standalone GUI application
Author: DevSec Engineer | Date: 2025-11-07
"""

import os
import json
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import webbrowser
from datetime import datetime

class LaravelRouteViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Laravel Route Viewer")
        self.root.geometry("1280x760")
        self.root.minsize(1000, 600)
        self.root.configure(bg="#f5f5f5")

        self.app_path = tk.StringVar()
        self.routes_data = []
        self.findings = []

        self.setup_ui()
        self.create_reports_dir()

    def create_reports_dir(self):
        Path("reports").mkdir(exist_ok=True)

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
        self.report_text = tk.Text(self.tab_report, wrap="word", font=("Consolas", 10), bg="white")
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
        style.configure("Accent.TButton", foreground="white", background="#1976d2")
        style.map("Accent.TButton", background=[("active", "#0d47a1")])

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

        # Match Route::method('uri', ...) patterns
        route_patterns = [
            r"Route::(get|post|put|patch|delete|options|any)\s*\(\s*['\"]([^'\"]+)['\"]\s*,",
            r"Route::(get|post|put|patch|delete|options|any)\s*\(\s*['\"]([^'\"]+)['\"]\s*,.*?\)\s*;",
        ]

        for pattern in route_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                method, uri = match
                # Create a basic route dict similar to artisan output
                route = {
                    "method": {"methods": [method.upper()]},
                    "uri": uri,
                    "name": "",
                    "action": "Closure",  # Default, could be improved
                    "middleware": []  # Default, could be improved
                }
                self.routes_data.append(route)

    def analyze_routes(self, routes):
        findings = []
        for route in routes:
            uri = route.get("uri", "").strip()
            methods = [m for m in route.get("method", {}).get("methods", []) if m != "HEAD"]
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
                methods = "|".join([m for m in route["method"]["methods"] if m != "HEAD"])
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

    def export_report(self):
        if not self.findings:
            messagebox.showinfo("Clean", "No security issues found. Nothing to export.")
            return
        default_name = f"route-viewer-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        file = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            title="Export Route Report"
        )
        if file:
            with open(file, "w", encoding="utf-8") as f:
                f.write(self.report_text.get(1.0, tk.END))
            messagebox.showinfo("Success", f"Report saved!\n{file}")
            webbrowser.open(file)


# === RUN APP ===
if __name__ == "__main__":
    root = tk.Tk()
    app = LaravelRouteViewer(root)
    root.mainloop()