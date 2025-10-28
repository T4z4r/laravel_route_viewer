
# Laravel Route Viewer

**List, analyze, and secure Laravel routes in a beautiful GUI with CLI support.**

---

## Features

- Browse Laravel project
- View all routes with methods, names, actions
- **Security scan** (CSRF, auth, debug, uploads)
- **Color-coded risks**
- **Dark theme toggle**
- **Auto-refresh functionality**
- **Export options**: HTML report, CSV, JSON
- **CLI mode** for automation and CI/CD
- No dependencies

---

## Requirements

| Tool | Install |
|------|--------|
| Python 3.6+ | `sudo apt install python3` |
| PHP CLI | `sudo apt install php-cli` |
| Laravel App | Must have `artisan` |

---

## How to Run

### GUI Mode (Default)
```bash
# 1. Create folder
mkdir laravel_route_viewer && cd laravel_route_viewer

# 2. Save files
# → Paste laravel_route_viewer.py and this README

# 3. Run
python3 laravel_route_viewer.py
```

### CLI Mode
```bash
# Scan and display results
python3 laravel_route_viewer.py /path/to/laravel/project

# Export HTML report
python3 laravel_route_viewer.py /path/to/laravel/project -o html -f report.html

# Export CSV
python3 laravel_route_viewer.py /path/to/laravel/project -o csv -f routes.csv

# Export JSON
python3 laravel_route_viewer.py /path/to/laravel/project -o json -f data.json

# Scan only (no GUI)
python3 laravel_route_viewer.py /path/to/laravel/project --scan-only
```

### CLI Options
- `path`: Path to Laravel project (required)
- `-o, --output`: Output format (html, csv, json)
- `-f, --file`: Output file path (optional, auto-generated if not specified)
- `--scan-only`: Only scan, don't show GUI