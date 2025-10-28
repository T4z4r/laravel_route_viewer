# Laravel Route Viewer

**List, analyze, and secure Laravel routes in a beautiful GUI.**

---

## Features

- Browse Laravel project
- View all routes with methods, names, actions
- **Security scan** (CSRF, auth, debug, uploads)
- **Color-coded risks**
- **Export HTML report**
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

```bash
# 1. Create folder
mkdir laravel_route_viewer && cd laravel_route_viewer

# 2. Save files
# → Paste laravel_route_viewer.py and this README

# 3. Run
python3 laravel_route_viewer.py