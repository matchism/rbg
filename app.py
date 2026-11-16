#!/usr/bin/env python3
"""
app.py — Offline Legal Correspondence Archiver (entry point).

* Ensures config.json exists (copied from config.example.json on first run).
* Serves the review UI on http://127.0.0.1:<port>/ ONLY (never 0.0.0.0).
* Opens the default browser.
* JSON API for importing .eml files, saving config, and exporting an archive.

Security model (localhost app handling privileged material):
* Bound to the loopback interface only.
* Host-header allow-list blocks DNS-rebinding attacks.
* Every /api/* call needs a per-launch random token sent in a custom header,
  which a hostile web page in another tab cannot forge (CSRF protection).
* Strict Content-Security-Policy: no external scripts, styles, fonts or calls.
* Originals are only ever opened read-only ("rb").

Standard library only — no pip installs, no network access.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from archive_builder import ExportError, build_archive
from parser_engine import CATEGORIES, DEFAULT_CATEGORY_RULES, annotate, parse_eml

APP_NAME = "Legal EML Archiver"
APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.json"
CONFIG_EXAMPLE_PATH = APP_DIR / "config.example.json"
UI_PATH = APP_DIR / "templates" / "ui.html"

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_EML_BYTES = 250 * 1024 * 1024      # per uploaded file
MAX_JSON_BYTES = 20 * 1024 * 1024      # per JSON request
MAX_SCAN_FILES = 5000

DEFAULT_CONFIG = {
    "role_mappings": {
        "counsel@example-law.com": "Counsel",
        "client@example.com": "Client",
        "opposing@example-firm.com": "Opposing",
    },
    "category_rules": DEFAULT_CATEGORY_RULES,
    "ignore_inline_images_under_kb": 15,
    "last_output_dir": "",
    "last_input_dir": "",
}

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
       "img-src data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; "
       "base-uri 'none'")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

def ensure_config() -> None:
    if CONFIG_PATH.exists():
        return
    if CONFIG_EXAMPLE_PATH.exists():
        shutil.copyfile(CONFIG_EXAMPLE_PATH, CONFIG_PATH)
        print(f"[setup] Created config.json from config.example.json")
    else:
        save_config(DEFAULT_CONFIG)
        print(f"[setup] Created default config.json")
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:
        pass


def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[warn] Could not read config.json ({exc}); using defaults.")
    return cfg


def save_config(cfg: dict) -> None:
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, CONFIG_PATH)


def validate_role_mappings(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError("role_mappings must be an object")
    clean = {}
    for k, v in value.items():
        key = str(k).strip().lower()
        role = str(v).strip()
        if not key:
            continue
        if len(key) > 254 or len(role) > 60:
            raise ValueError(f"Mapping too long: {key}")
        if not role:
            raise ValueError(f"Role for {key!r} is empty")
        clean[key] = role
    return clean


def validate_category_rules(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError("category_rules must be an object")
    clean = {}
    for cat in CATEGORIES[:-1]:
        kws = value.get(cat, [])
        if not isinstance(kws, list):
            raise ValueError(f"category_rules[{cat}] must be a list")
        clean[cat] = [str(k).strip().lower() for k in kws if str(k).strip()][:200]
    return clean


# --------------------------------------------------------------------------- #
# Session state (in memory only — nothing is cached to disk)
# --------------------------------------------------------------------------- #

class Session:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.emails: dict = {}          # id -> ParsedEmail (insertion ordered)
        self.dashboards: set = set()    # dashboards produced this session

    def add(self, pe) -> bool:
        with self.lock:
            if pe.id in self.emails:
                return False
            self.emails[pe.id] = pe
            return True


SESSION = Session()
TOKEN = secrets.token_urlsafe(32)


def _public_list() -> list:
    with SESSION.lock:
        return [pe.to_public() for pe in SESSION.emails.values()]


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "LegalEMLArchiver/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---- plumbing ----
    def log_message(self, fmt, *args):  # keep the console quiet & private
        if os.environ.get("ARCHIVER_DEBUG"):
            sys.stderr.write("[http] " + (fmt % args) + "\n")

    def _security_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"ok": False, "error": message})

    def _host_ok(self) -> bool:
        port = self.server.server_address[1]
        host = (self.headers.get("Host") or "").strip().lower()
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _api_authorized(self) -> bool:
        supplied = self.headers.get("X-Session-Token", "")
        return secrets.compare_digest(supplied.encode(), TOKEN.encode())

    def _read_body(self, limit: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length < 0 or length > limit:
            raise ValueError(f"Request too large (limit {limit // (1024 * 1024)} MB)")
        data = b""
        while len(data) < length:
            chunk = self.rfile.read(min(1024 * 1024, length - len(data)))
            if not chunk:
                break
            data += chunk
        return data

    def _read_json(self) -> dict:
        raw = self._read_body(MAX_JSON_BYTES)
        try:
            obj = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Malformed JSON body")
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    # ---- routing ----
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "Invalid Host header")
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = UI_PATH.read_text(encoding="utf-8").replace("__SESSION_TOKEN__", TOKEN)
            return self._send(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
        if not path.startswith("/api/"):
            return self._error(HTTPStatus.NOT_FOUND, "Not found")
        if not self._api_authorized():
            return self._error(HTTPStatus.FORBIDDEN, "Missing or invalid session token")
        if path == "/api/config":
            cfg = load_config()
            return self._json(HTTPStatus.OK, {"ok": True, "config": cfg, "categories": CATEGORIES})
        if path == "/api/emails":
            return self._json(HTTPStatus.OK, {"ok": True, "emails": _public_list()})
        return self._error(HTTPStatus.NOT_FOUND, "Unknown endpoint")

    def do_POST(self):
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "Invalid Host header")
        path = urlparse(self.path).path
        if not path.startswith("/api/") or not self._api_authorized():
            return self._error(HTTPStatus.FORBIDDEN, "Missing or invalid session token")
        routes = {
            "/api/upload": self.api_upload,
            "/api/scan": self.api_scan,
            "/api/config": self.api_save_config,
            "/api/remove": self.api_remove,
            "/api/clear": self.api_clear,
            "/api/export": self.api_export,
            "/api/open": self.api_open,
            "/api/shutdown": self.api_shutdown,
        }
        handler = routes.get(path)
        if not handler:
            return self._error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
        try:
            handler()
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except ExportError as exc:
            self._error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
        except Exception as exc:  # pragma: no cover — surface, never crash
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")

    # ---- API ----
    def api_upload(self):
        name = unquote(self.headers.get("X-Filename", "upload.eml"))[:255] or "upload.eml"
        raw = self._read_body(MAX_EML_BYTES)
        if not raw:
            raise ValueError(f"{name}: empty file")
        pe = parse_eml(raw, name, load_config())
        added = SESSION.add(pe)
        self._json(HTTPStatus.OK, {"ok": True, "added": added, "email": pe.to_public()})

    def api_scan(self):
        body = self._read_json()
        folder = Path(os.path.expanduser(str(body.get("path", "")).strip()))
        if not str(folder) or not folder.is_absolute():
            raise ValueError("Please enter an absolute folder path.")
        if not folder.is_dir():
            raise ValueError(f"Folder not found: {folder}")
        pattern = "**/*" if body.get("recursive") else "*"
        files = sorted(p for p in folder.glob(pattern)
                       if p.is_file() and p.suffix.lower() == ".eml")
        if len(files) > MAX_SCAN_FILES:
            raise ValueError(f"Too many .eml files ({len(files)}); limit is {MAX_SCAN_FILES}.")
        cfg = load_config()
        added, dupes, errors = 0, 0, []
        for p in files:
            try:
                if p.stat().st_size > MAX_EML_BYTES:
                    raise ValueError("file too large")
                with open(p, "rb") as fh:      # read-only: originals are never altered
                    raw = fh.read()
                if SESSION.add(parse_eml(raw, p.name, cfg)):
                    added += 1
                else:
                    dupes += 1
            except Exception as exc:
                errors.append(f"{p.name}: {exc}")
        cfg["last_input_dir"] = str(folder)
        save_config(cfg)
        self._json(HTTPStatus.OK, {"ok": True, "found": len(files), "added": added,
                                   "duplicates": dupes, "errors": errors,
                                   "emails": _public_list()})

    def api_save_config(self):
        body = self._read_json()
        cfg = load_config()
        if "role_mappings" in body:
            cfg["role_mappings"] = validate_role_mappings(body["role_mappings"])
        if "category_rules" in body:
            cfg["category_rules"] = validate_category_rules(body["category_rules"])
        if "ignore_inline_images_under_kb" in body:
            try:
                kb = float(body["ignore_inline_images_under_kb"])
            except (TypeError, ValueError):
                raise ValueError("Threshold must be a number")
            if not 0 <= kb <= 10240:
                raise ValueError("Threshold must be between 0 and 10240 KB")
            cfg["ignore_inline_images_under_kb"] = int(kb) if kb.is_integer() else kb
        save_config(cfg)
        with SESSION.lock:
            for pe in SESSION.emails.values():
                annotate(pe, cfg)
        self._json(HTTPStatus.OK, {"ok": True, "config": cfg, "emails": _public_list()})

    def api_remove(self):
        body = self._read_json()
        with SESSION.lock:
            SESSION.emails.pop(str(body.get("id", "")), None)
        self._json(HTTPStatus.OK, {"ok": True})

    def api_clear(self):
        with SESSION.lock:
            SESSION.emails.clear()
        self._json(HTTPStatus.OK, {"ok": True})

    def api_export(self):
        body = self._read_json()
        selections = body.get("emails")
        if not isinstance(selections, list):
            raise ValueError("emails must be a list")
        cfg = load_config()
        with SESSION.lock:
            emails = dict(SESSION.emails)
        result = build_archive(emails, selections, body.get("output_dir", ""), cfg)
        cfg["last_output_dir"] = str(Path(result["archive_path"]).parent)
        save_config(cfg)
        SESSION.dashboards.add(result["dashboard_path"])
        print(f"[export] Archive written: {result['archive_path']}")
        self._json(HTTPStatus.OK, {"ok": True, **result})

    def api_open(self):
        body = self._read_json()
        target = str(body.get("path", ""))
        # Only open things this session created — never arbitrary paths.
        if target not in SESSION.dashboards:
            raise ValueError("Can only open dashboards generated in this session.")
        webbrowser.open(Path(target).as_uri())
        self._json(HTTPStatus.OK, {"ok": True})

    def api_shutdown(self):
        self._json(HTTPStatus.OK, {"ok": True})
        threading.Thread(target=self.server.shutdown, daemon=True).start()


# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #

def _bind(port: int) -> ThreadingHTTPServer:
    candidates = [port] + list(range(port + 1, port + 20)) + [0]
    last_exc = None
    for p in candidates:
        try:
            return ThreadingHTTPServer((HOST, p), Handler)
        except OSError as exc:
            last_exc = exc
    raise SystemExit(f"Could not bind to {HOST}: {last_exc}")


def main() -> None:
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    args = ap.parse_args()

    if sys.version_info < (3, 9):
        raise SystemExit("Python 3.9 or newer is required.")
    os.chdir(APP_DIR)
    ensure_config()

    httpd = _bind(args.port)
    httpd.daemon_threads = True
    port = httpd.server_address[1]
    url = f"http://{HOST}:{port}/"
    print("=" * 64)
    print(f"  {APP_NAME} — running OFFLINE on {url}")
    print("  Bound to loopback only. Press Ctrl+C (or 'Quit' in the UI) to stop.")
    print("=" * 64)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("Server stopped. In-memory session data discarded.")


if __name__ == "__main__":
    main()
