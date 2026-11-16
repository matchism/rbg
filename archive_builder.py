"""
archive_builder.py — writes the standardized offline Legal Archive to disk.

Standard library only. The archive is assembled inside a hidden temporary
directory next to the destination and atomically renamed into place only
after every file has been written *and* its SHA-256 re-verified from disk,
so a failed export never leaves a half-written archive behind.

Output layout::

    Legal_Archive_[YYYY-MM-DD_HHMM]/
    ├── 00_Decision_Dashboard.html
    ├── 00_Master_Audit_Log.csv
    ├── 01_Action_Required/
    ├── 02_Drafts_And_Reviews/
    ├── 03_Executed_And_Final/
    ├── 04_Financials_And_Billing/
    ├── 05_General_Reference/
    └── 99_Raw_EML_Vault/
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from parser_engine import (
    CATEGORIES,
    DEFAULT_CATEGORY,
    VAULT_FOLDER,
    ParsedEmail,
    annotate,
    sanitize_component,
    split_filename,
    smart_truncate,
)

APP_DIR = Path(__file__).resolve().parent
DASHBOARD_TEMPLATE = APP_DIR / "templates" / "dashboard_template.html"
DASHBOARD_NAME = "00_Decision_Dashboard.html"
AUDIT_LOG_NAME = "00_Master_Audit_Log.csv"
MAX_NOTE_LEN = 5000

CSV_COLUMNS = [
    "Timestamp", "Sender_Role", "From", "To", "Subject", "Category",
    "Decision_Note", "Standardized_Filename", "Relative_Path",
    "Attachment_SHA256", "Raw_EML_SHA256",
]


class ExportError(Exception):
    pass


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_verified(path: Path, data: bytes, expected_sha256: str) -> None:
    """Write bytes exclusively (never overwrite) and verify the hash on disk."""
    with open(path, "xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise ExportError(f"Integrity check failed for {path.name}: "
                          f"expected {expected_sha256}, got {actual}")


def _unique_name(name: str, used: set) -> str:
    """Case-insensitive de-duplication (Windows/macOS are case-insensitive)."""
    if name.lower() not in used:
        used.add(name.lower())
        return name
    stem, ext = split_filename(name)
    n = 2
    while True:
        candidate = f"{stem}_{n}{ext}"
        if candidate.lower() not in used:
            used.add(candidate.lower())
            return candidate
        n += 1


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection (CWE-1236)."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _make_readonly(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def _rmtree_force(path: Path) -> None:
    """Remove a staging tree, clearing read-only bits if needed (Windows)."""
    if not path.exists():
        return

    def _retry(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_retry)
    else:  # pragma: no cover
        shutil.rmtree(path, onerror=_retry)


def build_archive(emails: dict, selections: list, output_dir: str,
                  config: dict) -> dict:
    """
    emails      — {email_id: ParsedEmail}
    selections  — [{"id", "category", "note", "attachments": {index: bool}}]
    output_dir  — destination folder (created if missing)
    """
    if not selections:
        raise ExportError("No emails selected for export.")
    out = Path(os.path.expanduser(str(output_dir or "").strip()))
    if not str(output_dir or "").strip():
        raise ExportError("Please choose an output directory.")
    if not out.is_absolute():
        raise ExportError("Output directory must be an absolute path.")
    out.mkdir(parents=True, exist_ok=True)
    out = out.resolve()
    if not os.access(out, os.W_OK):
        raise ExportError(f"Output directory is not writable: {out}")

    generated_at = datetime.now().astimezone()
    base_name = f"Legal_Archive_{generated_at.strftime('%Y-%m-%d_%H%M')}"
    final_dir = out / base_name
    n = 2
    while final_dir.exists():
        final_dir = out / f"{base_name}_{n}"
        n += 1

    staging = Path(tempfile.mkdtemp(prefix=".legal_archive_staging_", dir=out))
    try:
        for folder in CATEGORIES + [VAULT_FOLDER]:
            (staging / folder).mkdir()

        used = {folder: set() for folder in CATEGORIES + [VAULT_FOLDER]}
        records, csv_rows = [], []
        written_atts = 0

        # Resolve and sort chronologically (undated last).
        resolved = []
        for sel in selections:
            pe: ParsedEmail | None = emails.get(sel.get("id"))
            if pe is None:
                raise ExportError(f"Email {sel.get('id')!r} is no longer in this session; re-import it.")
            annotate(pe, config)
            resolved.append((pe, sel))
        resolved.sort(key=lambda t: (t[0].date is None, t[0].date.timestamp() if t[0].date else 0))

        for pe, sel in resolved:
            category = sel.get("category") if sel.get("category") in CATEGORIES else DEFAULT_CATEGORY
            note = str(sel.get("note") or "")[:MAX_NOTE_LEN].strip()
            includes = {int(k): bool(v) for k, v in (sel.get("attachments") or {}).items()}

            # ---- 99_Raw_EML_Vault: byte-for-byte original ----
            src_stem = split_filename(pe.source_name)[0]
            vault_name = f"{pe.date_prefix}_{sanitize_component(smart_truncate(src_stem, 120), 120, 'message')}.eml"
            vault_name = _unique_name(vault_name, used[VAULT_FOLDER])
            _write_verified(staging / VAULT_FOLDER / vault_name, pe.raw, pe.raw_sha256)
            vault_rel = f"./{VAULT_FOLDER}/{vault_name}"

            att_records = []
            for att in pe.attachments:
                include = includes.get(att.index, not att.is_clutter)
                if not include:
                    att_records.append({
                        "original_filename": att.original_filename,
                        "content_type": att.content_type, "size": att.size,
                        "sha256": att.sha256, "included": False,
                        "excluded_reason": att.clutter_reason or "Excluded by reviewer",
                    })
                    continue
                fname = _unique_name(att.proposed_filename, used[category])
                _write_verified(staging / category / fname, att.data, att.sha256)
                written_atts += 1
                rel = f"./{category}/{fname}"
                att_records.append({
                    "original_filename": att.original_filename,
                    "standardized_filename": fname,
                    "relative_path": rel, "folder": category,
                    "content_type": att.content_type, "size": att.size,
                    "sha256": att.sha256, "included": True,
                })
                csv_rows.append([
                    pe.date_iso, pe.sender_role, pe.from_display, "; ".join(pe.to),
                    pe.subject, category, note, fname, rel, att.sha256, pe.raw_sha256,
                ])

            if not any(a["included"] for a in att_records):
                # One row per email even when it carries no archived attachment.
                csv_rows.append([
                    pe.date_iso, pe.sender_role, pe.from_display, "; ".join(pe.to),
                    pe.subject, category, note, "", "", "", pe.raw_sha256,
                ])

            records.append({
                "date_iso": pe.date_iso,
                "date_display": pe.date.strftime("%Y-%m-%d %H:%M") if pe.date else "Undated",
                "sender_role": pe.sender_role,
                "from": pe.from_display,
                "to": pe.to, "cc": pe.cc,
                "subject": pe.subject,
                "message_id": pe.message_id,
                "category": category,
                "suggested_category": pe.suggested_category,
                "note": note,
                "body": pe.body_text[:20000],
                "raw_eml_path": vault_rel,
                "raw_eml_name": vault_name,
                "raw_sha256": pe.raw_sha256,
                "raw_size": pe.raw_size,
                "source_name": pe.source_name,
                "defects": pe.defects,
                "attachments": att_records,
            })

        # ---- 00_Master_Audit_Log.csv ----
        with open(staging / AUDIT_LOG_NAME, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
            writer.writerow(CSV_COLUMNS)
            for row in csv_rows:
                writer.writerow([_csv_safe(v) for v in row])

        # ---- 00_Decision_Dashboard.html ----
        meta = {
            "archive_name": final_dir.name,
            "generated_at": generated_at.isoformat(timespec="seconds"),
            "generated_display": generated_at.strftime("%Y-%m-%d %H:%M %Z").strip(),
            "categories": CATEGORIES,
            "email_count": len(records),
            "attachment_count": written_atts,
            "audit_log": f"./{AUDIT_LOG_NAME}",
        }
        _write_dashboard(staging / DASHBOARD_NAME, meta, records)

        os.replace(staging, final_dir)
    except Exception:
        _rmtree_force(staging)
        raise

    # Lock down the evidentiary vault after the archive is in place.
    for p in (final_dir / VAULT_FOLDER).iterdir():
        _make_readonly(p)

    return {
        "archive_path": str(final_dir),
        "dashboard_path": str(final_dir / DASHBOARD_NAME),
        "audit_log_path": str(final_dir / AUDIT_LOG_NAME),
        "email_count": len(records),
        "attachment_count": written_atts,
    }


def _write_dashboard(path: Path, meta: dict, records: list) -> None:
    template = DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    payload = json.dumps({"meta": meta, "emails": records}, ensure_ascii=False)
    # Prevent "</script>" / "<!--" break-outs: JSON allows < inside strings.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    html_out = template.replace("__ARCHIVE_TITLE__", meta["archive_name"])
    html_out = html_out.replace("/*__ARCHIVE_DATA__*/", payload, 1)
    path.write_text(html_out, encoding="utf-8")
