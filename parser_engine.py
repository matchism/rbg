"""
parser_engine.py — RFC 5322 / MIME parsing for legal correspondence (.eml).

Standard library only. This module never writes to disk and never mutates
the bytes it is given: every function works on an in-memory copy of the
original message so the evidentiary original stays untouched.

Responsibilities
----------------
* Parse raw .eml bytes with ``email.policy.default``.
* Walk nested MIME trees (multipart/*, message/rfc822) with a depth guard.
* Decode Base64 / Quoted-Printable transfer encodings.
* Decode text with charset fallbacks (declared -> utf-8 -> cp1252 -> latin-1).
* Extract a clean body (text/plain preferred, otherwise HTML stripped to text).
* Separate genuine attachments from signature clutter (small inline images).
* Resolve sender roles, suggest a Decision Category, and propose the
  standardized attachment filename.
"""

from __future__ import annotations

import email
import hashlib
import mimetypes
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CATEGORIES = [
    "01_Action_Required",
    "02_Drafts_And_Reviews",
    "03_Executed_And_Final",
    "04_Financials_And_Billing",
    "05_General_Reference",
]
DEFAULT_CATEGORY = "05_General_Reference"
VAULT_FOLDER = "99_Raw_EML_Vault"

DEFAULT_CATEGORY_RULES = {
    "01_Action_Required": [
        "urgent", "sign", "signature", "deadline", "action required",
        "please confirm", "approve", "response needed",
    ],
    "02_Drafts_And_Reviews": [
        "draft", "redline", "markup", "review", "comments", "v1", "v2",
        "proposal", "edits",
    ],
    "03_Executed_And_Final": [
        "executed", "signed", "final", "filed", "order", "agreement",
        "fully executed",
    ],
    "04_Financials_And_Billing": [
        "invoice", "billing", "retainer", "statement", "fee", "wire",
        "payment", "receipt",
    ],
}

# latin-1 can decode any byte sequence, so it must be the *last* fallback;
# cp1252 is tried before it because it maps the 0x80-0x9F range to the
# "smart quotes" that Outlook-generated mail commonly contains.
FALLBACK_ENCODINGS = ("utf-8", "cp1252", "latin-1")

MAX_MIME_DEPTH = 25
UNDATED_PREFIX = "0000-00-00_0000"
UNKNOWN_ROLE = "Unknown"

_REPLY_PREFIX_RE = re.compile(
    r"^\s*(?:re|fw|fwd|aw|wg|sv|vs|antw|rif|tr)\s*(?:\[\d+\])?\s*:\s*",
    re.IGNORECASE,
)
# Anything that is not a Unicode word character or a small set of safe
# punctuation becomes "_". This removes every character that is invalid on
# Windows (<>:"/\|?* and control chars) or macOS (":" and "/").
_UNSAFE_CHARS_RE = re.compile(r"[^\w\-.()+,&']", re.UNICODE)
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_bytes(data: bytes, declared: str | None = None) -> str:
    """Decode bytes using the declared charset, then the fallback chain."""
    candidates = []
    if declared:
        candidates.append(declared.strip().strip('"').lower())
    candidates.extend(FALLBACK_ENCODINGS)
    seen = set()
    for enc in candidates:
        if enc in seen:
            continue
        seen.add(enc)
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")  # pragma: no cover


def _fix_surrogates(text: str) -> str:
    """Undo surrogateescape artefacts left by undeclared 8-bit headers."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        raw = text.encode("utf-8", errors="surrogateescape")
        return decode_bytes(raw)


def _safe_header(msg: Message, name: str) -> str:
    """Return a decoded header value; never raises on malformed headers."""
    try:
        value = msg.get(name)
        if value is None:
            return ""
        text = _fix_surrogates(str(value)).strip()
        if "�" not in text:
            return text
        # Undeclared 8-bit bytes were replaced; recover them from the raw header.
        recovered = _raw_header(msg, name)
        return recovered or text
    except Exception:
        pass
    return _raw_header(msg, name)


def _raw_header(msg: Message, name: str) -> str:
    """Decode a header from its raw (surrogate-escaped) form with charset fallbacks."""
    # Fallback: decode the raw header ourselves.
    for key, raw in msg.raw_items():
        if key.lower() == name.lower():
            raw = re.sub(r"\r?\n[ \t]+", " ", _fix_surrogates(str(raw)))
            try:
                return str(make_header(decode_header(raw))).strip()
            except Exception:
                return raw.strip()
    return ""


def _safe_header_all(msg: Message, name: str) -> list[str]:
    out = []
    try:
        values = msg.get_all(name) or []
        for v in values:
            text = _fix_surrogates(str(v))
            out.append(_raw_header(msg, name) or text if "�" in text else text)
        return out
    except Exception:
        value = _safe_header(msg, name)
        return [value] if value else []


def _parse_addresses(values: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for name, addr in getaddresses(values):
        addr = (addr or "").strip()
        name = (name or "").strip()
        if not addr and not name:
            continue
        pairs.append((name, addr))
    return pairs


def _format_address(name: str, addr: str) -> str:
    if name and addr and name.lower() != addr.lower():
        return f"{name} <{addr}>"
    return addr or name


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"  # pragma: no cover


# --------------------------------------------------------------------------- #
# HTML -> text
# --------------------------------------------------------------------------- #

class _HTMLToText(HTMLParser):
    _BLOCK = {
        "p", "div", "br", "tr", "li", "ul", "ol", "table", "h1", "h2", "h3",
        "h4", "h5", "h6", "blockquote", "pre", "hr", "section", "article",
        "header", "footer", "dt", "dd",
    }
    _SKIP = {"script", "style", "head", "title", "noscript", "template", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self._SKIP:
            self._skip_depth += 1
            return
        if tag == "li":
            self.parts.append("\n• ")
        elif tag in ("td", "th"):
            self.parts.append("\t")
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if tag.lower() in ("br", "hr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self._SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(markup: str) -> str:
    parser = _HTMLToText()
    try:
        parser.feed(markup)
        parser.close()
        text = "".join(parser.parts)
    except Exception:
        text = re.sub(r"<[^>]+>", " ", markup)
    return normalize_whitespace(text)


def normalize_whitespace(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\xa0", " ")
    lines = [re.sub(r"[ \t\f\v]+", " ", ln).strip() for ln in text.split("\n")]
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# --------------------------------------------------------------------------- #
# Filename sanitization & naming schema
# --------------------------------------------------------------------------- #

def sanitize_component(value: str, max_len: int | None = None,
                       fallback: str = "Untitled") -> str:
    """Make a string safe as part of a filename on Windows, macOS and Linux."""
    value = unicodedata.normalize("NFC", value or "")
    value = _UNSAFE_CHARS_RE.sub("_", value)
    value = re.sub(r"_+", "_", value)
    value = value.strip("._-, ")
    if max_len and len(value) > max_len:
        value = smart_truncate(value, max_len)
    if not value:
        value = fallback
    if value.split(".")[0].upper() in _WINDOWS_RESERVED:
        value = "_" + value
    return value


def smart_truncate(value: str, max_len: int) -> str:
    """Truncate at a word boundary ("_") when one exists reasonably close."""
    if len(value) <= max_len:
        return value
    cut = value[:max_len]
    boundary = cut.rfind("_")
    if boundary >= max_len * 0.5:
        cut = cut[:boundary]
    return cut.strip("._-, ")


def clean_subject(subject: str) -> str:
    """Strip any number of leading Re:/Fwd:/AW: style prefixes."""
    previous = None
    subject = subject or ""
    while previous != subject:
        previous = subject
        subject = _REPLY_PREFIX_RE.sub("", subject)
    return subject.strip()


def split_filename(name: str) -> tuple[str, str]:
    """Split into (stem, .ext). Extension is lowercase and sanitized."""
    if "." in name.strip(".") and not name.startswith("."):
        stem, _, ext = name.rpartition(".")
        ext = re.sub(r"[^A-Za-z0-9]", "", ext).lower()[:10]
        if ext:
            return stem, "." + ext
    return name, ""


def standardized_filename(date_day: str, sender_role: str, subject: str,
                          original_filename: str, content_type: str = "") -> str:
    """[YYYY-MM-DD]_[SenderRole]_[SanitizedSubject]_[OriginalFilename].[ext]"""
    stem, ext = split_filename(original_filename)
    if not ext and content_type:
        ext = (mimetypes.guess_extension(content_type) or "").lower()
    role = sanitize_component(sender_role, 30, UNKNOWN_ROLE)
    subj = sanitize_component(clean_subject(subject), 40, "No_Subject")
    stem = sanitize_component(stem, 80, "attachment")
    head = f"{date_day}_{role}_{subj}_"
    # Keep the whole filename under ~180 chars for deep Windows paths.
    budget = max(20, 180 - len(head) - len(ext))
    stem = smart_truncate(stem, budget) or "attachment"
    return f"{head}{stem}{ext}"


def safe_original_filename(raw: str | None, index: int, content_type: str) -> str:
    """Strip any path components (path traversal) and unsafe characters."""
    name = _fix_surrogates(raw or "").replace("\x00", "")
    name = re.split(r"[\\/]", name)[-1].strip()
    if not name:
        ext = mimetypes.guess_extension(content_type or "") or ".bin"
        if content_type == "message/rfc822":
            ext = ".eml"
        name = f"unnamed_attachment_{index + 1}{ext}"
    stem, ext = split_filename(name)
    return sanitize_component(stem, 120, f"attachment_{index + 1}") + ext


# --------------------------------------------------------------------------- #
# Roles & categories
# --------------------------------------------------------------------------- #

def resolve_role(address: str, role_mappings: dict) -> str:
    """Exact address first, then domain / parent-domain (``@x.com`` or ``x.com``)."""
    norm = {str(k).strip().lower(): str(v).strip()
            for k, v in (role_mappings or {}).items() if str(k).strip()}
    addr = (address or "").strip().lower()
    if not addr:
        return UNKNOWN_ROLE
    if addr in norm and norm[addr]:
        return norm[addr]
    domain = addr.rpartition("@")[2]
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        for key in ("@" + candidate, candidate):
            if norm.get(key):
                return norm[key]
    return UNKNOWN_ROLE


def _keyword_pattern(keyword: str) -> re.Pattern:
    kw = re.escape(keyword.strip().lower()).replace(r"\ ", r"\s+")
    return re.compile(r"(?<![a-z0-9])" + kw + r"(?![a-z0-9])")


def suggest_category(subject: str, body: str, attachment_names: list[str],
                     category_rules: dict) -> tuple[str, list[str]]:
    """Weighted keyword match: subject x3, attachment names x2, body x1 (capped)."""
    subject_l = (subject or "").lower()
    names_l = " ".join(attachment_names or []).lower().replace("_", " ")
    body_l = (body or "")[:20000].lower()
    best_cat, best_score, best_hits = DEFAULT_CATEGORY, 0, []
    for cat in CATEGORIES:
        keywords = (category_rules or {}).get(cat) or []
        score, hits = 0, []
        for kw in keywords:
            if not str(kw).strip():
                continue
            pat = _keyword_pattern(str(kw))
            s = 3 * len(pat.findall(subject_l))
            s += 2 * len(pat.findall(names_l))
            s += min(len(pat.findall(body_l)), 2)
            if s:
                score += s
                hits.append(str(kw))
        # Strictly greater keeps CATEGORIES order as the tie-breaker
        # (Action Required wins ties — the safer default for a lawyer).
        if score > best_score:
            best_cat, best_score, best_hits = cat, score, hits
    return best_cat, best_hits


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Attachment:
    index: int
    original_filename: str
    content_type: str
    size: int
    disposition: str          # attachment | inline | none
    content_id: str
    sha256: str
    data: bytes = field(repr=False)
    is_clutter: bool = False
    clutter_reason: str = ""
    proposed_filename: str = ""

    def to_public(self) -> dict:
        return {
            "index": self.index,
            "original_filename": self.original_filename,
            "content_type": self.content_type,
            "size": self.size,
            "size_human": human_size(self.size),
            "disposition": self.disposition,
            "content_id": self.content_id,
            "sha256": self.sha256,
            "is_clutter": self.is_clutter,
            "clutter_reason": self.clutter_reason,
            "include_default": not self.is_clutter,
            "proposed_filename": self.proposed_filename,
        }


@dataclass
class ParsedEmail:
    id: str
    source_name: str
    raw_sha256: str
    raw_size: int
    raw: bytes = field(repr=False)
    date: datetime | None = None
    subject: str = ""
    message_id: str = ""
    from_name: str = ""
    from_addr: str = ""
    to: list = field(default_factory=list)
    cc: list = field(default_factory=list)
    body_text: str = ""
    body_source: str = "none"   # plain | html | none
    attachments: list = field(default_factory=list)
    defects: list = field(default_factory=list)
    sender_role: str = UNKNOWN_ROLE
    suggested_category: str = DEFAULT_CATEGORY
    category_matches: list = field(default_factory=list)

    # ---- derived date strings ----
    @property
    def date_prefix(self) -> str:
        return self.date.strftime("%Y-%m-%d_%H%M") if self.date else UNDATED_PREFIX

    @property
    def date_day(self) -> str:
        return self.date.strftime("%Y-%m-%d") if self.date else UNDATED_PREFIX[:10]

    @property
    def date_iso(self) -> str:
        return self.date.isoformat(timespec="seconds") if self.date else ""

    @property
    def from_display(self) -> str:
        return _format_address(self.from_name, self.from_addr)

    def to_public(self, body_limit: int = 50000) -> dict:
        body = self.body_text
        truncated = len(body) > body_limit
        return {
            "id": self.id,
            "source_name": self.source_name,
            "raw_sha256": self.raw_sha256,
            "raw_size": self.raw_size,
            "raw_size_human": human_size(self.raw_size),
            "date_iso": self.date_iso,
            "date_prefix": self.date_prefix,
            "date_day": self.date_day,
            "date_display": self.date.strftime("%Y-%m-%d %H:%M") if self.date else "Undated",
            "subject": self.subject,
            "message_id": self.message_id,
            "from": self.from_display,
            "from_addr": self.from_addr,
            "to": self.to,
            "cc": self.cc,
            "sender_role": self.sender_role,
            "body_text": body[:body_limit] + ("\n\n[… truncated in preview …]" if truncated else ""),
            "body_source": self.body_source,
            "snippet": re.sub(r"\s+", " ", body[:400]).strip(),
            "attachments": [a.to_public() for a in self.attachments],
            "defects": self.defects,
            "suggested_category": self.suggested_category,
            "category_matches": self.category_matches,
        }


# --------------------------------------------------------------------------- #
# MIME walking
# --------------------------------------------------------------------------- #

def _part_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None:
        raw = part.get_payload()
        if isinstance(raw, str):
            return _fix_surrogates(raw)
        return ""
    return decode_bytes(payload, part.get_content_charset())


def _disposition(part: Message) -> str:
    try:
        return (part.get_content_disposition() or "none").lower()
    except Exception:
        return "none"


def _filename(part: Message) -> str | None:
    try:
        name = part.get_filename()
    except Exception:
        name = None
    if not name:
        # Some mailers only put the name on Content-Type (name=...)
        try:
            name = part.get_param("name")
            if isinstance(name, tuple):  # RFC 2231 tuple
                name = email.utils.collapse_rfc2231_value(name)
        except Exception:
            name = None
    return str(name) if name else None


def _walk(part: Message, plain: list, htmls: list, atts: list, depth: int = 0) -> None:
    if depth > MAX_MIME_DEPTH:
        return
    ctype = (part.get_content_type() or "application/octet-stream").lower()
    disp = _disposition(part)
    fname = _filename(part)

    # Attached / forwarded e-mails are preserved whole as .eml evidence.
    if ctype == "message/rfc822":
        inner = part.get_payload()
        if isinstance(inner, list) and inner:
            inner = inner[0]
        try:
            data = inner.as_bytes() if isinstance(inner, Message) else bytes(part.get_payload(decode=True) or b"")
        except Exception:
            data = _part_text(part).encode("utf-8", errors="replace")
        if not fname and isinstance(inner, Message):
            subj = _safe_header(inner, "Subject")
            fname = (subj or "forwarded_message")[:80] + ".eml"
        atts.append((part, ctype, disp if disp != "none" else "attachment", fname, data))
        return

    if part.is_multipart():
        for child in part.iter_parts() if isinstance(part, EmailMessage) else part.get_payload():
            _walk(child, plain, htmls, atts, depth + 1)
        return

    is_body_type = ctype in ("text/plain", "text/html")
    if is_body_type and disp != "attachment" and not fname:
        (plain if ctype == "text/plain" else htmls).append(_part_text(part))
        return

    try:
        data = part.get_payload(decode=True)
    except Exception:
        data = None
    if data is None:
        raw = part.get_payload()
        data = raw.encode("utf-8", errors="surrogateescape") if isinstance(raw, str) else b""
    atts.append((part, ctype, disp, fname, data))


def parse_eml(raw: bytes, source_name: str, config: dict | None = None) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail. Never modifies ``raw``."""
    raw = bytes(raw)
    msg = email.message_from_bytes(raw, policy=policy.default)
    digest = sha256_bytes(raw)
    pe = ParsedEmail(id=digest, source_name=source_name, raw_sha256=digest,
                     raw_size=len(raw), raw=raw)

    # ---- headers ----
    pe.subject = _safe_header(msg, "Subject")
    pe.message_id = _safe_header(msg, "Message-ID")
    date_str = _safe_header(msg, "Date")
    if date_str:
        try:
            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:          # "-0000" / missing zone => assume UTC
                dt = dt.replace(tzinfo=timezone.utc)
            pe.date = dt.astimezone()      # convert to the machine's local time
        except Exception:
            pe.defects.append(f"Unparseable Date header: {date_str!r}")
    else:
        pe.defects.append("Missing Date header")

    senders = _parse_addresses(_safe_header_all(msg, "From"))
    if senders:
        pe.from_name, pe.from_addr = senders[0]
    pe.to = [_format_address(n, a) for n, a in _parse_addresses(_safe_header_all(msg, "To"))]
    pe.cc = [_format_address(n, a) for n, a in _parse_addresses(_safe_header_all(msg, "Cc"))]

    # ---- body & attachments ----
    plain, htmls, raw_atts = [], [], []
    try:
        _walk(msg, plain, htmls, raw_atts)
    except Exception as exc:  # extremely malformed structure
        pe.defects.append(f"MIME walk aborted: {exc}")

    plain_text = normalize_whitespace("\n\n".join(t for t in plain if t.strip()))
    if plain_text:
        pe.body_text, pe.body_source = plain_text, "plain"
    elif htmls:
        pe.body_text, pe.body_source = html_to_text("\n".join(htmls)), "html"

    for i, (part, ctype, disp, fname, data) in enumerate(raw_atts):
        cid = ""
        try:
            cid = (str(part.get("Content-ID", "")) or "").strip().strip("<>")
        except Exception:
            pass
        pe.attachments.append(Attachment(
            index=i,
            original_filename=safe_original_filename(fname, i, ctype),
            content_type=ctype,
            size=len(data),
            disposition=disp,
            content_id=cid,
            sha256=sha256_bytes(data),
            data=data,
        ))

    try:
        for d in msg.defects:
            pe.defects.append(type(d).__name__)
    except Exception:
        pass

    annotate(pe, config or {})
    return pe


def annotate(pe: ParsedEmail, config: dict) -> ParsedEmail:
    """(Re)apply config-dependent fields: role, clutter flags, names, category."""
    threshold_kb = float(config.get("ignore_inline_images_under_kb", 15) or 0)
    pe.sender_role = resolve_role(pe.from_addr, config.get("role_mappings", {}))
    for att in pe.attachments:
        att.is_clutter, att.clutter_reason = False, ""
        if att.content_type.startswith("image/") and att.size < threshold_kb * 1024:
            if att.disposition != "attachment":
                att.is_clutter = True
                att.clutter_reason = f"Inline image under {threshold_kb:g} KB (likely signature logo / tracking pixel)"
            elif att.content_id:
                att.is_clutter = True
                att.clutter_reason = f"Embedded (Content-ID) image under {threshold_kb:g} KB"
        att.proposed_filename = standardized_filename(
            pe.date_day, pe.sender_role, pe.subject, att.original_filename, att.content_type)
    rules = config.get("category_rules") or DEFAULT_CATEGORY_RULES
    names = [a.original_filename for a in pe.attachments if not a.is_clutter]
    pe.suggested_category, pe.category_matches = suggest_category(
        pe.subject, pe.body_text, names, rules)
    return pe
