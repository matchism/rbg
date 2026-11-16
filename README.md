# Legal EML Archiver

An offline tool for organizing legal correspondence. It parses raw `.eml` files, extracts and renames attachments, logs a SHA-256 hash for every file, and writes an archive you can search and filter on your own disk. A local review UI lets you record a decision for each email before the archive is written.

- **No dependencies.** It uses only the Python 3.9+ standard library. You don't need `pip`, Node or any CDN.
- **Works air-gapped.** The server binds to `127.0.0.1` only. Neither the UI nor the generated dashboard loads anything external, and a Content-Security-Policy enforces that.
- **Chain of custody.** Original `.eml` files are only ever opened read-only. Byte-for-byte copies go into a read-only vault. After writing, every file is hashed again from disk and checked against its import hash.

---

## ⚠️ OpSec / privacy warning

This repository is meant to be **public code only**. Client material must never be committed.

- `config.json` holds real email addresses and is git-ignored. Only `config.example.json`, with placeholder data, belongs in git.
- `.gitignore` also excludes `*.eml`, `Legal_Archive_*/`, CSVs, PDFs, Office files and common input/output folders. **Don't override it with `git add -f`.**
- Keep input and output folders **outside this repository**, ideally on an encrypted volume (FileVault / BitLocker / VeraCrypt).
- Generated archives contain privileged content. Treat them like the original file.
- Decision notes stay in browser memory only until you export. The app writes no caches, logs or temp files containing email content outside the archive you choose.

---

## Quick start

| OS | Launch |
|---|---|
| macOS | Double-click `launch_mac.command`. The first time, right-click → Open to get past Gatekeeper. |
| Windows | Double-click `launch_windows.bat` |
| Any | `python3 app.py` (options: `--port 8765`, `--no-browser`) |

On first run, `config.json` is created from `config.example.json`, and your browser opens at `http://127.0.0.1:8765/`. If that port is busy, the app picks the next free one.

## Workflow

1. **Import.** Drag `.eml` files onto the page, or enter an absolute folder path and click **Scan folder**. Identical files, matched by SHA-256, are skipped.
2. **Sender roles.** Map full addresses (`counsel@firm.com`) or whole domains (`@firm.com` / `firm.com`) to roles such as Counsel, Client, Opposing or Court. Unmapped senders show as `Unknown`. Settings are saved to `config.json`.
3. **Review and decide.** For each email you can:
   - Read the date, role, subject and the expandable body.
   - Tick or untick attachments. Inline images below the threshold (default **15 KB**) are flagged as signature clutter and unticked.
   - Change the auto-suggested **Decision Category**.
   - Write a **Decision / Context Note**.
4. **Generate the archive.** Enter an output folder and click **Generate Offline Archive**.

## Output

```text
Legal_Archive_[YYYY-MM-DD_HHMM]/
├── 00_Decision_Dashboard.html   searchable/filterable offline report (tabs, notes, hashes, relative links)
├── 00_Master_Audit_Log.csv      UTF-8-SIG; one row per archived attachment (or per email without one)
├── 01_Action_Required/
├── 02_Drafts_And_Reviews/
├── 03_Executed_And_Final/
├── 04_Financials_And_Billing/
├── 05_General_Reference/
└── 99_Raw_EML_Vault/            unmodified originals, prefixed [YYYY-MM-DD_HHMM]_, read-only
```

Attachment names follow `[YYYY-MM-DD]_[SenderRole]_[SanitizedSubject]_[OriginalFilename].[ext]`:

- `Re:`/`Fwd:` prefixes are stripped from the subject, and the subject is cut to 40 characters at a word boundary.
- Characters that are invalid on Windows or macOS are replaced, and reserved names such as `CON` are escaped.
- Path components are removed from attachment names, which blocks path traversal.
- If two files would get the same name, the later one gets `_2`, `_3` and so on.

The audit log columns are: `Timestamp, Sender_Role, From, To, Subject, Category, Decision_Note, Standardized_Filename, Relative_Path, Attachment_SHA256, Raw_EML_SHA256`. Any cell that begins with `= + - @` is prefixed with `'` so spreadsheets don't treat it as a formula.

**Verifying a file yourself:** run `shasum -a 256 <file>` on macOS/Linux, or `certutil -hashfile <file> SHA256` on Windows, and compare the result with the log.

## Auto-categorization

The app scores the keywords in `config.json → category_rules`. Subject matches count ×3, attachment-name matches ×2, and body matches ×1 (capped). The highest score wins. On a tie, the lower-numbered category wins, so *Action Required* comes out ahead. If nothing matches, the email goes to `05_General_Reference`. You can edit the keyword lists in `config.json`.

## Project layout

| File | Purpose |
|---|---|
| `app.py` | Entry point, config bootstrap, `127.0.0.1` HTTP server and JSON API |
| `parser_engine.py` | RFC 5322/MIME parsing, charset fallbacks, body/attachment extraction, roles, categories, naming |
| `archive_builder.py` | Atomic archive writer with hash verification, CSV and dashboard output |
| `templates/ui.html` | Review UI (inline CSS/JS) |
| `templates/dashboard_template.html` | Template for the standalone dashboard |
| `config.example.json` | Placeholder configuration template |

## Security notes

- The server listens on loopback only. It checks the `Host` header to block DNS rebinding, and requires a random per-launch token in a custom header on every API call, which blocks CSRF from other browser tabs.
- An archive is first built in a hidden staging folder. It is renamed into place only after every hash checks out, so a failed export leaves nothing half-written.
- Message bodies are displayed as text only. Email HTML is never rendered, so remote images and tracking pixels never load.
- One limitation: an email forwarded *as an attachment* (`message/rfc822`) is saved by re-serializing the parsed message. Its bytes can differ slightly from what the sender's client produced, though it is hashed exactly as written. The outer original `.eml` in the vault is always byte-exact.
