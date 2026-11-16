#!/bin/bash
# Double-click in Finder to start Legal EML Archiver (offline, 127.0.0.1 only).
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
  python3 app.py "$@"
else
  echo "Python 3 was not found. Install it from python.org (or run: xcode-select --install)."
  read -r -p "Press Enter to close..."
fi
