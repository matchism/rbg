@echo off
REM Double-click to start Legal EML Archiver (offline, 127.0.0.1 only).
setlocal
cd /d "%~dp0"
title Legal EML Archiver

where py >nul 2>nul && ( py -3 app.py %* & goto :end )
where python3 >nul 2>nul && ( python3 app.py %* & goto :end )
where python >nul 2>nul && ( python app.py %* & goto :end )

echo Python 3 was not found. Install it from https://www.python.org/downloads/ (tick "Add to PATH").

:end
echo.
pause
