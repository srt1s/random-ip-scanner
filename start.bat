@echo off
cd /d "%~dp0"
if exist "RandomIPScanner.exe" (
    start "" "%~dp0RandomIPScanner.exe" %*
) else (
    start "" pythonw "%~dp0main.py" %*
)
