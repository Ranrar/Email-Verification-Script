@echo off
cd /d "%~dp0"
if exist "main.py" (
    py main.py
) else (
    echo main.py not found in the current directory.
)
pause