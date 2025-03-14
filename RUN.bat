@echo off
:: Change to the directory where the batch file is located
cd /d "%~dp0"

:: Ensure the script exists and run it
if exist "main.py" (
    echo Running EVS...
    py main.py
) else (
    echo main.py not found in the current directory.
)

pause