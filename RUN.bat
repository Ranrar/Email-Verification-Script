@echo off
:: Change to the directory where the batch file is located
cd /d "%~dp0"

:: Ensure the script exists and run it
if exist "EVS.py" (
    echo Running EVS.py...
    py EVS.py
) else (
    echo EVS.py not found in the current directory.
)

pause