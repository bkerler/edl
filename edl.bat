@echo off
setlocal
if not exist "%~dp0.venv\Scripts\edl.exe" (
    echo EDL is not installed. Run install_edl_win10_win11.ps1 from this directory first. 1>&2
    exit /b 1
)
"%~dp0.venv\Scripts\edl.exe" %*
exit /b %errorlevel%
