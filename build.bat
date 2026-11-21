@echo off
REM Builds dist\PCShield.exe - needs Python 3.10-3.13 from python.org ("Add python.exe to PATH" ticked).
REM Set PYTHON=C:\path\to\python.exe to use a specific Python (the GitHub build does this).
setlocal
cd /d "%~dp0"

REM PC Shield keeps running in the tray, and a running copy locks dist\PCShield.exe
tasklist /fi "imagename eq PCShield.exe" 2>nul | find /i "PCShield.exe" >nul && (
  echo Closing the running PC Shield so the new build can replace it...
  taskkill /f /im PCShield.exe >nul 2>&1
  ping -n 3 127.0.0.1 >nul
)

set "PY="
if defined PYTHON set PY="%PYTHON%"
if not defined PY for %%V in (3.13 3.12 3.11 3.10) do (
  if not defined PY ( py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V" )
)
if not defined PY (
  echo Couldn't find Python 3.10-3.13. Install 3.12 from https://www.python.org/downloads/ and run this again.
  goto :err
)
echo Using %PY%

%PY% -m pip install --upgrade pip >nul
%PY% -m pip install --upgrade pywebview psutil pystray pillow pyinstaller || goto :err

REM --exclude-module: optional extras other packages drag in; PC Shield never uses them (smaller exe)
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
  --name PCShield --icon icon.ico ^
  --add-data "web;web" --add-data "icons;icons" ^
  --hidden-import clr --hidden-import pystray._win32 ^
  --exclude-module numpy --exclude-module cryptography --exclude-module jinja2 --exclude-module mako ^
  --exclude-module pygments --exclude-module tkinter --exclude-module gi ^
  app.py || goto :err

echo.
echo Built: %~dp0dist\PCShield.exe
echo (If Defender flags the new exe, that's a common PyInstaller false positive - exclude the dist folder.)
if not defined CI pause
exit /b 0

:err
echo Build failed - scroll up for the error.
if not defined CI pause
exit /b 1
