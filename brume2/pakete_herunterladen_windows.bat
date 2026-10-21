@echo off
REM ============================================================
REM  Netzwerk-Chat - Brume-2-Offline-Paket erstellen (Windows)
REM  Auf einem Windows-PC MIT Internet ausfuehren (Python 3 noetig).
REM  Laedt Python 3 fuer die GL.iNet Brume 2 in den Ordner "ipk"
REM  und packt alles zu NetzwerkChat-v<Version>-brume2-offline.tar.gz
REM ============================================================
setlocal
cd /d "%~dp0"

set "PYCMD="
where python >nul 2>nul && python -c "import sys;sys.exit(0 if sys.version_info[0]==3 else 1)" >nul 2>nul && set "PYCMD=python"
if not defined PYCMD (
    where py >nul 2>nul && py -3 -c "pass" >nul 2>nul && set "PYCMD=py -3"
)
if not defined PYCMD (
    echo [FEHLER] Python 3 nicht gefunden. Bitte von https://www.python.org installieren.
    pause
    exit /b 1
)

%PYCMD% brume_pakete_laden.py --ziel ipk
if errorlevel 1 (
    pause
    exit /b 1
)

%PYCMD% _paket_packen.py
if errorlevel 1 (
    pause
    exit /b 1
)
echo.
pause
