@echo off
REM ============================================================
REM  Netzwerk-Chat Offline-Build-Kit v1.0.0
REM  Schritt 2 von 3 - auf dem Windows-10-PC ausfuehren.
REM  Python 3.11 (64-Bit) muss auf diesem PC bereits installiert sein.
REM
REM  Installiert PyInstaller komplett OFFLINE aus dem Ordner
REM  "offline_pakete" (vom Mac-Skript) in eine neue virtuelle
REM  Umgebung "venv". Kein Internetzugriff noetig.
REM ============================================================

setlocal
cd /d "%~dp0"

echo.
echo === Netzwerk-Chat Offline-Build-Kit v1.0.0 ===
echo === Schritt 2: Pakete offline installieren ===
echo.

if not exist "offline_pakete\python_version.txt" (
    echo [FEHLER] Ordner "offline_pakete" fehlt oder ist unvollstaendig.
    echo Bitte zuerst auf dem Mac "1_mac_pakete_herunterladen.sh"
    echo ausfuehren und den kompletten Ordner hierher kopieren.
    pause
    exit /b 1
)
if not exist "paketliste.txt" (
    echo [FEHLER] "paketliste.txt" fehlt - sie entsteht in Schritt 1 auf dem Mac.
    pause
    exit /b 1
)

set /p PYVER=<"offline_pakete\python_version.txt"
echo Benoetigte Python-Version: %PYVER% ^(64-Bit^)

REM --- passendes Python suchen: erst "python", dann Python-Launcher "py" ---
set "PYCMD="
set "PYCHECK=import sys,struct;v=sys.argv[1].split('.');sys.exit(0 if list(sys.version_info[:2])==[int(v[0]),int(v[1])] and struct.calcsize('P')==8 else 1)"

where python >nul 2>nul
if not errorlevel 1 (
    python -c "%PYCHECK%" %PYVER% >nul 2>nul
    if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD (
    where py >nul 2>nul
    if not errorlevel 1 (
        py -%PYVER% -c "%PYCHECK%" %PYVER% >nul 2>nul
        if not errorlevel 1 set "PYCMD=py -%PYVER%"
    )
)
if not defined PYCMD (
    echo [FEHLER] Kein passendes Python %PYVER% ^(64-Bit^) gefunden.
    echo Pruefen mit:  python --version   bzw.   py --list
    pause
    exit /b 1
)
echo Gefunden: %PYCMD%
echo.

echo Pruefe Pakete ...
%PYCMD% "_pruefsummen.py" "offline_pakete"
if errorlevel 1 (
    echo Ordner "offline_pakete" erneut vom Mac kopieren.
    pause
    exit /b 1
)
echo.

if exist "venv" (
    echo Entferne alte venv ...
    rmdir /s /q "venv"
)
echo Lege virtuelle Umgebung "venv" an ...
%PYCMD% -m venv venv
if errorlevel 1 (
    echo [FEHLER] venv konnte nicht angelegt werden.
    pause
    exit /b 1
)

echo Installiere Pakete OFFLINE ...
"venv\Scripts\python.exe" -m pip install --no-index --find-links "offline_pakete" -r "paketliste.txt"
if errorlevel 1 (
    echo [FEHLER] Installation fehlgeschlagen - siehe Meldungen oben.
    pause
    exit /b 1
)

if not exist "venv\Scripts\pyinstaller.exe" (
    echo [FEHLER] PyInstaller wurde nicht installiert.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  FERTIG. PyInstaller ist offline installiert.
echo  Naechster Schritt: 3_win10_exe_bauen.bat starten.
echo ============================================================
echo.
pause
