@echo off
REM ============================================================
REM  Netzwerk-Chat Offline-Build-Kit v1.1.0
REM  Schritt 3 von 3 - auf dem Windows-10-PC ausfuehren.
REM
REM  Baut aus netzwerk_chat.py die exe - genauso wie der
REM  GitHub-Actions-Workflow (--onefile --console).
REM  Ergebnis: fertige_exe\NetzwerkChat-v<Version>-windows.exe
REM ============================================================

setlocal EnableDelayedExpansion
cd /d "%~dp0"
set "KITDIR=%~dp0"

echo.
echo === Netzwerk-Chat Offline-Build-Kit v1.1.0 ===
echo === Schritt 3: exe bauen ===
echo.

if not exist "venv\Scripts\pyinstaller.exe" (
    echo [FEHLER] venv mit PyInstaller wurde nicht gefunden.
    echo Bitte zuerst "2_win10_pakete_installieren.bat" ausfuehren.
    pause
    exit /b 1
)

REM --- netzwerk_chat.py suchen: Projektordner (eine Ebene hoeher) oder Kit-Ordner ---
set "APPPY="
if exist "%KITDIR%..\netzwerk_chat.py" set "APPPY=%KITDIR%..\netzwerk_chat.py"
if not defined APPPY if exist "%KITDIR%netzwerk_chat.py" set "APPPY=%KITDIR%netzwerk_chat.py"
if not defined APPPY (
    echo [FEHLER] netzwerk_chat.py nicht gefunden.
    echo Der Ordner offline_build_kit muss im Netzwerk-Chat-Ordner liegen
    echo ^(neben netzwerk_chat.py^) - oder netzwerk_chat.py hierher kopieren.
    pause
    exit /b 1
)
for %%I in ("!APPPY!") do (
    set "APPPY=%%~fI"
    set "APPDIR=%%~dpI"
)
echo Quelle: !APPPY!

REM --- Version aus VERSION = "x.y.z" lesen ---
set "APPVER="
set "NC_APPPY=!APPPY!"
for /f "usebackq delims=" %%V in (`venv\Scripts\python.exe -c "import re,os;m=re.search(r'^VERSION\s*=\s*[\x22\x27]([0-9A-Za-z.\-]+)',open(os.environ['NC_APPPY'],encoding='utf-8').read(),re.M);print(m.group(1) if m else '')"`) do set "APPVER=%%V"
if not defined APPVER (
    echo [FEHLER] Version in netzwerk_chat.py nicht gefunden.
    pause
    exit /b 1
)
echo Version: !APPVER!

set "EXEBASE=NetzwerkChat"
set "EXENAME=NetzwerkChat-v!APPVER!-windows"
if not exist "fertige_exe" mkdir "fertige_exe"
if exist "build_tmp" rmdir /s /q "build_tmp"

echo.
echo Baue !EXENAME!.exe ... ^(dauert ca. 1 Minute^)
echo.
pushd "!APPDIR!"
"!KITDIR!venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --console ^
    --name "!EXEBASE!" ^
    --distpath "!KITDIR!build_tmp\dist" --workpath "!KITDIR!build_tmp\work" ^
    --specpath "!KITDIR!build_tmp" "!APPPY!"
set "PYIERR=!errorlevel!"
popd
if not "!PYIERR!"=="0" (
    echo [FEHLER] Build von !EXENAME!.exe fehlgeschlagen.
    pause
    exit /b 1
)
if not exist "build_tmp\dist\!EXEBASE!.exe" (
    echo [FEHLER] PyInstaller lief durch, aber die exe fehlt.
    pause
    exit /b 1
)
move /y "build_tmp\dist\!EXEBASE!.exe" "fertige_exe\!EXENAME!.exe" >nul

REM Kurztest der exe
"fertige_exe\!EXENAME!.exe" --help >nul 2>nul
if errorlevel 1 (
    echo [WARNUNG] Kurztest der exe ^(--help^) fehlgeschlagen.
)

REM Aufraeumen der PyInstaller-Zwischendateien
if exist "build_tmp" rmdir /s /q "build_tmp"

echo.
echo ============================================================
echo  FERTIG
echo.
echo  Im Ordner
echo    %~dp0fertige_exe
echo  liegt jetzt:
dir /b "fertige_exe"
echo.
echo  Die exe in einen eigenen Ordner legen und starten - dort
echo  wird netzwerk_chat.db angelegt. Das Konsolenfenster zeigt
echo  die Adresse im Netzwerk an ^(Standard-Port 8090, ggf. in
echo  der Windows-Firewall fuer private Netzwerke freigeben^).
echo ============================================================
echo.
pause
