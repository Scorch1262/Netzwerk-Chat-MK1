@echo off
REM ============================================================
REM  Netzwerk-Chat Offline-Build-Kit v1.1.0
REM  Schritt 1 von 3 (Windows-Variante) - auf einem Windows-PC
REM  MIT Internet ausfuehren. Python 3 (beliebige Version) noetig.
REM
REM  Laedt PyInstaller und alle Abhaengigkeiten als Wheels fuer
REM  Windows 64-Bit / Python 3.11 in den Ordner "offline_pakete".
REM  Es wird dabei nichts installiert.
REM ============================================================

setlocal
cd /d "%~dp0"

set "PY_VER=3.11"
set "PY_TAG=311"
set "PYINSTALLER=pyinstaller==6.10.0"

echo.
echo === Netzwerk-Chat Offline-Build-Kit v1.1.0 ===
echo === Schritt 1: Pakete fuer Windows herunterladen ===
echo.

set "PYCMD="
where python >nul 2>nul && python -m pip --version >nul 2>nul && set "PYCMD=python"
if not defined PYCMD (
    where py >nul 2>nul && py -3 -m pip --version >nul 2>nul && set "PYCMD=py -3"
)
if not defined PYCMD (
    echo [FEHLER] Kein Python 3 mit pip gefunden.
    echo Python von https://www.python.org installieren und erneut starten.
    pause
    exit /b 1
)
echo Benutze: %PYCMD%

> "paketliste.txt" echo %PYINSTALLER%
echo Paketliste ^(paketliste.txt^):
type "paketliste.txt"

if exist "offline_pakete" rmdir /s /q "offline_pakete"
mkdir "offline_pakete"
> "offline_pakete\python_version.txt" echo %PY_VER%

REM pefile und pywin32-ctypes werden fuer PyInstaller unter Windows gebraucht -
REM explizit mitladen, damit das Ergebnis identisch zum Mac-Skript ist.
copy /y "paketliste.txt" "_download_reqs.txt" >nul
>> "_download_reqs.txt" echo pefile^>=2022.5.30
>> "_download_reqs.txt" echo pywin32-ctypes^>=0.2.0

echo.
echo Lade fertige Wheels herunter ^(Ziel: Windows 64-Bit, Python %PY_VER%^)...
%PYCMD% -m pip download -r "_download_reqs.txt" -d "offline_pakete" --platform win_amd64 --python-version %PY_TAG% --implementation cp --abi cp%PY_TAG% --only-binary=:all:
set "DLERR=%errorlevel%"
del "_download_reqs.txt" >nul 2>nul
if not "%DLERR%"=="0" (
    echo [FEHLER] Download fehlgeschlagen - Internetverbindung pruefen.
    pause
    exit /b 1
)

for %%P in (pyinstaller pefile pywin32_ctypes) do (
    if not exist "offline_pakete\%%P-*.whl" (
        echo [FEHLER] Kein Wheel fuer '%%P' heruntergeladen.
        pause
        exit /b 1
    )
)

%PYCMD% "_pruefsummen.py" "offline_pakete" --erzeugen
if errorlevel 1 (
    pause
    exit /b 1
)

echo.
echo Heruntergeladen:
dir /b "offline_pakete"
echo.
echo ============================================================
echo  FERTIG. Der Ordner "offline_pakete" enthaelt alle Pakete
echo  fuer Windows / Python %PY_VER%.
echo.
echo  Naechster Schritt: den kompletten Netzwerk-Chat-Ordner
echo  ^(mit netzwerk_chat.py und offline_build_kit inkl.
echo  offline_pakete und paketliste.txt^) auf den Win10-PC
echo  ohne Internet kopieren, z. B. per USB-Stick.
echo ============================================================
echo.
pause
