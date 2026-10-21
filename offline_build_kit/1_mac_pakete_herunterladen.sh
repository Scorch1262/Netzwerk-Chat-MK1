#!/usr/bin/env bash
# ============================================================
#  Netzwerk-Chat Offline-Build-Kit v1.1.0
#  Schritt 1 von 3 - auf dem Mac (mit Internet) ausfuehren.
#
#  Laedt PyInstaller und alle Abhaengigkeiten als fertige Wheels
#  fuer Windows 64-Bit / Python 3.11 in den Ordner "offline_pakete".
#  Auf dem Mac wird dabei nichts installiert.
#  (Netzwerk-Chat selbst braucht nur die Python-Standardbibliothek.)
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

PY_VER="3.11"                       # Python-Version auf dem Windows-PC
PY_TAG="${PY_VER/./}"               # -> 311
PYINSTALLER="pyinstaller==6.10.0"

echo
echo "=== Netzwerk-Chat Offline-Build-Kit v1.1.0 ==="
echo "=== Schritt 1: Pakete fuer Windows herunterladen ==="
echo

PYTHON=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -m pip --version >/dev/null 2>&1; then
        PYTHON="$c"; break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "[FEHLER] Kein python3 mit pip gefunden."
    echo "         Python von https://www.python.org installieren und erneut starten."
    exit 1
fi
echo "Benutze: $("$PYTHON" --version 2>&1) ($PYTHON)"

REQ_FILE="paketliste.txt"
echo "$PYINSTALLER" > "$REQ_FILE"
echo "Paketliste ($REQ_FILE):"
sed 's/^/   /' "$REQ_FILE"

rm -rf offline_pakete
mkdir -p offline_pakete
echo "$PY_VER" > offline_pakete/python_version.txt

echo
echo "Aktualisiere pip (falls moeglich)..."
"$PYTHON" -m pip install --upgrade pip --quiet 2>/dev/null \
    || echo "   (pip-Aktualisierung uebersprungen - kein Problem)"

# WICHTIG: "pip download --platform win_amd64" waehlt korrekt Windows-
# Wheels aus, wertet bedingte Abhaengigkeiten (z. B. sys_platform ==
# 'win32') aber anhand DIESES Macs aus. PyInstaller braucht unter
# Windows "pefile" und "pywin32-ctypes" - deshalb explizit ergaenzt.
cp "$REQ_FILE" _download_reqs.txt
{
    echo "pefile>=2022.5.30"
    echo "pywin32-ctypes>=0.2.0"
} >> _download_reqs.txt

echo
echo "Lade fertige Wheels herunter (Ziel: Windows 64-Bit, Python ${PY_VER})..."
"$PYTHON" -m pip download -r _download_reqs.txt -d offline_pakete \
    --platform win_amd64 --python-version "$PY_TAG" --implementation cp --abi "cp$PY_TAG" \
    --only-binary=:all:
rm -f _download_reqs.txt

for pkg in pyinstaller pefile pywin32_ctypes; do
    if ! ls offline_pakete/${pkg}-*.whl >/dev/null 2>&1; then
        echo "[FEHLER] Kein Wheel fuer '${pkg}' heruntergeladen."
        exit 1
    fi
done

# Pruefsummen fuer die Kontrolle auf dem Windows-PC
( cd offline_pakete && { shasum -a 256 *.whl > SHA256SUMS.txt 2>/dev/null \
    || sha256sum *.whl > SHA256SUMS.txt; } )

echo
echo "Heruntergeladen:"
ls -1 offline_pakete | sed 's/^/   /'

echo
echo "============================================================"
echo " FERTIG. Der Ordner 'offline_pakete' enthaelt jetzt alle"
echo " benoetigten .whl-Dateien fuer Windows/Python ${PY_VER}."
echo
echo " Naechster Schritt: den kompletten Netzwerk-Chat-Ordner"
echo " (mit netzwerk_chat.py und diesem Ordner offline_build_kit"
echo "  inkl. offline_pakete/ und paketliste.txt) auf den"
echo " Windows-10-PC kopieren, z. B. per USB-Stick."
echo "============================================================"
echo
