#!/usr/bin/env bash
# ============================================================
#  Netzwerk-Chat - Brume-2-Offline-Paket erstellen (Mac)
#  Auf dem Mac MIT Internet ausfuehren. Laedt Python 3 fuer die
#  GL.iNet Brume 2 in den Ordner "ipk" und packt alles zu
#  NetzwerkChat-brume2-offline.tar.gz - das wird auf die Brume 2 kopiert.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

PYTHON=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then PYTHON="$c"; break; fi
done
[ -n "$PYTHON" ] || { echo "[FEHLER] python3 nicht gefunden (https://www.python.org)."; exit 1; }

"$PYTHON" brume_pakete_laden.py --ziel ipk

"$PYTHON" _paket_packen.py
