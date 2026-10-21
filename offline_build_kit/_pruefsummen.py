# Netzwerk-Chat Offline-Build-Kit v1.0.0 - Hilfsskript fuer Schritt 2.
# Prueft die heruntergeladenen Wheels gegen offline_pakete/SHA256SUMS.txt.
import hashlib
import os
import sys

folder = sys.argv[1] if len(sys.argv) > 1 else "offline_pakete"
sums_file = os.path.join(folder, "SHA256SUMS.txt")
if not os.path.isfile(sums_file):
    print("[FEHLER] SHA256SUMS.txt fehlt in", folder)
    sys.exit(1)

bad = 0
with open(sums_file, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        expected, name = line.split(None, 1)
        name = name.lstrip("*")
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            print("   FEHLT  ", name)
            bad += 1
            continue
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest().lower() != expected.lower():
            print("   DEFEKT ", name)
            bad += 1
        else:
            print("   OK     ", name)

if bad:
    print("[FEHLER] %d Datei(en) fehlen oder sind beschaedigt." % bad)
    sys.exit(1)
print("Alle Pakete in Ordnung.")
