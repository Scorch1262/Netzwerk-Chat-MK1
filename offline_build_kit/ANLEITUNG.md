# Netzwerk-Chat – Windows-exe offline bauen: Mac oder Windows lädt, Win10 baut

**Offline-Build-Kit v1.1.0**

Drei Schritte. Python 3.11 (64-Bit) muss auf dem Windows-10-PC
bereits installiert sein. Das Kit lädt auf einem Rechner mit Internet (Mac **oder** Windows)
PyInstaller herunter,
installiert es auf dem Windows-PC ohne Internet und baut dort die exe. Das
Ergebnis entspricht dem GitHub-Actions-Build: `NetzwerkChat-v<Version>-windows.exe`.

Netzwerk-Chat selbst braucht nur die Python-Standardbibliothek – deshalb
lädt das Kit nur PyInstaller und dessen Abhängigkeiten.

```
Netzwerk-Chat/
├── netzwerk_chat.py                     <- wird gebaut
└── offline_build_kit/
    ├── 1_mac_pakete_herunterladen.sh    <- Schritt 1 auf dem Mac (mit Internet)
    ├── 1_windows_pakete_herunterladen.bat <- ODER Schritt 1 auf einem Windows-PC (mit Internet)
    ├── 2_win10_pakete_installieren.bat  <- läuft auf dem Win10-PC
    ├── 3_win10_exe_bauen.bat            <- läuft auf dem Win10-PC
    ├── _pruefsummen.py                  <- Hilfsskript (Prüfsummen)
    └── ANLEITUNG.md                     <- diese Datei
```

---

## Schritt 1 – Variante Mac

1. Die Netzwerk-Chat-ZIP entpacken.
2. Terminal öffnen, in den Kit-Ordner wechseln und das Skript starten:
   ```bash
   cd ~/Downloads/Netzwerk-Chat/offline_build_kit
   chmod +x 1_mac_pakete_herunterladen.sh
   ./1_mac_pakete_herunterladen.sh
   ```
3. Es entstehen
   - der Ordner **`offline_pakete`** mit den `.whl`-Dateien für
     `pyinstaller` (6.10.0) samt `pefile`, `pywin32-ctypes`, `altgraph`,
     `pyinstaller-hooks-contrib`, `packaging` und `setuptools` – passend für
     **Windows 64-Bit / Python 3.11**, egal welches Python auf dem Mac läuft
     (auf dem Mac wird nichts installiert),
   - die Prüfsummen-Datei `offline_pakete/SHA256SUMS.txt`,
   - die Datei **`paketliste.txt`**.
4. Den **kompletten Ordner `Netzwerk-Chat`** (mit `netzwerk_chat.py` und
   `offline_build_kit`) auf den Windows-PC kopieren, z. B. per USB-Stick.

## Schritt 1 – Variante Windows

Auf einem **beliebigen Windows-PC mit Internet** (Python 3 in irgendeiner Version mit pip):
1. Die Netzwerk-Chat-ZIP entpacken.
2. Im Ordner `offline_build_kit` doppelt auf **`1_windows_pakete_herunterladen.bat`** klicken.
3. Es entstehen dieselben Dateien wie beim Mac-Skript (`offline_pakete` mit Prüfsummen,
   `paketliste.txt`) – immer passend für **Python 3.11 / 64-Bit** auf dem Ziel-PC.
4. Den kompletten Ordner `Netzwerk-Chat` auf den Windows-10-PC ohne Internet kopieren.

Ist das der **gleiche** PC, auf dem gebaut wird, einfach direkt mit Schritt 2 weitermachen.

## Schritt 2 – auf dem Windows-10-PC

Im Ordner `offline_build_kit` doppelt auf **`2_win10_pakete_installieren.bat`** klicken.

- Sucht ein passendes Python 3.11 (64-Bit) – erst `python`, dann `py -3.11`.
- Prüft alle Pakete gegen die Prüfsummen.
- Legt die virtuelle Umgebung `venv` an und installiert PyInstaller
  **ohne Internet** aus `offline_pakete`.

Nur einmal nötig. Bei späteren Versionen von Netzwerk-Chat direkt mit Schritt 3 weitermachen.

## Schritt 3 – auf dem Windows-10-PC

Doppelklick auf **`3_win10_exe_bauen.bat`**.

- Nimmt `netzwerk_chat.py` aus dem übergeordneten Ordner (oder aus dem Kit-Ordner).
- Liest die Version aus `VERSION = "…"`.
- Baut wie der GitHub-Workflow (`--onefile --console`).
- Ergebnis: **`fertige_exe\NetzwerkChat-v<Version>-windows.exe`**.

Neue Programmversion bauen: neue `netzwerk_chat.py` über die alte kopieren
und Schritt 3 erneut starten.

---

## exe benutzen

1. Die exe in einen **eigenen Ordner** legen und starten.
2. Daneben entsteht `netzwerk_chat.db`.
3. Das Konsolenfenster zeigt die Adresse an: `http://<Rechnername>:8090`.
   Beim ersten Start fragt Windows ggf. nach der Firewall-Freigabe:
   „Private Netzwerke" erlauben.

---

## Was dieses Kit nicht baut

- **macOS-App:** lässt sich nur auf einem Mac bauen. Auf dem Mac läuft
  Netzwerk-Chat aber auch direkt mit `python3 netzwerk_chat.py`.

---

## Fehlerbehebung

- **„Kein passendes Python 3.11 (64-Bit) gefunden"** (Schritt 2) →
  `python --version` bzw. `py --list` prüfen. Die Pakete aus Schritt 1 passen
  nur zu 3.11 / 64-Bit. Anderes Python? Dann im Download-Skript oben
  `PY_VER`/`PY_TAG` anpassen (z. B. `3.12` / `312`) und Schritt 1 wiederholen.
- **„DEFEKT"/„FEHLT" bei der Paketprüfung** → Kopiervorgang unvollständig;
  `offline_pakete` erneut auf den PC kopieren.
- **„venv mit PyInstaller wurde nicht gefunden"** (Schritt 3) → erst Schritt 2
  erfolgreich durchlaufen lassen, im selben Ordner.
- **„netzwerk_chat.py nicht gefunden"** → `offline_build_kit` muss im
  Netzwerk-Chat-Ordner neben `netzwerk_chat.py` liegen.
- **Windows Defender meldet die neue exe** → normal bei frisch gebauten,
  unsignierten PyInstaller-Dateien: „Trotzdem ausführen" bzw. Ausnahme eintragen.
- **Port 8090 belegt** → exe mit `--port 8091` (o. ä.) starten.
