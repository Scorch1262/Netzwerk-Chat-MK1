# Netzwerk-Chat - packt das Brume-2-Offline-Paket (Hilfsskript fuer Windows).
# tar.gz mit Unix-Rechten, damit install.sh auf der Brume 2 ausfuehrbar ist.
import io
import os
import re
import sys
import tarfile

here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, "netzwerk_chat.py")
if not os.path.isfile(src):
    src = os.path.join(here, "..", "netzwerk_chat.py")
if not os.path.isfile(src):
    print("[FEHLER] netzwerk_chat.py nicht gefunden.")
    sys.exit(1)
m = re.search(r'^VERSION = "([^"]+)"', open(src, encoding="utf-8").read(), re.M)
version = m.group(1) if m else "unbekannt"

top = "NetzwerkChat-brume2"
out = os.path.join(here, "NetzwerkChat-v%s-brume2-offline.tar.gz" % version)


def add(tar, path, arcname, mode):
    data = open(path, "rb").read()
    if arcname.endswith(".sh"):
        data = data.replace(b"\r\n", b"\n")          # Shell-Skripte immer mit LF
    info = tarfile.TarInfo(arcname)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


with tarfile.open(out, "w:gz") as tar:
    add(tar, src, top + "/netzwerk_chat.py", 0o644)
    add(tar, os.path.join(here, "install.sh"), top + "/install.sh", 0o755)
    add(tar, os.path.join(here, "uninstall.sh"), top + "/uninstall.sh", 0o755)
    add(tar, os.path.join(here, "ANLEITUNG_BRUME2.md"), top + "/ANLEITUNG_BRUME2.md", 0o644)
    ipk = os.path.join(here, "ipk")
    for name in sorted(os.listdir(ipk)):
        add(tar, os.path.join(ipk, name), top + "/ipk/" + name, 0o644)

print("=" * 60)
print(" FERTIG:", out)
print(" Diese Datei auf die Brume 2 kopieren und dort installieren")
print(" (siehe ANLEITUNG_BRUME2.md).")
print("=" * 60)
