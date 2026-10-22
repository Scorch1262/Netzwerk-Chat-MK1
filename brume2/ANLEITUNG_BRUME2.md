# Netzwerk-Chat auf der GL.iNet Brume 2 – Offline-Installation

**Installer v1.0.0** · für GL.iNet Brume 2 (GL-MT2500, Firmware 4.x = OpenWrt 21.02, aarch64)

Die Brume 2 übernimmt die Rolle des Server-Rechners. Alle anderen öffnen nur die Seite im
Browser. Das Offline-Paket enthält Python 3 – auf der Brume 2 ist **kein Internet** nötig.

## 1. Offline-Paket besorgen

**Variante A – fertig aus dem GitHub-Release:**
`NetzwerkChat-v<Version>-brume2-offline.tar.gz` herunterladen.

**Variante B – selbst erstellen** (Rechner mit Internet, Python 3 nötig), im Ordner `brume2`:
- **Mac:** Terminal → `cd …/Netzwerk-Chat/brume2` → `bash pakete_herunterladen_mac.sh`
- **Windows:** Doppelklick auf `pakete_herunterladen_windows.bat`

Ergebnis: `NetzwerkChat-v<Version>-brume2-offline.tar.gz` im Ordner `brume2`.

## 2. Auf die Brume 2 kopieren

Die IP-Adresse der Brume 2 im eigenen Netz verwenden (Werkseinstellung: `192.168.8.1`).

**Windows (PowerShell) oder Mac (Terminal):**
```
scp -O NetzwerkChat-v1.5.0-brume2-offline.tar.gz root@192.168.8.1:/tmp/
```
`-O` ist nötig, weil die Brume 2 nur das klassische SCP-Protokoll kann.
Alternativ mit **WinSCP** (Protokoll „SCP“) nach `/tmp` kopieren.

## 3. Installieren

```
ssh root@192.168.8.1
cd /tmp
tar -xzf NetzwerkChat-v1.5.0-brume2-offline.tar.gz
sh NetzwerkChat-brume2/install.sh
```

Der Installer
- installiert Python 3 aus dem Ordner `ipk` – nur die Pakete, die noch fehlen
  (ist Python 3 schon vorhanden, wird nichts installiert),
- legt das Programm in **`/root/Netzwerk-Chat`** ab (neben den anderen Programmen),
- richtet den **Autostart** ein (`/etc/init.d/netzwerk-chat`, startet nach jedem Neustart),
- öffnet den Port in der Firewall auch für den WAN-Port,
- zeigt am Ende die Adressen an, z. B. `http://GL-MT2500:8090`.

Anderer Port (8090 belegt?): `PORT=8091 sh NetzwerkChat-brume2/install.sh`

Ein erneuter Aufruf von `install.sh` aktualisiert das Programm (z. B. bei einer neuen Version).

## Bedienung

| Aktion | Befehl |
|---|---|
| Status | `/etc/init.d/netzwerk-chat status` |
| Neustart | `/etc/init.d/netzwerk-chat restart` – **verwirft die Chats** |
| Log | `logread -e netzwerk_chat` |
| Entfernen | `sh /root/Netzwerk-Chat/uninstall.sh` (Python 3 bleibt installiert) |

## Automatische Windows-Anmeldung

Edge/Chrome melden den Windows-Benutzer nur automatisch an, wenn die Seite über einen
**Namen ohne Punkt** aufgerufen wird (z. B. `http://GL-MT2500:8090`) – dafür muss der Name der
Brume 2 im Netz auflösbar sein (DNS des Routers). Wird die **IP-Adresse** verwendet, diese
in Windows unter *Internetoptionen → Sicherheit → Lokales Intranet → Sites → Erweitert* eintragen
(z. B. `http://192.168.8.1`). Firefox und Windows-Benachrichtigungen: einmalige Freigabe über die Anmeldeseite bzw. den Button
**MELDUNG: EINRICHTEN** im Chat (siehe README).

## Fehlerbehebung

- **„Datei fehlt: ipk/…“** → Archiv unvollständig kopiert, erneut kopieren und entpacken.
- **„opkg-Installation fehlgeschlagen“** → Firmware-Version prüfen (`cat /etc/openwrt_release`).
  Das Paket ist für OpenWrt 21.02 / aarch64_cortex-a53. Mit Internet: `opkg update && opkg install python3`.
- **„Port … ist bereits belegt“** → mit `PORT=…` einen anderen Port wählen.
- **Seite nicht erreichbar** → `/etc/init.d/netzwerk-chat status` und `logread -e netzwerk_chat` prüfen.
