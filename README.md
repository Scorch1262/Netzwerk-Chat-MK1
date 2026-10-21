# Netzwerk-Chat v1.2.1

Lokaler Netzwerk-Chat als Website. Das Programm läuft auf **einem** Rechner im Netzwerk –
alle anderen öffnen nur die Seite im Browser. Keine Installation auf den Arbeitsplätzen.

## Funktionen
- **Automatische Anmeldung über den Windows-Benutzer** (integrierte Windows-Anmeldung / NTLM –
  derselbe Benutzername, den `whoami` anzeigt)
- **Präsenz:** Alle Teilnehmer werden links angezeigt – Punkt grün = hat die Seite gerade geöffnet,
  Punkt leer = Seite geschlossen. Keine Aktivitätsanzeige.
- **Verschlüsselte Speicherung:** Chats werden in der Datenbank verschlüsselt abgelegt. Der Schlüssel
  existiert nur im Arbeitsspeicher und wird bei jedem Programmstart neu erzeugt.
- **Verlauf:** Jeder Chat mit einer Person wird beim erneuten Anklicken automatisch geladen –
  solange das Programm auf dem Server läuft. **Beim Neustart werden alle Chats verworfen.**
- Ungelesen-Zähler, Hinweiston (abschaltbar), Anzahl im Browser-Tab-Titel
- Nur Python-Standardbibliothek (Python ≥ 3.8) bzw. fertige `NetzwerkChat.exe`

## Start (auf dem Server-Rechner)
`NetzwerkChat.exe` aus dem GitHub-Release starten – oder mit Python:
```
python netzwerk_chat.py
```
(bzw. Doppelklick auf `start_netzwerk_chat.bat`).

Optionen:
| Option | Bedeutung |
|---|---|
| `--port 8090` | Port (Standard **8090**) |
| `--host 0.0.0.0` | Bind-Adresse |
| `--db pfad.db` | Speicherort der Datenbank (Standard: neben dem Programm / der exe) |
| `--no-manual-login` | Ersatzanmeldung per Namenseingabe abschalten |

Ist der Port belegt, meldet das Programm das und beendet sich – dann mit `--port` einen anderen wählen.

Beim ersten Start fragt die Windows-Firewall nach – Zugriff im **privaten Netzwerk** erlauben
(oder Port 8090 eingehend freigeben).

## Aufruf an den Arbeitsplätzen
```
http://SERVERNAME:8090
```
Wichtig: immer denselben **Rechnernamen ohne Punkt** verwenden, nicht die IP-Adresse.
- Nur dann behandeln Edge/Chrome die Seite als „Lokales Intranet“ und melden den Windows-Benutzer automatisch an.

Falls stattdessen ein Anmeldefenster erscheint:
- **Domänen-Netz:** Adresse per Gruppenrichtlinie in die Zone „Lokales Intranet“ aufnehmen
  (Site-to-Zone-Zuweisung, Wert `1`) – danach geht es überall ohne Rückfrage.
- **Einzelner PC:** `inetcpl.cpl` → Sicherheit → Lokales Intranet → Sites → Erweitert →
  `http://SERVERNAME` hinzufügen.
- **Firefox:** `about:config` → `network.automatic-ntlm-auth.trusted-uris` = `http://SERVERNAME`
- Fenster abbrechen → es erscheint die Ersatzanmeldung per Namenseingabe (abschaltbar).

## Verschlüsselung der gespeicherten Chats
- In `netzwerk_chat.db` stehen die Nachrichtentexte nur verschlüsselt (HMAC-SHA256-Schlüsselstrom +
  Prüfsumme, nur Python-Standardbibliothek). Wer die Datei kopiert oder öffnet, kann sie nicht lesen.
- Der Schlüssel wird beim Start zufällig erzeugt und nie auf die Platte geschrieben.
- Programm beenden/neu starten = Schlüssel weg = alle Chats werden beim nächsten Start gelöscht.
  Teilnehmerliste und Anmeldungen bleiben erhalten.
- Lesbar sind die Chats nur über das laufende Programm (Webseite) – also für die beiden Gesprächspartner.

## Hinweise
- Die Anmeldung liest nur den Windows-Benutzernamen aus, das Passwort wird **nicht** geprüft
  (es gibt keine Verbindung zum Domänencontroller). Für ein vertrauenswürdiges internes Netz gedacht,
  nicht für das Internet.
- Benutzer werden über den Namen ohne Domäne zugeordnet (Groß-/Kleinschreibung egal).
- Die Datenbank `netzwerk_chat.db` liegt neben dem Programm bzw. der exe.
- Anmeldung bleibt 30 Tage per Cookie gespeichert.

## EXE und Release per GitHub Actions
Der Workflow `.github/workflows/build-exe.yml` baut auf Windows mit PyInstaller `NetzwerkChat.exe`
und erzeugt ein GitHub-Release (exe + ZIP mit README).

Auslösen:
```
git tag v1.2.1
git push origin v1.2.1
```
oder in GitHub unter **Actions → „EXE bauen und Release erzeugen“ → Run workflow** die Version eingeben.
Der Workflow bricht ab, wenn die Version nicht zu `VERSION` in `netzwerk_chat.py` passt.

## EXE offline bauen (ohne GitHub)
Im Ordner `offline_build_kit` liegt ein Offline-Build-Kit: Der Mac lädt PyInstaller als
Windows-Pakete herunter, ein Windows-10-PC mit Python 3.11 installiert sie ohne Internet und baut
`NetzwerkChat-v<Version>-windows.exe`. Ablauf siehe `offline_build_kit/ANLEITUNG.md`.
