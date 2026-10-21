# Netzwerk-Chat v1.0.0

Lokaler Netzwerk-Chat als Website. Das Programm läuft auf **einem** Rechner im Netzwerk –
alle anderen öffnen nur die Seite im Browser. Keine Installation auf den Arbeitsplätzen.

## Funktionen
- **Automatische Anmeldung über den Windows-Benutzer** (integrierte Windows-Anmeldung / NTLM –
  derselbe Benutzername, den `whoami` anzeigt)
- **Präsenz:** Alle Teilnehmer werden links angezeigt – Punkt grün = hat die Seite gerade geöffnet,
  Punkt leer = Seite geschlossen. Keine Aktivitätsanzeige.
- **Verlauf:** Jeder Chat mit einer Person wird gespeichert und beim erneuten Anklicken automatisch geladen.
- Ungelesen-Zähler, Hinweiston (abschaltbar), Anzahl im Browser-Tab-Titel
- Nur Python-Standardbibliothek (Python ≥ 3.8), keine zusätzlichen Pakete

## Start (auf dem Server-Rechner)
```
python netzwerk_chat.py
```
oder Doppelklick auf `start_netzwerk_chat.bat`.

Optionen:
| Option | Bedeutung |
|---|---|
| `--port 8080` | Port (Standard 8080) |
| `--host 0.0.0.0` | Bind-Adresse |
| `--db pfad.db` | Speicherort der Datenbank (Standard: neben dem Programm) |
| `--no-manual-login` | Ersatzanmeldung per Namenseingabe abschalten |

Beim ersten Start fragt die Windows-Firewall nach – Zugriff im **privaten Netzwerk** erlauben
(oder Port 8080 eingehend freigeben).

## Aufruf an den Arbeitsplätzen
```
http://SERVERNAME:8080
```
Wichtig: den **Rechnernamen ohne Punkt** verwenden, nicht die IP-Adresse. Nur dann behandeln
Edge/Chrome die Seite als „Lokales Intranet“ und melden den Windows-Benutzer automatisch an.

Falls stattdessen ein Anmeldefenster erscheint:
- **Domänen-Netz:** Adresse per Gruppenrichtlinie in die Zone „Lokales Intranet“ aufnehmen
  (Site-to-Zone-Zuweisung, Wert `1`) – danach geht es überall ohne Rückfrage.
- **Einzelner PC:** `inetcpl.cpl` → Sicherheit → Lokales Intranet → Sites → Erweitert →
  `http://SERVERNAME` hinzufügen.
- **Firefox:** `about:config` → `network.automatic-ntlm-auth.trusted-uris` = `http://SERVERNAME`
- Fenster abbrechen → es erscheint die Ersatzanmeldung per Namenseingabe (abschaltbar).

## Hinweise
- Die Anmeldung liest nur den Windows-Benutzernamen aus, das Passwort wird **nicht** geprüft
  (es gibt keine Verbindung zum Domänencontroller). Für ein vertrauenswürdiges internes Netz gedacht,
  nicht für das Internet.
- Benutzer werden über den Namen ohne Domäne zugeordnet (Groß-/Kleinschreibung egal).
- Die Daten liegen in `netzwerk_chat.db` (SQLite) neben dem Programm – zum Sichern einfach kopieren.
- Anmeldung bleibt 30 Tage per Cookie gespeichert.
