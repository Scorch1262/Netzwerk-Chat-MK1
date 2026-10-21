# Netzwerk-Chat v1.1.0

Lokaler Netzwerk-Chat als Website. Das Programm läuft auf **einem** Rechner im Netzwerk –
alle anderen öffnen nur die Seite im Browser. Keine Installation auf den Arbeitsplätzen.

## Funktionen
- **Automatische Anmeldung über den Windows-Benutzer** (integrierte Windows-Anmeldung / NTLM –
  derselbe Benutzername, den `whoami` anzeigt)
- **Präsenz:** Alle Teilnehmer werden links angezeigt – Punkt grün = hat die Seite gerade geöffnet,
  Punkt leer = Seite geschlossen. Keine Aktivitätsanzeige.
- **Ende-zu-Ende-Verschlüsselung:** Nachrichten werden im Browser verschlüsselt (X25519 +
  XSalsa20-Poly1305, TweetNaCl). Der Server speichert nur Chiffretext und kann die Chats nicht lesen.
- **Verlauf:** Jeder Chat mit einer Person wird (verschlüsselt) gespeichert und beim erneuten Anklicken
  automatisch geladen und im Browser entschlüsselt.
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
- Der Schlüssel wird je Adresse im Browser gespeichert – wer mal über die IP und mal über den Namen
  aufruft, hat zwei verschiedene Schlüssel.

Falls stattdessen ein Anmeldefenster erscheint:
- **Domänen-Netz:** Adresse per Gruppenrichtlinie in die Zone „Lokales Intranet“ aufnehmen
  (Site-to-Zone-Zuweisung, Wert `1`) – danach geht es überall ohne Rückfrage.
- **Einzelner PC:** `inetcpl.cpl` → Sicherheit → Lokales Intranet → Sites → Erweitert →
  `http://SERVERNAME` hinzufügen.
- **Firefox:** `about:config` → `network.automatic-ntlm-auth.trusted-uris` = `http://SERVERNAME`
- Fenster abbrechen → es erscheint die Ersatzanmeldung per Namenseingabe (abschaltbar).

## Verschlüsselung – was man wissen sollte
- Jeder Browser erzeugt beim ersten Aufruf einen eigenen Schlüssel. Der **private** Schlüssel bleibt im
  Browser, der Server bekommt nur den öffentlichen.
- Jede Nachricht wird für alle Geräte des Empfängers **und** für die eigenen Geräte verschlüsselt.
- **Neuer PC / anderer Browser / Browserdaten gelöscht:** Neue Nachrichten gehen sofort, der *alte* Verlauf
  ist dort aber nicht lesbar (🔒). Abhilfe: auf dem alten Gerät **SCHLÜSSEL → Code kopieren**, auf dem neuen
  **Code übernehmen**. Den Code nur selbst übertragen – er ist der private Schlüssel.
- Geht der Schlüssel verloren (Browserdaten gelöscht, kein Code gesichert), ist der alte Verlauf
  nicht wiederherstellbar – auch nicht durch den Server. Das ist der Sinn der Verschlüsselung.
- Der Server sieht weiterhin, **wer wann mit wem** schreibt (nicht was).
- Grenzen: Der Server liefert die Webseite aus. Wer den Server-Rechner kontrolliert, könnte das Programm
  verändern und so künftige Nachrichten abgreifen. Über den Fingerabdruck im Schlüssel-Dialog lässt sich
  prüfen, ob ein Gerät der erwartete ist. Nachrichten von nicht beim Server registrierten Schlüsseln werden
  mit „⚠ Absender-Schlüssel nicht bestätigt“ markiert.
- Beim Update von v1.0.0 werden die alten **unverschlüsselten** Nachrichten aus der Datenbank gelöscht.

## Hinweise
- Die Anmeldung liest nur den Windows-Benutzernamen aus, das Passwort wird **nicht** geprüft
  (es gibt keine Verbindung zum Domänencontroller). Für ein vertrauenswürdiges internes Netz gedacht,
  nicht für das Internet.
- Benutzer werden über den Namen ohne Domäne zugeordnet (Groß-/Kleinschreibung egal).
- Die Daten liegen in `netzwerk_chat.db` (SQLite) neben dem Programm.
- Anmeldung bleibt 30 Tage per Cookie gespeichert.

## EXE und Release per GitHub Actions
Der Workflow `.github/workflows/build-exe.yml` baut auf Windows mit PyInstaller `NetzwerkChat.exe`
und erzeugt ein GitHub-Release (exe + ZIP mit README).

Auslösen:
```
git tag v1.1.0
git push origin v1.1.0
```
oder in GitHub unter **Actions → „EXE bauen und Release erzeugen“ → Run workflow** die Version eingeben.
Der Workflow bricht ab, wenn die Version nicht zu `VERSION` in `netzwerk_chat.py` passt.

## Lizenzen
Enthält TweetNaCl-js 1.0.3 (Public Domain / Unlicense).
