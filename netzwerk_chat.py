#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netzwerk-Chat  -  v1.3.0

Lokaler Netzwerk-Chat als Website. Läuft auf EINEM Rechner im Netzwerk,
alle anderen öffnen nur die Seite im Browser (keine Installation).

- Anmeldung automatisch über den Windows-Benutzer (integrierte Windows-
  Anmeldung / NTLM - derselbe Name, den "whoami" liefert)
  Firefox: einmalige Freigabe per /firefox-einrichten.reg (wird vom Server
  passend erzeugt und auf der Anmeldeseite angeboten)
- Live-Anzeige, wer die Seite gerade geöffnet hat (online / offline)
- Chatverlauf je Person wird verschlüsselt in SQLite gespeichert und beim
  erneuten Öffnen automatisch wiederhergestellt. Der Schlüssel liegt nur im
  Arbeitsspeicher und wird bei jedem Programmstart neu erzeugt - alte Chats
  werden beim Neustart verworfen.
- Nur Python-Standardbibliothek, keine zusätzlichen Pakete

Start:  python netzwerk_chat.py            (Port 8090)
        python netzwerk_chat.py --port 9000
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import queue
import secrets
import socket
import sqlite3
import struct
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.3.0"

# --------------------------------------------------------------------------
# Einstellungen (per Kommandozeile überschreibbar)
# --------------------------------------------------------------------------
if getattr(sys, "frozen", False):          # als exe (PyInstaller)
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

CFG = {
    "host": "0.0.0.0",
    "port": 8090,     # 8000, 8080, 8081-8083, 8097, 5000-5003 sind im Netz bereits belegt
    "db": os.path.join(APP_DIR, "netzwerk_chat.db"),
    "manual_login": True,      # Ersatz-Anmeldung per Namenseingabe, falls NTLM nicht klappt
    "session_days": 30,
}
COOKIE_NAME = "nchat_sid"
KEEPALIVE_S = 10          # Ping-Intervall der Live-Verbindung
OFFLINE_GRACE_S = 4       # Karenzzeit, damit ein Seiten-Neuladen nicht "offline" blinkt
MAX_MSG_LEN = 4000
MAX_BODY = 64 * 1024


def log(text):
    print(time.strftime("%H:%M:%S"), text, flush=True)


# --------------------------------------------------------------------------
# NTLM (nur Benutzername auslesen - keine Passwortprüfung)
# --------------------------------------------------------------------------
NTLM_SIG = b"NTLMSSP\x00"


def ntlm_type(data):
    if len(data) < 12 or data[:8] != NTLM_SIG:
        return 0
    return struct.unpack_from("<I", data, 8)[0]


def ntlm_build_challenge():
    """Type-2-Nachricht (Challenge) an den Browser."""
    flags = 0xA2898205  # UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|TARGET_TYPE_DOMAIN|
    #                     EXT_SESSIONSECURITY|TARGET_INFO|VERSION|128|56
    domain = "NETZCHAT".encode("utf-16-le")
    computer = (socket.gethostname().split(".")[0].upper()[:15] or "SERVER").encode("utf-16-le")

    def av(av_id, value):
        return struct.pack("<HH", av_id, len(value)) + value

    target_info = av(2, domain) + av(1, computer) + av(4, domain) + av(3, computer) + av(0, b"")
    version = struct.pack("<BBH", 10, 0, 19041) + b"\x00\x00\x00" + bytes([15])
    header_len = 56
    msg = (
        NTLM_SIG
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(domain), len(domain), header_len)
        + struct.pack("<I", flags)
        + os.urandom(8)
        + b"\x00" * 8
        + struct.pack("<HHI", len(target_info), len(target_info), header_len + len(domain))
        + version
        + domain
        + target_info
    )
    return msg


def ntlm_parse_authenticate(data):
    """Type-3-Nachricht auswerten -> {'user', 'domain', 'workstation'}"""
    if len(data) < 52 or ntlm_type(data) != 3:
        return None
    flags = struct.unpack_from("<I", data, 60)[0] if len(data) >= 64 else 1
    enc = "utf-16-le" if flags & 1 else "cp850"

    def field(off):
        length, _maxlen, offset = struct.unpack_from("<HHI", data, off)
        return data[offset:offset + length].decode(enc, "replace").strip()

    try:
        return {"domain": field(28), "user": field(36), "workstation": field(44)}
    except (struct.error, ValueError):
        return None


# --------------------------------------------------------------------------
# Verschlüsselung der gespeicherten Nachrichten
# --------------------------------------------------------------------------
class RamCipher:
    """Verschlüsselt Nachrichtentexte für die Datenbank.

    Der Schlüssel wird bei jedem Programmstart zufällig erzeugt und existiert
    nur im Arbeitsspeicher - in der Datei steht nie ein lesbarer Text.
    Verfahren (nur Standardbibliothek): HMAC-SHA256 als Schlüsselstrom im
    Zählermodus + HMAC-SHA256-Prüfsumme (Encrypt-then-MAC).
    """

    def __init__(self):
        master = secrets.token_bytes(32)
        self.k_enc = hmac.new(master, b"enc", hashlib.sha256).digest()
        self.k_mac = hmac.new(master, b"mac", hashlib.sha256).digest()

    def _stream(self, nonce, length):
        out = bytearray()
        counter = 0
        while len(out) < length:
            out += hmac.new(self.k_enc, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            counter += 1
        return bytes(out[:length])

    def encrypt(self, text):
        data = text.encode("utf-8")
        nonce = secrets.token_bytes(16)
        ct = bytes(a ^ b for a, b in zip(data, self._stream(nonce, len(data))))
        tag = hmac.new(self.k_mac, nonce + ct, hashlib.sha256).digest()[:16]
        return base64.b64encode(nonce + tag + ct).decode("ascii")

    def decrypt(self, blob):
        try:
            raw = base64.b64decode(blob)
        except (ValueError, base64.binascii.Error):
            return None
        nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
        if not hmac.compare_digest(tag, hmac.new(self.k_mac, nonce + ct, hashlib.sha256).digest()[:16]):
            return None
        return bytes(a ^ b for a, b in zip(ct, self._stream(nonce, len(ct)))).decode("utf-8", "replace")


CIPHER = RamCipher()


# --------------------------------------------------------------------------
# Datenbank
# --------------------------------------------------------------------------
class Store:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, domain TEXT,
                    host TEXT, last_seen REAL);
                CREATE TABLE IF NOT EXISTS sessions(
                    token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS messages(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL,
                    recipient TEXT NOT NULL, text TEXT NOT NULL, ts REAL NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS idx_pair ON messages(sender, recipient, id);
                CREATE INDEX IF NOT EXISTS idx_unread ON messages(recipient, read);
                DROP TABLE IF EXISTS keys;
                """
            )
            # Schlüssel des letzten Laufs ist weg -> alte Chats sind nicht mehr lesbar
            removed = self.db.execute("DELETE FROM messages").rowcount
            self.db.commit()
            self.db.execute("VACUUM")
            if removed:
                log("%d Nachricht(en) aus dem letzten Lauf verworfen" % removed)

    def _q(self, sql, args=(), commit=False):
        with self.lock:
            cur = self.db.execute(sql, args)
            rows = cur.fetchall()
            if commit:
                self.db.commit()
            return rows, cur.lastrowid

    def upsert_user(self, uid, name, domain, host):
        self._q(
            """INSERT INTO users(id, name, domain, host, last_seen) VALUES(?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, domain=excluded.domain,
               host=excluded.host, last_seen=excluded.last_seen""",
            (uid, name, domain, host, time.time()), commit=True)

    def user(self, uid):
        rows, _ = self._q("SELECT * FROM users WHERE id=?", (uid,))
        return dict(rows[0]) if rows else None

    def users(self):
        rows, _ = self._q("SELECT * FROM users ORDER BY name COLLATE NOCASE")
        return [dict(r) for r in rows]

    def create_session(self, uid):
        token = secrets.token_urlsafe(32)
        self._q("INSERT INTO sessions(token, user_id, created) VALUES(?,?,?)",
                (token, uid, time.time()), commit=True)
        return token

    def user_for_token(self, token):
        min_created = time.time() - CFG["session_days"] * 86400
        rows, _ = self._q(
            """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token=? AND s.created > ?""", (token, min_created))
        return dict(rows[0]) if rows else None

    def add_message(self, sender, recipient, text):
        ts = time.time()
        _, mid = self._q("INSERT INTO messages(sender, recipient, text, ts) VALUES(?,?,?,?)",
                         (sender, recipient, CIPHER.encrypt(text), ts), commit=True)
        return {"id": mid, "from": sender, "to": recipient, "text": text, "ts": ts}

    def history(self, me, partner, limit=500):
        rows, _ = self._q(
            """SELECT * FROM (
                 SELECT id, sender, recipient, text, ts FROM messages
                 WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
                 ORDER BY id DESC LIMIT ?) ORDER BY id ASC""",
            (me, partner, partner, me, limit))
        out = []
        for r in rows:
            text = CIPHER.decrypt(r["text"])
            if text is not None:
                out.append({"id": r["id"], "from": r["sender"], "to": r["recipient"],
                            "text": text, "ts": r["ts"]})
        return out

    def mark_read(self, me, partner):
        self._q("UPDATE messages SET read=1 WHERE recipient=? AND sender=? AND read=0",
                (me, partner), commit=True)

    def unread_counts(self, me):
        rows, _ = self._q(
            "SELECT sender, COUNT(*) AS n FROM messages WHERE recipient=? AND read=0 GROUP BY sender",
            (me,))
        return {r["sender"]: r["n"] for r in rows}

    def last_contact(self, me):
        rows, _ = self._q(
            """SELECT CASE WHEN sender=? THEN recipient ELSE sender END AS partner, MAX(ts) AS t
               FROM messages WHERE sender=? OR recipient=? GROUP BY partner""", (me, me, me))
        return {r["partner"]: r["t"] for r in rows}


# --------------------------------------------------------------------------
# Präsenz / Live-Verbindungen
# --------------------------------------------------------------------------
class Hub:
    def __init__(self):
        self.lock = threading.Lock()
        self.conns = {}            # cid -> (uid, queue)
        self.by_user = {}          # uid -> set(cid)
        self.pending_offline = set()

    def online_ids(self):
        with self.lock:
            return list(self.by_user.keys())

    def _broadcast(self, event):
        for _uid, q in self.conns.values():
            q.put(event)

    def add(self, cid, uid):
        q = queue.Queue()
        with self.lock:
            old = self.conns.pop(cid, None)
            if old:
                old[1].put(None)
                self.by_user.get(old[0], set()).discard(cid)
            was_online = bool(self.by_user.get(uid))
            self.conns[cid] = (uid, q)
            self.by_user.setdefault(uid, set()).add(cid)
            if uid in self.pending_offline:
                self.pending_offline.discard(uid)   # war nur kurz weg -> nichts melden
            elif not was_online:
                self._broadcast({"type": "presence", "id": uid, "online": True})
        return q

    def remove(self, cid, q=None, uid=None):
        with self.lock:
            entry = self.conns.get(cid)
            if not entry or (q is not None and entry[1] is not q) or (uid and entry[0] != uid):
                return
            self.conns.pop(cid)
            entry[1].put(None)
            owner = entry[0]
            cids = self.by_user.get(owner, set())
            cids.discard(cid)
            if not cids:
                self.by_user.pop(owner, None)
                self.pending_offline.add(owner)
                t = threading.Timer(OFFLINE_GRACE_S, self._check_offline, (owner,))
                t.daemon = True
                t.start()

    def _check_offline(self, uid):
        with self.lock:
            if uid in self.pending_offline and not self.by_user.get(uid):
                self.pending_offline.discard(uid)
                self._broadcast({"type": "presence", "id": uid, "online": False})
                log("offline: " + uid)

    def send_to_user(self, uid, event):
        with self.lock:
            for cid in self.by_user.get(uid, ()):
                self.conns[cid][1].put(event)


STORE = None
HUB = Hub()


def login_user(name, domain, host):
    name = name.strip()
    uid = name.lower()
    known = STORE.user(uid) is not None
    STORE.upsert_user(uid, name, domain or "", host or "")
    log("Anmeldung: %s%s (%s)%s" % (domain + "\\" if domain else "", name, host,
                                     "" if known else "  [neu]"))
    return uid


# --------------------------------------------------------------------------
# HTTP-Server
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # Keep-Alive wird für NTLM benötigt
    server_version = "NetzwerkChat/" + VERSION

    def log_message(self, fmt, *args):     # Zugriffslog unterdrücken
        pass

    # ---- Hilfsfunktionen ----
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", headers=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self.close_connection = True
            return None
        return self.rfile.read(length) if length else b""

    def _session_user(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get(COOKIE_NAME)
        return STORE.user_for_token(morsel.value) if morsel else None

    def _cookie(self, token):
        return ("Set-Cookie", "%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax"
                % (COOKIE_NAME, token, CFG["session_days"] * 86400))

    def _is_firefox(self):
        return "Firefox/" in (self.headers.get("User-Agent") or "")

    def _request_host(self):
        host = (self.headers.get("Host") or "").strip()
        if host.startswith("["):                     # IPv6 [::1]:port
            return host.split("]")[0] + "]"
        return host.rsplit(":", 1)[0] if ":" in host else host

    def firefox_reg(self):
        """Registry-Datei: Firefox darf die Windows-Anmeldung (NTLM) an diesen Server senden.

        Schreibt Firefox-Richtlinien nach HKEY_CURRENT_USER (keine Adminrechte nötig).
        """
        hosts = []
        for h in (self._request_host(), socket.gethostname().split(".")[0], socket.getfqdn()):
            h = (h or "").strip().lower()
            if h and h not in hosts and h not in ("localhost", "localhost.localdomain"):
                hosts.append(h)
        lines = ["Windows Registry Editor Version 5.00", "",
                 "; Netzwerk-Chat v%s - Firefox: automatische Windows-Anmeldung freischalten" % VERSION,
                 "; Erlaubt Firefox, den Windows-Benutzernamen an diese Adresse(n) zu senden.",
                 "; Danach Firefox einmal komplett schliessen und neu starten.", "",
                 r"[HKEY_CURRENT_USER\Software\Policies\Mozilla\Firefox\Authentication\NTLM]"]
        for i, h in enumerate(hosts, 1):
            lines.append('"%d"="%s"' % (i, h.replace("\\", "").replace('"', "")))
        lines += ["", r"[HKEY_CURRENT_USER\Software\Policies\Mozilla\Firefox\Authentication\AllowNonFQDN]",
                  '"NTLM"=dword:00000001', ""]
        body = "\ufeff".encode("utf-16-le") + "\r\n".join(lines).encode("utf-16-le")
        self._send(200, body, "application/octet-stream",
                   [("Content-Disposition", 'attachment; filename="netzwerk-chat-firefox.reg"')])

    def _client_host(self):
        ip = self.client_address[0]
        try:
            return socket.gethostbyaddr(ip)[0].split(".")[0].upper()
        except OSError:
            return ip

    # ---- Routing ----
    def do_GET(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        if url.path == "/":
            return self.page_index()
        if url.path == "/favicon.svg":
            return self._send(200, FAVICON, "image/svg+xml")
        if url.path == "/favicon.ico":
            return self._send(204)
        if url.path == "/firefox-einrichten.reg":
            return self.firefox_reg()
        user = self._session_user()
        if not user:
            return self._json({"error": "nicht angemeldet"}, 401)
        if url.path == "/events":
            return self.stream_events(user, qs)
        if url.path == "/api/users":
            return self.api_users(user)
        if url.path == "/api/history":
            return self.api_history(user, qs)
        return self._send(404, "Nicht gefunden")

    def do_POST(self):
        url = urlparse(self.path)
        body = self._read_body()
        if body is None:
            return self._send(413, "Zu groß")
        if url.path == "/anmelden":
            return self.form_login(body)
        user = self._session_user()
        if not user:
            return self._json({"error": "nicht angemeldet"}, 401)
        if url.path == "/api/bye":
            return self.api_bye(user, body)
        # Schutz gegen fremde Seiten: JSON-POSTs nur mit passendem Content-Type
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._json({"error": "falscher Content-Type"}, 415)
        try:
            data = json.loads(body.decode("utf-8") or "{}")
        except ValueError:
            return self._json({"error": "ungültiges JSON"}, 400)
        if url.path == "/api/send":
            return self.api_send(user, data)
        if url.path == "/api/read":
            return self.api_read(user, data)
        return self._send(404, "Nicht gefunden")

    # ---- Seiten ----
    def page_index(self):
        if self._session_user():
            return self._send(200, APP_HTML, "text/html; charset=utf-8")

        auth = self.headers.get("Authorization", "")
        if auth[:5].upper() == "NTLM ":
            try:
                data = base64.b64decode(auth[5:].strip())
            except (ValueError, base64.binascii.Error):
                data = b""
            mtype = ntlm_type(data)
            if mtype == 1:
                challenge = base64.b64encode(ntlm_build_challenge()).decode()
                return self._send(401, b"", headers=[("WWW-Authenticate", "NTLM " + challenge)])
            if mtype == 3:
                info = ntlm_parse_authenticate(data)
                if info and info["user"]:
                    uid = login_user(info["user"], info["domain"],
                                     info["workstation"] or self._client_host())
                    token = STORE.create_session(uid)
                    return self._send(200, APP_HTML, "text/html; charset=utf-8", [self._cookie(token)])
            # anonym / unlesbar -> Ersatzanmeldung ohne erneute Abfrage
            return self._send(200, login_html(firefox=self._is_firefox()), "text/html; charset=utf-8")

        # Browser zur Windows-Anmeldung auffordern. Kann er das nicht (oder bricht
        # der Benutzer einen Dialog ab), zeigt er den Inhalt dieser Antwort an.
        return self._send(401, login_html(firefox=self._is_firefox()), "text/html; charset=utf-8",
                          [("WWW-Authenticate", "NTLM")])

    def form_login(self, body):
        if not CFG["manual_login"]:
            return self._send(403, "Manuelle Anmeldung ist deaktiviert.")
        name = (parse_qs(body.decode("utf-8", "replace")).get("name") or [""])[0].strip()
        if not (1 <= len(name) <= 40) or any(ord(c) < 32 for c in name) or "\\" in name:
            return self._send(400, login_html("Bitte einen gültigen Namen (1–40 Zeichen) eingeben.", self._is_firefox()),
                              "text/html; charset=utf-8")
        uid = login_user(name, "", self._client_host())
        token = STORE.create_session(uid)
        return self._send(303, b"", headers=[("Location", "/"), self._cookie(token)])

    # ---- Live-Verbindung (Server-Sent Events) ----
    def stream_events(self, user, qs):
        cid = (qs.get("cid") or [""])[0][:64] or secrets.token_hex(8)
        q = HUB.add(cid, user["id"])
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self._sse({"type": "hello", "online": HUB.online_ids()})
            while True:
                try:
                    event = q.get(timeout=KEEPALIVE_S)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if event is None:
                    break
                self._sse(event)
        except OSError:
            pass
        finally:
            HUB.remove(cid, q=q)

    def _sse(self, event):
        self.wfile.write(b"data: " + json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n\n")
        self.wfile.flush()

    # ---- API ----
    def api_users(self, user):
        me = user["id"]
        online = set(HUB.online_ids())
        unread = STORE.unread_counts(me)
        last = STORE.last_contact(me)
        users = [{"id": u["id"], "name": u["name"], "host": u["host"] or "",
                  "online": u["id"] in online, "unread": unread.get(u["id"], 0),
                  "last": last.get(u["id"])}
                 for u in STORE.users() if u["id"] != me]
        self._json({"me": {"id": me, "name": user["name"], "host": user["host"] or ""},
                    "users": users, "version": VERSION})

    def api_history(self, user, qs):
        partner = (qs.get("with") or [""])[0]
        if not STORE.user(partner):
            return self._json({"error": "unbekannter Teilnehmer"}, 404)
        messages = STORE.history(user["id"], partner)
        STORE.mark_read(user["id"], partner)
        HUB.send_to_user(user["id"], {"type": "read", "with": partner})
        self._json({"messages": messages})

    def api_send(self, user, data):
        partner = str(data.get("to") or "")
        text = str(data.get("text") or "").strip()
        if not text:
            return self._json({"error": "leere Nachricht"}, 400)
        if len(text) > MAX_MSG_LEN:
            return self._json({"error": "Nachricht zu lang (max. %d Zeichen)" % MAX_MSG_LEN}, 400)
        if partner == user["id"] or not STORE.user(partner):
            return self._json({"error": "unbekannter Teilnehmer"}, 404)
        msg = STORE.add_message(user["id"], partner, text)
        event = {"type": "message", "msg": msg}
        HUB.send_to_user(partner, event)
        HUB.send_to_user(user["id"], event)   # weitere eigene Tabs
        self._json({"ok": True, "msg": msg})

    def api_read(self, user, data):
        partner = str(data.get("with") or "")
        STORE.mark_read(user["id"], partner)
        HUB.send_to_user(user["id"], {"type": "read", "with": partner})
        self._json({"ok": True})

    def api_bye(self, user, body):
        try:
            cid = str(json.loads(body.decode("utf-8") or "{}").get("cid") or "")
        except ValueError:
            cid = ""
        if cid:
            HUB.remove(cid, uid=user["id"])
        self._send(204)


# --------------------------------------------------------------------------
# Oberfläche  (Stil: Drucker Dashboard - dunkel, Amber/Türkis)
# --------------------------------------------------------------------------
FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" rx="6" fill="#0b0f12"/>
<path d="M7 9h18v11H15l-5 4v-4H7z" fill="none" stroke="#ffae1a" stroke-width="2.4" stroke-linejoin="round"/>
<circle cx="25" cy="8" r="4" fill="#1fd1c1"/></svg>"""

BASE_CSS = r"""
:root{
  --bg:#080b0e; --bg2:#0b1014; --panel:#0e1419; --panel2:#121a20; --line:#1c2730; --line2:#2a3843;
  --text:#d5dfe5; --muted:#6f818c; --dim:#4a5964;
  --amber:#ffae1a; --amber-d:rgba(255,174,26,.12); --amber-g:rgba(255,174,26,.35);
  --teal:#1fd1c1; --teal-d:rgba(31,209,193,.10); --teal-g:rgba(31,209,193,.45);
  --red:#ff5a5a;
  --mono:"Cascadia Mono","JetBrains Mono",Consolas,"SFMono-Regular",monospace;
  --sans:"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--text);font:14px/1.45 var(--sans);
  background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);
  background-size:32px 32px}
.mono{font-family:var(--mono)}
button,input,textarea{font:inherit;color:inherit}
.panel{position:relative;background:var(--panel);border:1px solid var(--line)}
.panel::before,.panel::after{content:"";position:absolute;width:10px;height:10px;pointer-events:none}
.panel::before{top:-1px;left:-1px;border-top:2px solid var(--amber);border-left:2px solid var(--amber)}
.panel::after{bottom:-1px;right:-1px;border-bottom:2px solid var(--amber);border-right:2px solid var(--amber)}
.panel-h{display:flex;align-items:center;gap:10px;min-height:44px;padding:0 14px;border-bottom:1px solid var(--line);
  font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted);background:var(--panel2)}
.btn{background:var(--amber);color:#1a1200;border:0;padding:10px 18px;font:700 12px/1 var(--mono);
  letter-spacing:.14em;cursor:pointer;text-transform:uppercase}
.btn:hover{filter:brightness(1.1)}
.btn:disabled{background:var(--line2);color:var(--dim);cursor:not-allowed}
.field{width:100%;background:var(--bg2);border:1px solid var(--line2);padding:10px 12px;outline:none}
.field:focus{border-color:var(--amber);box-shadow:0 0 0 1px var(--amber-g)}
"""

APP_HTML = (r"""<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netzwerk-Chat</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>""" + BASE_CSS + r"""
body{display:flex;flex-direction:column;overflow:hidden}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;height:58px;padding:0 18px;
  border-bottom:1px solid var(--line);background:rgba(11,16,20,.92)}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:26px;height:26px;border:2px solid var(--amber);position:relative;transform:rotate(45deg)}
.logo::after{content:"";position:absolute;inset:5px;background:var(--teal);box-shadow:0 0 10px var(--teal-g)}
.title{font:700 15px/1 var(--mono);letter-spacing:.22em}
.sub{font:500 10px/1 var(--mono);letter-spacing:.18em;color:var(--muted);margin-top:5px}
.top-right{display:flex;align-items:center;gap:14px}
.tbtn{background:transparent;border:1px solid var(--line2);color:var(--muted);padding:6px 10px;
  font:600 10px/1 var(--mono);letter-spacing:.14em;cursor:pointer}
.tbtn:hover{color:var(--text);border-color:var(--muted)}
.conn{display:flex;align-items:center;gap:8px;font:600 10px/1 var(--mono);letter-spacing:.16em;color:var(--muted)}
.led{width:8px;height:8px;border-radius:50%;background:var(--dim)}
.conn.ok{color:var(--teal)} .conn.ok .led{background:var(--teal);box-shadow:0 0 8px var(--teal-g)}
.conn.bad{color:var(--amber)} .conn.bad .led{background:var(--amber);animation:blink 1s infinite}
@keyframes blink{50%{opacity:.25}}
.me{display:flex;flex-direction:column;align-items:flex-end;padding-left:14px;border-left:1px solid var(--line)}
.me .lbl{font:600 9px/1 var(--mono);letter-spacing:.18em;color:var(--muted)}
.me #meName{font-weight:600;margin-top:3px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.app{flex:1;display:grid;grid-template-columns:300px 1fr;gap:14px;padding:14px;min-height:0}
.side,.chat{display:flex;flex-direction:column;min-height:0}
.count b{color:var(--teal);font-weight:700}
.search{padding:10px;border-bottom:1px solid var(--line)}
.search input{padding:8px 10px;font-size:13px}
.users{list-style:none;margin:0;padding:6px;overflow-y:auto;flex:1}
.user{display:flex;align-items:center;gap:10px;padding:10px;cursor:pointer;border:1px solid transparent;margin-bottom:2px}
.user:hover{background:var(--panel2);border-color:var(--line)}
.user.active{background:var(--amber-d);border-color:var(--amber-g)}
.dot{width:9px;height:9px;border-radius:50%;flex:none;background:transparent;border:1.5px solid var(--dim)}
.dot.on{background:var(--teal);border-color:var(--teal);box-shadow:0 0 8px var(--teal-g)}
.u-main{flex:1;min-width:0}
.u-name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.user.off .u-name{color:#9aa9b2}
.u-sub{font:500 10px/1.3 var(--mono);letter-spacing:.08em;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge{min-width:20px;height:20px;padding:0 6px;border-radius:10px;background:var(--amber);color:#1a1200;
  font:700 11px/20px var(--mono);text-align:center}
.sep-h{font:600 9px/1 var(--mono);letter-spacing:.2em;color:var(--dim);padding:12px 10px 6px}
.empty-side{padding:22px 16px;color:var(--muted);font-size:13px;text-align:center;display:none}

.chat-h{gap:12px}
.chat-h #chatName{color:var(--text);font-size:12px}
.status-tag{margin-left:auto;padding:4px 8px;border:1px solid var(--line2);font-size:9px}
.status-tag.on{color:var(--teal);border-color:var(--teal-g);background:var(--teal-d)}
.back{display:none;background:none;border:1px solid var(--line2);color:var(--text);width:30px;height:30px;cursor:pointer;font-size:18px;line-height:1}
.messages{flex:1;overflow-y:auto;padding:18px 20px;display:flex;flex-direction:column;gap:6px}
.placeholder{margin:auto;text-align:center;color:var(--muted);font-size:13px;max-width:320px}
.placeholder .big{font:700 12px/1 var(--mono);letter-spacing:.2em;color:var(--dim);margin-bottom:10px}
.day{align-self:center;margin:12px 0 6px;font:600 10px/1 var(--mono);letter-spacing:.18em;color:var(--muted);
  padding:5px 10px;border:1px solid var(--line)}
.msg{max-width:min(70%,640px);padding:9px 12px 6px;border:1px solid var(--line2);background:var(--panel2);
  border-left:2px solid var(--teal);align-self:flex-start;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere}
.msg.own{align-self:flex-end;border-left:1px solid var(--line2);border-right:2px solid var(--amber);background:#17150f}
.msg .t{display:block;margin-top:3px;font:500 10px/1 var(--mono);color:var(--muted);text-align:right}
.composer{display:flex;gap:10px;padding:12px;border-top:1px solid var(--line);background:var(--panel2)}
.composer textarea{flex:1;resize:none;max-height:160px;min-height:42px;padding:10px 12px}
.composer textarea:disabled{opacity:.5}
.err{color:var(--red);font:600 11px/1 var(--mono);padding:0 14px 10px;display:none;background:var(--panel2)}

@media (max-width:760px){
  .app{grid-template-columns:1fr;padding:8px}
  .chat{display:none} body.chat-open .chat{display:flex} body.chat-open .side{display:none}
  .back{display:block}
  .me{display:none} .sub{display:none}
  .msg{max-width:85%}
}
</style></head>
<body>
<header class="top">
  <div class="brand"><div class="logo"></div>
    <div><div class="title">NETZWERK-CHAT</div><div class="sub">LOKALES NETZ · V__VERSION__</div></div></div>
  <div class="top-right">
    <button id="soundBtn" class="tbtn" title="Ton bei neuer Nachricht">TON: AN</button>
    <div id="conn" class="conn"><span class="led"></span><span id="connTxt">VERBINDE …</span></div>
    <div class="me"><span class="lbl">ANGEMELDET ALS</span><span id="meName">–</span></div>
  </div>
</header>
<main class="app">
  <aside class="side panel">
    <div class="panel-h"><span>Teilnehmer</span><span class="mono count" id="count" style="margin-left:auto"></span></div>
    <div class="search"><input id="filter" class="field" placeholder="Suchen …" autocomplete="off"></div>
    <ul id="userList" class="users"></ul>
    <div id="noUsers" class="empty-side">Noch keine anderen Teilnehmer.<br>Sobald jemand die Seite öffnet, erscheint er hier.</div>
  </aside>
  <section class="chat panel">
    <div class="panel-h chat-h">
      <button id="back" class="back" title="Zurück">‹</button>
      <span id="chatDot" class="dot" style="display:none"></span>
      <span id="chatName">Kein Chat gewählt</span>
      <span id="chatStatus" class="status-tag" style="display:none"></span>
    </div>
    <div id="messages" class="messages">
      <div class="placeholder"><div class="big">BEREIT</div>Links einen Teilnehmer auswählen – der bisherige Verlauf wird automatisch geladen.</div>
    </div>
    <div id="err" class="err"></div>
    <form id="composer" class="composer">
      <textarea id="input" class="field" rows="1" placeholder="Nachricht … (Enter = senden, Umschalt+Enter = neue Zeile)" disabled></textarea>
      <button id="sendBtn" class="btn" type="submit" disabled>Senden</button>
    </form>
  </section>
</main>
<script>
(() => {
const $ = s => document.querySelector(s);
const CID = 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
const S = { me: null, users: new Map(), active: null, shown: new Set(), lastDay: null, es: null, lost: false, sound: true };
try { S.sound = localStorage.getItem('nchat_sound') !== '0'; } catch (e) {}

async function api(path, body) {
  const opt = body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
                   : { cache: 'no-store' };
  const r = await fetch(path, opt);
  if (r.status === 401) { location.reload(); throw new Error('Nicht angemeldet'); }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('Fehler ' + r.status));
  return d;
}

// ---------- Zeit ----------
const pad = n => String(n).padStart(2, '0');
const fmtTime = ts => { const d = new Date(ts * 1000); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };
function dayKey(ts) { const d = new Date(ts * 1000); return d.getFullYear() + '-' + d.getMonth() + '-' + d.getDate(); }
function fmtDay(ts) {
  const d = new Date(ts * 1000), now = new Date(), y = new Date(); y.setDate(now.getDate() - 1);
  if (dayKey(ts) === dayKey(now / 1000)) return 'HEUTE';
  if (dayKey(ts) === dayKey(y / 1000)) return 'GESTERN';
  return d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' }).toUpperCase();
}
function fmtLast(ts) {
  if (!ts) return '';
  return dayKey(ts) === dayKey(Date.now() / 1000) ? fmtTime(ts) : new Date(ts * 1000).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
}

// ---------- Teilnehmerliste ----------
async function loadUsers() {
  const d = await api('/api/users');
  S.me = d.me;
  $('#meName').textContent = d.me.name;
  S.users = new Map(d.users.map(u => [u.id, u]));
  renderUsers(); renderChatHeader(); updateTitle();
}

function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

function renderUsers() {
  const f = $('#filter').value.trim().toLowerCase();
  const all = [...S.users.values()];
  const list = all.filter(u => !f || u.name.toLowerCase().includes(f) || (u.host || '').toLowerCase().includes(f));
  list.sort((a, b) => (b.online - a.online) || ((b.unread > 0) - (a.unread > 0)) || ((b.last || 0) - (a.last || 0)) || a.name.localeCompare(b.name, 'de'));
  const ul = $('#userList'); ul.innerHTML = '';
  let section = null;
  for (const u of list) {
    const sec = u.online ? 'ONLINE' : 'OFFLINE';
    if (sec !== section) { section = sec; ul.appendChild(el('li', 'sep-h', sec)); }
    const li = el('li', 'user ' + (u.online ? 'on' : 'off') + (u.id === S.active ? ' active' : ''));
    li.appendChild(el('span', 'dot' + (u.online ? ' on' : '')));
    const main = el('div', 'u-main');
    main.appendChild(el('div', 'u-name', u.name));
    const sub = [u.host, u.last ? 'zuletzt ' + fmtLast(u.last) : ''].filter(Boolean).join(' · ');
    main.appendChild(el('div', 'u-sub', sub || (u.online ? 'Seite geöffnet' : 'Seite geschlossen')));
    li.appendChild(main);
    if (u.unread > 0 && u.id !== S.active) li.appendChild(el('span', 'badge', u.unread > 99 ? '99+' : u.unread));
    li.onclick = () => openChat(u.id);
    ul.appendChild(li);
  }
  const on = all.filter(u => u.online).length;
  $('#count').innerHTML = '<b>' + on + '</b> / ' + all.length + ' ONLINE';
  $('#noUsers').style.display = all.length ? 'none' : 'block';
}

function renderChatHeader() {
  const u = S.active && S.users.get(S.active);
  const dot = $('#chatDot'), st = $('#chatStatus');
  if (!u) { $('#chatName').textContent = 'Kein Chat gewählt'; dot.style.display = st.style.display = 'none'; return; }
  $('#chatName').textContent = u.name;
  dot.style.display = st.style.display = '';
  dot.className = 'dot' + (u.online ? ' on' : '');
  st.className = 'status-tag' + (u.online ? ' on' : '');
  st.textContent = u.online ? 'SEITE GEÖFFNET' : 'NICHT GEÖFFNET';
}

function updateTitle() {
  let n = 0; S.users.forEach(u => { if (u.id !== S.active || document.hidden) n += u.unread || 0; });
  document.title = (n ? '(' + n + ') ' : '') + 'Netzwerk-Chat';
}

// ---------- Chat ----------
async function openChat(id, keepScroll) {
  S.active = id;
  document.body.classList.add('chat-open');
  const u = S.users.get(id); if (u) u.unread = 0;
  renderUsers(); renderChatHeader(); updateTitle();
  $('#input').disabled = $('#sendBtn').disabled = false;
  if (!keepScroll) { const box = $('#messages'); box.innerHTML = ''; box.appendChild(el('div', 'placeholder', 'Lade Verlauf …')); }
  try {
    const d = await api('/api/history?with=' + encodeURIComponent(id));
    if (S.active !== id) return;
    const box = $('#messages'); box.innerHTML = ''; S.shown.clear(); S.lastDay = null;
    if (!d.messages.length) {
      const p = el('div', 'placeholder'); p.appendChild(el('div', 'big', 'NEUER CHAT'));
      p.appendChild(document.createTextNode('Noch keine Nachrichten mit ' + (u ? u.name : id) + '.'));
      box.appendChild(p);
    }
    d.messages.forEach(m => appendMessage(m, false));
    box.scrollTop = box.scrollHeight;
  } catch (e) { showErr(e.message); }
  if (window.innerWidth > 760) $('#input').focus();
}

function appendMessage(m, scroll = true) {
  if (S.shown.has(m.id)) return;
  S.shown.add(m.id);
  const box = $('#messages');
  const ph = box.querySelector('.placeholder'); if (ph) ph.remove();
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const dk = dayKey(m.ts);
  if (dk !== S.lastDay) { S.lastDay = dk; box.appendChild(el('div', 'day', fmtDay(m.ts))); }
  const own = m.from === S.me.id;
  const div = el('div', 'msg' + (own ? ' own' : ''), m.text);
  div.appendChild(el('span', 't', fmtTime(m.ts)));
  box.appendChild(div);
  if (scroll && (own || nearBottom)) box.scrollTop = box.scrollHeight;
}

async function send() {
  const inp = $('#input'), text = inp.value.trim();
  if (!text || !S.active) return;
  $('#sendBtn').disabled = true;
  try {
    const d = await api('/api/send', { to: S.active, text });
    inp.value = ''; autosize();
    appendMessage(d.msg);
    const u = S.users.get(S.active); if (u) { u.last = d.msg.ts; renderUsers(); }
    showErr('');
  } catch (e) { showErr(e.message); }
  $('#sendBtn').disabled = false; inp.focus();
}

function showErr(t) { const e = $('#err'); e.textContent = t; e.style.display = t ? 'block' : 'none'; }
function autosize() { const t = $('#input'); t.style.height = 'auto'; t.style.height = Math.min(t.scrollHeight + 2, 160) + 'px'; }

// ---------- Ton ----------
let actx = null;
function beep() {
  if (!S.sound) return;
  try {
    actx = actx || new (window.AudioContext || window.webkitAudioContext)();
    const o = actx.createOscillator(), g = actx.createGain();
    o.type = 'sine'; o.frequency.value = 880; o.frequency.setValueAtTime(1320, actx.currentTime + 0.08);
    g.gain.setValueAtTime(0.0001, actx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.15, actx.currentTime + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + 0.25);
    o.connect(g); g.connect(actx.destination); o.start(); o.stop(actx.currentTime + 0.3);
  } catch (e) {}
}
function renderSound() { $('#soundBtn').textContent = 'TON: ' + (S.sound ? 'AN' : 'AUS'); }

// ---------- Live-Verbindung ----------
function setConn(ok) {
  $('#conn').className = 'conn ' + (ok ? 'ok' : 'bad');
  $('#connTxt').textContent = ok ? 'LIVE' : 'GETRENNT';
}

function connect() {
  const es = new EventSource('/events?cid=' + encodeURIComponent(CID));
  S.es = es;
  es.onopen = async () => {
    setConn(true);
    if (S.lost) { S.lost = false; await loadUsers().catch(() => {}); if (S.active) openChat(S.active, true); }
  };
  es.onerror = () => { setConn(false); S.lost = true; };
  es.onmessage = e => { try { handle(JSON.parse(e.data)); } catch (err) { console.error(err); } };
}

function handle(ev) {
  if (ev.type === 'hello') {
    const on = new Set(ev.online);
    let unknown = false;
    on.forEach(id => { if (id !== S.me.id && !S.users.has(id)) unknown = true; });
    S.users.forEach(u => u.online = on.has(u.id));
    if (unknown) loadUsers(); else { renderUsers(); renderChatHeader(); }
  } else if (ev.type === 'presence') {
    if (S.me && ev.id === S.me.id) return;
    const u = S.users.get(ev.id);
    if (!u) { loadUsers(); return; }
    u.online = ev.online; renderUsers(); renderChatHeader();
  } else if (ev.type === 'message') {
    const m = ev.msg, own = m.from === S.me.id, partner = own ? m.to : m.from;
    const u = S.users.get(partner);
    if (!u) { loadUsers(); }
    else u.last = m.ts;
    if (S.active === partner) {
      appendMessage(m);
      if (!own) { if (document.hidden) { if (u) u.unread++; } else api('/api/read', { with: partner }).catch(() => {}); }
    } else if (!own && u) u.unread++;
    if (!own && (document.hidden || S.active !== partner)) beep();
    renderUsers(); updateTitle();
  } else if (ev.type === 'read') {
    const u = S.users.get(ev.with); if (u) { u.unread = 0; renderUsers(); updateTitle(); }
  }
}

// ---------- Ereignisse ----------
$('#composer').addEventListener('submit', e => { e.preventDefault(); send(); });
$('#input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
$('#input').addEventListener('input', autosize);
$('#filter').addEventListener('input', renderUsers);
$('#back').addEventListener('click', () => { document.body.classList.remove('chat-open'); S.active = null; renderUsers(); renderChatHeader(); });
$('#soundBtn').addEventListener('click', () => { S.sound = !S.sound; try { localStorage.setItem('nchat_sound', S.sound ? '1' : '0'); } catch (e) {} renderSound(); if (S.sound) beep(); });
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && S.active) {
    const u = S.users.get(S.active);
    if (u && u.unread) { u.unread = 0; api('/api/read', { with: S.active }).catch(() => {}); renderUsers(); }
  }
  updateTitle();
});
window.addEventListener('pagehide', () => {
  try { navigator.sendBeacon('/api/bye', JSON.stringify({ cid: CID })); } catch (e) {}
  if (S.es) S.es.close();
});
setInterval(() => { renderUsers(); }, 60000);   // "zuletzt"-Zeiten / Tageswechsel

renderSound();
loadUsers().then(connect).catch(e => showErr(e.message));
})();
</script>
</body></html>
""").replace("__VERSION__", VERSION)


def login_html(error="", firefox=False):
    if CFG["manual_login"]:
        form = """
      <p>Die automatische Anmeldung über den Windows-Benutzer war in diesem Browser nicht möglich.
         Du kannst stattdessen einen Namen eingeben.</p>
      <form method="post" action="/anmelden">
        <input class="field" name="name" maxlength="40" placeholder="Windows-Benutzername" %s required>
        <button class="btn" type="submit">Betreten</button>
      </form>""" % ("" if firefox else "autofocus")
    else:
        form = """
      <p>Die automatische Anmeldung über den Windows-Benutzer war in diesem Browser nicht möglich.</p>"""
    ff = """
      <div class="ff">
        <div class="ff-h">FIREFOX · EINMALIG FREISCHALTEN</div>
        <p>Firefox sendet den Windows-Benutzer erst, wenn diese Adresse freigegeben ist.
           Einmal pro PC/Benutzer – danach meldet Firefox dich automatisch an.</p>
        <ol>
          <li><a class="btn dl" href="/firefox-einrichten.reg">Freigabe herunterladen</a></li>
          <li>Datei <code>netzwerk-chat-firefox.reg</code> doppelklicken → <b>Ja</b> → <b>OK</b>
              <span class="small">(keine Adminrechte nötig)</span></li>
          <li>Firefox komplett schließen und neu starten.</li>
        </ol>
      </div>""" if firefox else ""
    err = '<div class="err">%s</div>' % error if error else ""
    hint = ("""<div class="hint">Erscheint ein Anmeldefenster: <b>Abbrechen</b> – dann kommt diese Seite.
Die Adresse immer über den <b>Rechnernamen</b> aufrufen (z.&nbsp;B. <code>http://SERVERNAME:%d</code>).</div>"""
            if firefox else
            """<div class="hint">Tipp für die automatische Anmeldung: Seite über den <b>Rechnernamen</b> aufrufen
(z.&nbsp;B. <code>http://SERVERNAME:%d</code>, nicht über die IP-Adresse) bzw. die Adresse in Windows
unter <i>Internetoptionen → Sicherheit → Lokales Intranet → Sites</i> eintragen.</div>""") % CFG["port"]
    return ("""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netzwerk-Chat – Anmeldung</title><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>""" + BASE_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:16px;min-height:100%}
.box{width:min(480px,100%)}
.box .in{padding:22px}
p{color:#a9b7bf;margin:0 0 16px}
form{display:flex;gap:10px}
.ff{border:1px solid var(--amber-g);background:var(--amber-d);padding:14px 16px 6px;margin-bottom:20px}
.ff-h{font:700 10px/1 var(--mono);letter-spacing:.18em;color:var(--amber);margin-bottom:10px}
.ff p{margin-bottom:10px}
.ff ol{margin:0 0 8px;padding-left:20px;color:#c5d0d6;font-size:13px}
.ff li{margin-bottom:9px}
.ff code{font-family:var(--mono);color:var(--amber);font-size:12px}
.dl{display:inline-block;text-decoration:none}
.small{color:var(--muted);font-size:12px}
.hint{margin-top:18px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.hint code{font-family:var(--mono);color:var(--amber)}
.err{color:var(--red);font:600 12px/1.3 var(--mono);margin-bottom:12px}
</style></head><body>
<div class="box panel"><div class="panel-h">Netzwerk-Chat · Anmeldung</div><div class="in">""" + err + ff + form + hint + """
</div></div></body></html>""")


# --------------------------------------------------------------------------
# Start
# --------------------------------------------------------------------------
def main():
    global STORE
    ap = argparse.ArgumentParser(description="Netzwerk-Chat v" + VERSION)
    ap.add_argument("--host", default=CFG["host"], help="Bind-Adresse (Standard 0.0.0.0)")
    ap.add_argument("--port", type=int, default=CFG["port"], help="Port (Standard 8090)")
    ap.add_argument("--db", default=CFG["db"], help="Pfad zur SQLite-Datenbank")
    ap.add_argument("--no-manual-login", action="store_true",
                    help="Ersatzanmeldung per Namenseingabe abschalten (nur Windows-Anmeldung)")
    args = ap.parse_args()
    CFG.update(host=args.host, port=args.port, db=args.db, manual_login=not args.no_manual_login)

    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass

    STORE = Store(CFG["db"])
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        server = ThreadingHTTPServer((CFG["host"], CFG["port"]), Handler)
    except OSError as exc:
        print("FEHLER: Port %d ist bereits belegt oder nicht nutzbar (%s)." % (CFG["port"], exc))
        print("Anderen Port wählen, z. B.:  NetzwerkChat.exe --port 8091")
        if getattr(sys, "frozen", False):
            input("Enter zum Beenden ...")
        sys.exit(1)

    name = socket.gethostname().split(".")[0]
    print("=" * 60)
    print(" NETZWERK-CHAT  v%s" % VERSION)
    print("=" * 60)
    print(" Adresse für alle im Netzwerk:  http://%s:%d" % (name, CFG["port"]))
    print(" Datenbank:                     %s" % CFG["db"])
    print(" Chats:                         verschlüsselt, Schlüssel nur im RAM")
    print("                                (werden beim Neustart verworfen)")
    print(" Ersatzanmeldung per Name:      %s" % ("an" if CFG["manual_login"] else "aus"))
    print(" Beenden mit Strg+C")
    print("=" * 60, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
