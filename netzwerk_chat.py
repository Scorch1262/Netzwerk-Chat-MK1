#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netzwerk-Chat  -  v1.1.0

Lokaler Netzwerk-Chat als Website. Läuft auf EINEM Rechner im Netzwerk,
alle anderen öffnen nur die Seite im Browser (keine Installation).

- Anmeldung automatisch über den Windows-Benutzer (integrierte Windows-
  Anmeldung / NTLM - derselbe Name, den "whoami" liefert)
- Live-Anzeige, wer die Seite gerade geöffnet hat (online / offline)
- Ende-zu-Ende-Verschlüsselung: Nachrichten werden im Browser ver- und
  entschlüsselt (X25519 + XSalsa20-Poly1305, TweetNaCl). Der Server speichert
  nur Chiffretext und kann die Chats nicht lesen.
- Chatverlauf je Person wird (verschlüsselt) in SQLite gespeichert und beim
  erneuten Öffnen automatisch wiederhergestellt
- Nur Python-Standardbibliothek, keine zusätzlichen Pakete

Start:  python netzwerk_chat.py            (Port 8090)
        python netzwerk_chat.py --port 9000
"""

import argparse
import base64
import hashlib
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

VERSION = "1.1.0"

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
MAX_ENVELOPE = 96 * 1024  # verschlüsselte Nachricht (Chiffretext + Schlüssel je Gerät)
MAX_BODY = 256 * 1024
MAX_KEYS_PER_USER = 20    # Geräte-Schlüssel je Benutzer, an die verschlüsselt wird


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
                CREATE TABLE IF NOT EXISTS keys(
                    user_id TEXT NOT NULL, key_id TEXT NOT NULL, pub TEXT NOT NULL,
                    created REAL NOT NULL, last_used REAL NOT NULL,
                    PRIMARY KEY(user_id, key_id));
                """
            )
            cols = [r[1] for r in self.db.execute("PRAGMA table_info(messages)")]
            if "enc" not in cols:
                self.db.execute("ALTER TABLE messages ADD COLUMN enc INTEGER NOT NULL DEFAULT 0")
            # Klartext-Nachrichten aus v1.0.0 entfernen - der Server soll nichts Lesbares halten
            removed = self.db.execute("DELETE FROM messages WHERE enc=0").rowcount
            self.db.commit()
            if removed:
                self.db.execute("VACUUM")
                log("%d unverschlüsselte Nachricht(en) aus v1.0.0 gelöscht" % removed)

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

    def add_message(self, sender, recipient, data):
        ts = time.time()
        _, mid = self._q("INSERT INTO messages(sender, recipient, text, ts, enc) VALUES(?,?,?,?,1)",
                         (sender, recipient, data, ts), commit=True)
        return {"id": mid, "from": sender, "to": recipient, "data": data, "ts": ts}

    def add_key(self, uid, key_id, pub):
        now = time.time()
        self._q("""INSERT INTO keys(user_id, key_id, pub, created, last_used) VALUES(?,?,?,?,?)
                   ON CONFLICT(user_id, key_id) DO UPDATE SET last_used=excluded.last_used""",
                (uid, key_id, pub, now, now), commit=True)

    def keys_for(self, uid):
        rows, _ = self._q("""SELECT key_id, pub FROM keys WHERE user_id=?
                             ORDER BY last_used DESC LIMIT ?""", (uid, MAX_KEYS_PER_USER))
        return [{"id": r["key_id"], "pub": r["pub"]} for r in rows]

    def all_keys_for(self, uid):
        rows, _ = self._q("SELECT key_id, pub FROM keys WHERE user_id=?", (uid,))
        return [{"id": r["key_id"], "pub": r["pub"]} for r in rows]

    def history(self, me, partner, limit=500):
        rows, _ = self._q(
            """SELECT * FROM (
                 SELECT id, sender, recipient, text, ts FROM messages
                 WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
                 ORDER BY id DESC LIMIT ?) ORDER BY id ASC""",
            (me, partner, partner, me, limit))
        return [{"id": r["id"], "from": r["sender"], "to": r["recipient"],
                 "data": r["text"], "ts": r["ts"]} for r in rows]

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
        if not any(k == "Cache-Control" for k, _ in headers):
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
        if url.path == "/nacl.js":
            return self._send(200, NACL_JS, "application/javascript; charset=utf-8",
                              [("Cache-Control", "max-age=86400")])
        user = self._session_user()
        if not user:
            return self._json({"error": "nicht angemeldet"}, 401)
        if url.path == "/events":
            return self.stream_events(user, qs)
        if url.path == "/api/users":
            return self.api_users(user)
        if url.path == "/api/history":
            return self.api_history(user, qs)
        if url.path == "/api/keys":
            return self.api_keys(user, qs)
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
        if url.path == "/api/keys":
            return self.api_add_key(user, data)
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
            return self._send(200, login_html(), "text/html; charset=utf-8")

        # Browser zur Windows-Anmeldung auffordern. Kann er das nicht (oder bricht
        # der Benutzer einen Dialog ab), zeigt er den Inhalt dieser Antwort an.
        return self._send(401, login_html(), "text/html; charset=utf-8",
                          [("WWW-Authenticate", "NTLM")])

    def form_login(self, body):
        if not CFG["manual_login"]:
            return self._send(403, "Manuelle Anmeldung ist deaktiviert.")
        name = (parse_qs(body.decode("utf-8", "replace")).get("name") or [""])[0].strip()
        if not (1 <= len(name) <= 40) or any(ord(c) < 32 for c in name) or "\\" in name:
            return self._send(400, login_html("Bitte einen gültigen Namen (1–40 Zeichen) eingeben."),
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
        envelope = data.get("data")
        if not isinstance(envelope, str) or not envelope:
            return self._json({"error": "keine Nachricht"}, 400)
        if len(envelope) > MAX_ENVELOPE:
            return self._json({"error": "Nachricht zu lang"}, 400)
        try:   # Server prüft nur die Form - lesen kann er den Inhalt nicht
            env = json.loads(envelope)
            ok = (env.get("v") == 1 and isinstance(env.get("c"), str) and isinstance(env.get("n"), str)
                  and isinstance(env.get("k"), dict) and env["k"])
        except (ValueError, AttributeError):
            ok = False
        if not ok:
            return self._json({"error": "Nachricht ist nicht verschlüsselt"}, 400)
        if partner == user["id"] or not STORE.user(partner):
            return self._json({"error": "unbekannter Teilnehmer"}, 404)
        msg = STORE.add_message(user["id"], partner, envelope)
        event = {"type": "message", "msg": msg}
        HUB.send_to_user(partner, event)
        HUB.send_to_user(user["id"], event)   # weitere eigene Tabs
        self._json({"ok": True, "msg": msg})

    def api_read(self, user, data):
        partner = str(data.get("with") or "")
        STORE.mark_read(user["id"], partner)
        HUB.send_to_user(user["id"], {"type": "read", "with": partner})
        self._json({"ok": True})

    def api_keys(self, user, qs):
        uids = [u for u in (qs.get("users") or [""])[0].split(",") if u][:10]
        result = {}
        for uid in uids:
            result[uid] = STORE.all_keys_for(uid) if qs.get("all") else STORE.keys_for(uid)
        self._json({"keys": result})

    def api_add_key(self, user, data):
        pub = str(data.get("pub") or "")
        try:
            raw = base64.b64decode(pub, validate=True)
        except (ValueError, base64.binascii.Error):
            raw = b""
        if len(raw) != 32:
            return self._json({"error": "ungültiger Schlüssel"}, 400)
        key_id = hashlib.sha512(raw).hexdigest()[:16]
        STORE.add_key(user["id"], key_id, pub)
        self._json({"ok": True, "id": key_id})

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
.e2e{padding:4px 8px;border:1px solid var(--amber-g);color:var(--amber);font-size:9px;cursor:help;display:none}
.msg.locked{color:var(--muted);font-style:italic;border-left-color:var(--dim)}
.msg .warn{display:block;color:var(--red);font:600 10px/1.3 var(--mono);margin-top:4px}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.65);display:none;align-items:center;justify-content:center;padding:16px;z-index:10}
.modal-bg.show{display:flex}
.modal{width:min(560px,100%);max-height:90vh;overflow:auto}
.modal .in{padding:18px}
.modal h4{margin:16px 0 6px;font:600 10px/1 var(--mono);letter-spacing:.16em;color:var(--muted)}
.modal p{margin:0 0 10px;color:#a9b7bf;font-size:13px}
.modal textarea{height:70px;font:12px/1.4 var(--mono);resize:vertical}
.modal .row{display:flex;gap:10px;margin-top:8px;align-items:center}
.fp{font:600 13px/1.6 var(--mono);color:var(--teal);letter-spacing:.06em}
.ok{color:var(--teal);font:600 11px/1.3 var(--mono)}

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
    <button id="keyBtn" class="tbtn" title="Schlüssel dieses Geräts anzeigen / auf anderen PC übertragen">SCHLÜSSEL</button>
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
      <span id="e2e" class="e2e">🔒 E2E</span>
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
<div id="keyModal" class="modal-bg"><div class="modal panel">
  <div class="panel-h"><span>Schlüssel · Ende-zu-Ende</span><button id="keyClose" class="tbtn" style="margin-left:auto">SCHLIESSEN</button></div>
  <div class="in">
    <p>Nachrichten werden in diesem Browser verschlüsselt. Der Server speichert nur Chiffretext und kann nichts lesen.
       Der private Schlüssel liegt nur in diesem Browser.</p>
    <h4>FINGERABDRUCK DIESES GERÄTS</h4>
    <div id="myFp" class="fp"></div>
    <h4>AUF ANDEREN PC ÜBERTRAGEN</h4>
    <p>Damit ein anderer PC/Browser auch den <b>bisherigen</b> Verlauf lesen kann: Code hier kopieren und dort unter
       „Code übernehmen“ einfügen. <b>Der Code ist dein privater Schlüssel – nur selbst übertragen, nicht per Chat senden.</b></p>
    <textarea id="keyExport" class="field" readonly></textarea>
    <div class="row"><button id="keyCopy" class="tbtn">CODE KOPIEREN</button><span id="copyOk" class="ok"></span></div>
    <h4>CODE ÜBERNEHMEN</h4>
    <textarea id="keyImport" class="field" placeholder="NCK1:…"></textarea>
    <div class="row"><button id="keyImportBtn" class="btn">Übernehmen</button><span id="importMsg" class="ok"></span></div>
  </div>
</div></div>
<script src="/nacl.js"></script>
<script>
(() => {
const $ = s => document.querySelector(s);
const CID = 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
const S = { me: null, users: new Map(), active: null, shown: new Set(), lastDay: null, es: null, lost: false, sound: true };
try { S.sound = localStorage.getItem('nchat_sound') !== '0'; } catch (e) {}
S.ring = [];            // eigene Geräte-Schlüssel (erster = aktiv)
S.keyIds = new Map();   // uid -> Set(key_id) bekannte, beim Server registrierte Schlüssel
S.storageOk = true;

// ---------- Kryptografie (TweetNaCl: X25519 + XSalsa20-Poly1305) ----------
const TE = new TextEncoder(), TD = new TextDecoder();
const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const keyIdOf = pub => hex(nacl.hash(pub).subarray(0, 8));
const fpOf = pub => hex(nacl.hash(pub).subarray(0, 10)).toUpperCase().match(/.{4}/g).join(' ');
const ringKey = () => 'nchat_keys_' + S.me.id;

function kpFromSecret(sk) { const kp = nacl.box.keyPair.fromSecretKey(sk); kp.id = keyIdOf(kp.publicKey); return kp; }
function saveRing() {
  try { localStorage.setItem(ringKey(), S.ring.map(k => b64(k.secretKey)).join(',')); } catch (e) { S.storageOk = false; }
}
async function ensureKeys() {
  try {
    const raw = localStorage.getItem(ringKey());
    if (raw) S.ring = raw.split(',').filter(Boolean).map(x => kpFromSecret(ub64(x)));
  } catch (e) { S.storageOk = false; }
  if (!S.ring.length) { S.ring = [kpFromSecret(nacl.box.keyPair().secretKey)]; saveRing(); }
  for (const k of S.ring) await api('/api/keys', { pub: b64(k.publicKey) });
  if (!S.storageOk) showErr('Browser-Speicher gesperrt – Schlüssel gilt nur bis zum Schließen der Seite.');
}
async function loadKeyIds(uids) {
  const d = await api('/api/keys?all=1&users=' + uids.map(encodeURIComponent).join(','));
  for (const uid of uids) S.keyIds.set(uid, new Set((d.keys[uid] || []).map(k => k.id)));
}
async function encryptFor(partner, text) {
  const d = await api('/api/keys?users=' + encodeURIComponent(partner) + ',' + encodeURIComponent(S.me.id));
  const theirs = d.keys[partner] || [], mine = d.keys[S.me.id] || [];
  if (!theirs.length) throw new Error('Für diesen Teilnehmer ist noch kein Schlüssel vorhanden.');
  const me = S.ring[0], mk = nacl.randomBytes(32), n = nacl.randomBytes(24);
  const k = {};
  for (const t of theirs.concat(mine)) {
    const kn = nacl.randomBytes(24);
    k[t.id] = b64(kn) + '.' + b64(nacl.box(mk, kn, ub64(t.pub), me.secretKey));
  }
  return JSON.stringify({ v: 1, s: me.id, sp: b64(me.publicKey), n: b64(n), c: b64(nacl.secretbox(TE.encode(text), n, mk)), k });
}
// -> {text, verified} oder {text:null}
function decryptMsg(m) {
  let e; try { e = JSON.parse(m.data); } catch (err) { return { text: null }; }
  let sp; try { sp = ub64(e.sp); } catch (err) { return { text: null }; }
  for (const kp of S.ring) {
    const entry = e.k && e.k[kp.id]; if (!entry) continue;
    const [kn, box] = entry.split('.');
    const mk = nacl.box.open(ub64(box), ub64(kn), sp, kp.secretKey); if (!mk) continue;
    const pt = nacl.secretbox.open(ub64(e.c), ub64(e.n), mk); if (!pt) continue;
    const ids = S.keyIds.get(m.from);
    return { text: TD.decode(pt), verified: keyIdOf(sp) === e.s && !!ids && ids.has(e.s) };
  }
  return { text: null };
}

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

function renderE2E() {
  const t = $('#e2e');
  if (!S.active) { t.style.display = 'none'; return; }
  const n = (S.keyIds.get(S.active) || new Set()).size;
  t.style.display = 'inline-block';
  t.title = 'Ende-zu-Ende verschlüsselt – der Server kann diesen Chat nicht lesen.\n' + n + ' Gerät(e) des Gesprächspartners.';
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
    await loadKeyIds([id, S.me.id]);
    renderE2E();
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
  const r = decryptMsg(m);
  const div = r.text === null
    ? el('div', 'msg locked' + (own ? ' own' : ''), '🔒 Auf diesem Gerät nicht lesbar (mit anderem PC/Browser verschlüsselt). Schlüssel über „SCHLÜSSEL“ übertragen.')
    : el('div', 'msg' + (own ? ' own' : ''), r.text);
  if (r.text !== null && !r.verified) div.appendChild(el('span', 'warn', '⚠ Absender-Schlüssel nicht bestätigt'));
  div.appendChild(el('span', 't', fmtTime(m.ts)));
  box.appendChild(div);
  if (scroll && (own || nearBottom)) box.scrollTop = box.scrollHeight;
}

async function send() {
  const inp = $('#input'), text = inp.value.trim();
  if (!text || !S.active) return;
  if (text.length > 4000) { showErr('Nachricht zu lang (max. 4000 Zeichen).'); return; }
  $('#sendBtn').disabled = true;
  try {
    const data = await encryptFor(S.active, text);
    const d = await api('/api/send', { to: S.active, data });
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
    const m = ev.msg;
    let sid = null; try { sid = JSON.parse(m.data).s; } catch (e) {}
    const ids = S.keyIds.get(m.from);
    if (sid && (!ids || !ids.has(sid))) { loadKeyIds([m.from]).catch(() => {}).then(() => handleMessage(m)); return; }
    handleMessage(m);
  } else if (ev.type === 'read') {
    const u = S.users.get(ev.with); if (u) { u.unread = 0; renderUsers(); updateTitle(); }
  }
}

function handleMessage(m) {
  {
    const own = m.from === S.me.id, partner = own ? m.to : m.from;
    const u = S.users.get(partner);
    if (!u) { loadUsers(); }
    else u.last = m.ts;
    if (S.active === partner) {
      appendMessage(m);
      if (!own) { if (document.hidden) { if (u) u.unread++; } else api('/api/read', { with: partner }).catch(() => {}); }
    } else if (!own && u) u.unread++;
    if (!own && (document.hidden || S.active !== partner)) beep();
    renderUsers(); updateTitle();
  }
}

// ---------- Schlüssel-Dialog ----------
function openKeys() {
  $('#myFp').textContent = fpOf(S.ring[0].publicKey);
  $('#keyExport').value = 'NCK1:' + S.ring.map(k => b64(k.secretKey)).join(',');
  $('#copyOk').textContent = $('#importMsg').textContent = ''; $('#keyImport').value = '';
  $('#keyModal').classList.add('show');
}
$('#keyBtn').addEventListener('click', openKeys);
$('#keyClose').addEventListener('click', () => $('#keyModal').classList.remove('show'));
$('#keyModal').addEventListener('click', e => { if (e.target.id === 'keyModal') $('#keyModal').classList.remove('show'); });
$('#keyCopy').addEventListener('click', () => {
  const t = $('#keyExport'); t.focus(); t.select();
  let ok = false; try { ok = document.execCommand('copy'); } catch (e) {}
  $('#copyOk').textContent = ok ? 'KOPIERT' : 'Bitte mit Strg+C kopieren';
});
$('#keyImportBtn').addEventListener('click', async () => {
  const v = $('#keyImport').value.trim(), msg = $('#importMsg');
  try {
    if (!v.startsWith('NCK1:')) throw new Error('Kein gültiger Code');
    let added = 0;
    for (const x of v.slice(5).split(',').filter(Boolean)) {
      const sk = ub64(x); if (sk.length !== 32) throw new Error('Kein gültiger Code');
      const kp = kpFromSecret(sk);
      if (S.ring.some(k => k.id === kp.id)) continue;
      S.ring.push(kp); added++;
      await api('/api/keys', { pub: b64(kp.publicKey) });
    }
    saveRing();
    msg.style.color = ''; msg.textContent = added ? added + ' Schlüssel übernommen – Verlauf wird neu geladen' : 'Schlüssel bereits vorhanden';
    if (added && S.active) openChat(S.active, true);
  } catch (e) { msg.style.color = 'var(--red)'; msg.textContent = e.message; }
});

// ---------- Ereignisse ----------
$('#composer').addEventListener('submit', e => { e.preventDefault(); send(); });
$('#input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
$('#input').addEventListener('input', autosize);
$('#filter').addEventListener('input', renderUsers);
$('#back').addEventListener('click', () => { document.body.classList.remove('chat-open'); S.active = null; renderUsers(); renderChatHeader(); renderE2E(); });
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
loadUsers().then(ensureKeys).then(connect).catch(e => showErr(e.message));
})();
</script>
</body></html>
""").replace("__VERSION__", VERSION)


# TweetNaCl-js 1.0.3 (nacl-fast.min.js) - Public Domain (Unlicense), https://tweetnacl.js.org
NACL_JS = r"""!function(i){"use strict";var v=function(r){var t,n=new Float64Array(16);if(r)for(t=0;t<r.length;t++)n[t]=r[t];return n},h=function(){throw new Error("no PRNG")},o=new Uint8Array(16),n=new Uint8Array(32);n[0]=9;var s=v(),u=v([1]),p=v([56129,1]),c=v([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),y=v([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),e=v([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),a=v([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),l=v([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function f(r,t,n,e){r[t]=n>>24&255,r[t+1]=n>>16&255,r[t+2]=n>>8&255,r[t+3]=255&n,r[t+4]=e>>24&255,r[t+5]=e>>16&255,r[t+6]=e>>8&255,r[t+7]=255&e}function w(r,t,n,e,o){var i,h=0;for(i=0;i<o;i++)h|=r[t+i]^n[e+i];return(1&h-1>>>8)-1}function b(r,t,n,e){return w(r,t,n,e,16)}function g(r,t,n,e){return w(r,t,n,e,32)}function A(r,t,n,e){!function(r,t,n,e){for(var o,i=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,h=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,f=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,s=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,u=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,c=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,w=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,v=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,p=255&n[16]|(255&n[17])<<8|(255&n[18])<<16|(255&n[19])<<24,b=255&n[20]|(255&n[21])<<8|(255&n[22])<<16|(255&n[23])<<24,g=255&n[24]|(255&n[25])<<8|(255&n[26])<<16|(255&n[27])<<24,A=255&n[28]|(255&n[29])<<8|(255&n[30])<<16|(255&n[31])<<24,_=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,U=i,d=h,E=a,x=f,M=s,m=u,B=c,S=y,k=l,K=w,Y=v,L=p,T=b,z=g,R=A,P=_,N=0;N<20;N+=2)U^=(o=(T^=(o=(k^=(o=(M^=(o=U+T|0)<<7|o>>>25)+U|0)<<9|o>>>23)+M|0)<<13|o>>>19)+k|0)<<18|o>>>14,m^=(o=(d^=(o=(z^=(o=(K^=(o=m+d|0)<<7|o>>>25)+m|0)<<9|o>>>23)+K|0)<<13|o>>>19)+z|0)<<18|o>>>14,Y^=(o=(B^=(o=(E^=(o=(R^=(o=Y+B|0)<<7|o>>>25)+Y|0)<<9|o>>>23)+R|0)<<13|o>>>19)+E|0)<<18|o>>>14,P^=(o=(L^=(o=(S^=(o=(x^=(o=P+L|0)<<7|o>>>25)+P|0)<<9|o>>>23)+x|0)<<13|o>>>19)+S|0)<<18|o>>>14,U^=(o=(x^=(o=(E^=(o=(d^=(o=U+x|0)<<7|o>>>25)+U|0)<<9|o>>>23)+d|0)<<13|o>>>19)+E|0)<<18|o>>>14,m^=(o=(M^=(o=(S^=(o=(B^=(o=m+M|0)<<7|o>>>25)+m|0)<<9|o>>>23)+B|0)<<13|o>>>19)+S|0)<<18|o>>>14,Y^=(o=(K^=(o=(k^=(o=(L^=(o=Y+K|0)<<7|o>>>25)+Y|0)<<9|o>>>23)+L|0)<<13|o>>>19)+k|0)<<18|o>>>14,P^=(o=(R^=(o=(z^=(o=(T^=(o=P+R|0)<<7|o>>>25)+P|0)<<9|o>>>23)+T|0)<<13|o>>>19)+z|0)<<18|o>>>14;U=U+i|0,d=d+h|0,E=E+a|0,x=x+f|0,M=M+s|0,m=m+u|0,B=B+c|0,S=S+y|0,k=k+l|0,K=K+w|0,Y=Y+v|0,L=L+p|0,T=T+b|0,z=z+g|0,R=R+A|0,P=P+_|0,r[0]=U>>>0&255,r[1]=U>>>8&255,r[2]=U>>>16&255,r[3]=U>>>24&255,r[4]=d>>>0&255,r[5]=d>>>8&255,r[6]=d>>>16&255,r[7]=d>>>24&255,r[8]=E>>>0&255,r[9]=E>>>8&255,r[10]=E>>>16&255,r[11]=E>>>24&255,r[12]=x>>>0&255,r[13]=x>>>8&255,r[14]=x>>>16&255,r[15]=x>>>24&255,r[16]=M>>>0&255,r[17]=M>>>8&255,r[18]=M>>>16&255,r[19]=M>>>24&255,r[20]=m>>>0&255,r[21]=m>>>8&255,r[22]=m>>>16&255,r[23]=m>>>24&255,r[24]=B>>>0&255,r[25]=B>>>8&255,r[26]=B>>>16&255,r[27]=B>>>24&255,r[28]=S>>>0&255,r[29]=S>>>8&255,r[30]=S>>>16&255,r[31]=S>>>24&255,r[32]=k>>>0&255,r[33]=k>>>8&255,r[34]=k>>>16&255,r[35]=k>>>24&255,r[36]=K>>>0&255,r[37]=K>>>8&255,r[38]=K>>>16&255,r[39]=K>>>24&255,r[40]=Y>>>0&255,r[41]=Y>>>8&255,r[42]=Y>>>16&255,r[43]=Y>>>24&255,r[44]=L>>>0&255,r[45]=L>>>8&255,r[46]=L>>>16&255,r[47]=L>>>24&255,r[48]=T>>>0&255,r[49]=T>>>8&255,r[50]=T>>>16&255,r[51]=T>>>24&255,r[52]=z>>>0&255,r[53]=z>>>8&255,r[54]=z>>>16&255,r[55]=z>>>24&255,r[56]=R>>>0&255,r[57]=R>>>8&255,r[58]=R>>>16&255,r[59]=R>>>24&255,r[60]=P>>>0&255,r[61]=P>>>8&255,r[62]=P>>>16&255,r[63]=P>>>24&255}(r,t,n,e)}function _(r,t,n,e){!function(r,t,n,e){for(var o,i=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,h=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,f=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,s=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,u=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,c=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,w=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,v=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,p=255&n[16]|(255&n[17])<<8|(255&n[18])<<16|(255&n[19])<<24,b=255&n[20]|(255&n[21])<<8|(255&n[22])<<16|(255&n[23])<<24,g=255&n[24]|(255&n[25])<<8|(255&n[26])<<16|(255&n[27])<<24,A=255&n[28]|(255&n[29])<<8|(255&n[30])<<16|(255&n[31])<<24,_=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,U=0;U<20;U+=2)i^=(o=(b^=(o=(l^=(o=(s^=(o=i+b|0)<<7|o>>>25)+i|0)<<9|o>>>23)+s|0)<<13|o>>>19)+l|0)<<18|o>>>14,u^=(o=(h^=(o=(g^=(o=(w^=(o=u+h|0)<<7|o>>>25)+u|0)<<9|o>>>23)+w|0)<<13|o>>>19)+g|0)<<18|o>>>14,v^=(o=(c^=(o=(a^=(o=(A^=(o=v+c|0)<<7|o>>>25)+v|0)<<9|o>>>23)+A|0)<<13|o>>>19)+a|0)<<18|o>>>14,_^=(o=(p^=(o=(y^=(o=(f^=(o=_+p|0)<<7|o>>>25)+_|0)<<9|o>>>23)+f|0)<<13|o>>>19)+y|0)<<18|o>>>14,i^=(o=(f^=(o=(a^=(o=(h^=(o=i+f|0)<<7|o>>>25)+i|0)<<9|o>>>23)+h|0)<<13|o>>>19)+a|0)<<18|o>>>14,u^=(o=(s^=(o=(y^=(o=(c^=(o=u+s|0)<<7|o>>>25)+u|0)<<9|o>>>23)+c|0)<<13|o>>>19)+y|0)<<18|o>>>14,v^=(o=(w^=(o=(l^=(o=(p^=(o=v+w|0)<<7|o>>>25)+v|0)<<9|o>>>23)+p|0)<<13|o>>>19)+l|0)<<18|o>>>14,_^=(o=(A^=(o=(g^=(o=(b^=(o=_+A|0)<<7|o>>>25)+_|0)<<9|o>>>23)+b|0)<<13|o>>>19)+g|0)<<18|o>>>14;r[0]=i>>>0&255,r[1]=i>>>8&255,r[2]=i>>>16&255,r[3]=i>>>24&255,r[4]=u>>>0&255,r[5]=u>>>8&255,r[6]=u>>>16&255,r[7]=u>>>24&255,r[8]=v>>>0&255,r[9]=v>>>8&255,r[10]=v>>>16&255,r[11]=v>>>24&255,r[12]=_>>>0&255,r[13]=_>>>8&255,r[14]=_>>>16&255,r[15]=_>>>24&255,r[16]=c>>>0&255,r[17]=c>>>8&255,r[18]=c>>>16&255,r[19]=c>>>24&255,r[20]=y>>>0&255,r[21]=y>>>8&255,r[22]=y>>>16&255,r[23]=y>>>24&255,r[24]=l>>>0&255,r[25]=l>>>8&255,r[26]=l>>>16&255,r[27]=l>>>24&255,r[28]=w>>>0&255,r[29]=w>>>8&255,r[30]=w>>>16&255,r[31]=w>>>24&255}(r,t,n,e)}var U=new Uint8Array([101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107]);function d(r,t,n,e,o,i,h){var a,f,s=new Uint8Array(16),u=new Uint8Array(64);for(f=0;f<16;f++)s[f]=0;for(f=0;f<8;f++)s[f]=i[f];for(;64<=o;){for(A(u,s,h,U),f=0;f<64;f++)r[t+f]=n[e+f]^u[f];for(a=1,f=8;f<16;f++)a=a+(255&s[f])|0,s[f]=255&a,a>>>=8;o-=64,t+=64,e+=64}if(0<o)for(A(u,s,h,U),f=0;f<o;f++)r[t+f]=n[e+f]^u[f];return 0}function E(r,t,n,e,o){var i,h,a=new Uint8Array(16),f=new Uint8Array(64);for(h=0;h<16;h++)a[h]=0;for(h=0;h<8;h++)a[h]=e[h];for(;64<=n;){for(A(f,a,o,U),h=0;h<64;h++)r[t+h]=f[h];for(i=1,h=8;h<16;h++)i=i+(255&a[h])|0,a[h]=255&i,i>>>=8;n-=64,t+=64}if(0<n)for(A(f,a,o,U),h=0;h<n;h++)r[t+h]=f[h];return 0}function x(r,t,n,e,o){var i=new Uint8Array(32);_(i,e,o,U);for(var h=new Uint8Array(8),a=0;a<8;a++)h[a]=e[a+16];return E(r,t,n,h,i)}function M(r,t,n,e,o,i,h){var a=new Uint8Array(32);_(a,i,h,U);for(var f=new Uint8Array(8),s=0;s<8;s++)f[s]=i[s+16];return d(r,t,n,e,o,f,a)}var m=function(r){var t,n,e,o,i,h,a,f;this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.leftover=0,t=255&r[this.fin=0]|(255&r[1])<<8,this.r[0]=8191&t,n=255&r[2]|(255&r[3])<<8,this.r[1]=8191&(t>>>13|n<<3),e=255&r[4]|(255&r[5])<<8,this.r[2]=7939&(n>>>10|e<<6),o=255&r[6]|(255&r[7])<<8,this.r[3]=8191&(e>>>7|o<<9),i=255&r[8]|(255&r[9])<<8,this.r[4]=255&(o>>>4|i<<12),this.r[5]=i>>>1&8190,h=255&r[10]|(255&r[11])<<8,this.r[6]=8191&(i>>>14|h<<2),a=255&r[12]|(255&r[13])<<8,this.r[7]=8065&(h>>>11|a<<5),f=255&r[14]|(255&r[15])<<8,this.r[8]=8191&(a>>>8|f<<8),this.r[9]=f>>>5&127,this.pad[0]=255&r[16]|(255&r[17])<<8,this.pad[1]=255&r[18]|(255&r[19])<<8,this.pad[2]=255&r[20]|(255&r[21])<<8,this.pad[3]=255&r[22]|(255&r[23])<<8,this.pad[4]=255&r[24]|(255&r[25])<<8,this.pad[5]=255&r[26]|(255&r[27])<<8,this.pad[6]=255&r[28]|(255&r[29])<<8,this.pad[7]=255&r[30]|(255&r[31])<<8};function B(r,t,n,e,o,i){var h=new m(i);return h.update(n,e,o),h.finish(r,t),0}function S(r,t,n,e,o,i){var h=new Uint8Array(16);return B(h,0,n,e,o,i),b(r,t,h,0)}function k(r,t,n,e,o){var i;if(n<32)return-1;for(M(r,0,t,0,n,e,o),B(r,16,r,32,n-32,r),i=0;i<16;i++)r[i]=0;return 0}function K(r,t,n,e,o){var i,h=new Uint8Array(32);if(n<32)return-1;if(x(h,0,32,e,o),0!==S(t,16,t,32,n-32,h))return-1;for(M(r,0,t,0,n,e,o),i=0;i<32;i++)r[i]=0;return 0}function Y(r,t){var n;for(n=0;n<16;n++)r[n]=0|t[n]}function L(r){var t,n,e=1;for(t=0;t<16;t++)n=r[t]+e+65535,e=Math.floor(n/65536),r[t]=n-65536*e;r[0]+=e-1+37*(e-1)}function T(r,t,n){for(var e,o=~(n-1),i=0;i<16;i++)e=o&(r[i]^t[i]),r[i]^=e,t[i]^=e}function z(r,t){var n,e,o,i=v(),h=v();for(n=0;n<16;n++)h[n]=t[n];for(L(h),L(h),L(h),e=0;e<2;e++){for(i[0]=h[0]-65517,n=1;n<15;n++)i[n]=h[n]-65535-(i[n-1]>>16&1),i[n-1]&=65535;i[15]=h[15]-32767-(i[14]>>16&1),o=i[15]>>16&1,i[14]&=65535,T(h,i,1-o)}for(n=0;n<16;n++)r[2*n]=255&h[n],r[2*n+1]=h[n]>>8}function R(r,t){var n=new Uint8Array(32),e=new Uint8Array(32);return z(n,r),z(e,t),g(n,0,e,0)}function P(r){var t=new Uint8Array(32);return z(t,r),1&t[0]}function N(r,t){var n;for(n=0;n<16;n++)r[n]=t[2*n]+(t[2*n+1]<<8);r[15]&=32767}function O(r,t,n){for(var e=0;e<16;e++)r[e]=t[e]+n[e]}function C(r,t,n){for(var e=0;e<16;e++)r[e]=t[e]-n[e]}function F(r,t,n){var e,o,i=0,h=0,a=0,f=0,s=0,u=0,c=0,y=0,l=0,w=0,v=0,p=0,b=0,g=0,A=0,_=0,U=0,d=0,E=0,x=0,M=0,m=0,B=0,S=0,k=0,K=0,Y=0,L=0,T=0,z=0,R=0,P=n[0],N=n[1],O=n[2],C=n[3],F=n[4],I=n[5],Z=n[6],G=n[7],q=n[8],D=n[9],V=n[10],X=n[11],j=n[12],H=n[13],J=n[14],Q=n[15];i+=(e=t[0])*P,h+=e*N,a+=e*O,f+=e*C,s+=e*F,u+=e*I,c+=e*Z,y+=e*G,l+=e*q,w+=e*D,v+=e*V,p+=e*X,b+=e*j,g+=e*H,A+=e*J,_+=e*Q,h+=(e=t[1])*P,a+=e*N,f+=e*O,s+=e*C,u+=e*F,c+=e*I,y+=e*Z,l+=e*G,w+=e*q,v+=e*D,p+=e*V,b+=e*X,g+=e*j,A+=e*H,_+=e*J,U+=e*Q,a+=(e=t[2])*P,f+=e*N,s+=e*O,u+=e*C,c+=e*F,y+=e*I,l+=e*Z,w+=e*G,v+=e*q,p+=e*D,b+=e*V,g+=e*X,A+=e*j,_+=e*H,U+=e*J,d+=e*Q,f+=(e=t[3])*P,s+=e*N,u+=e*O,c+=e*C,y+=e*F,l+=e*I,w+=e*Z,v+=e*G,p+=e*q,b+=e*D,g+=e*V,A+=e*X,_+=e*j,U+=e*H,d+=e*J,E+=e*Q,s+=(e=t[4])*P,u+=e*N,c+=e*O,y+=e*C,l+=e*F,w+=e*I,v+=e*Z,p+=e*G,b+=e*q,g+=e*D,A+=e*V,_+=e*X,U+=e*j,d+=e*H,E+=e*J,x+=e*Q,u+=(e=t[5])*P,c+=e*N,y+=e*O,l+=e*C,w+=e*F,v+=e*I,p+=e*Z,b+=e*G,g+=e*q,A+=e*D,_+=e*V,U+=e*X,d+=e*j,E+=e*H,x+=e*J,M+=e*Q,c+=(e=t[6])*P,y+=e*N,l+=e*O,w+=e*C,v+=e*F,p+=e*I,b+=e*Z,g+=e*G,A+=e*q,_+=e*D,U+=e*V,d+=e*X,E+=e*j,x+=e*H,M+=e*J,m+=e*Q,y+=(e=t[7])*P,l+=e*N,w+=e*O,v+=e*C,p+=e*F,b+=e*I,g+=e*Z,A+=e*G,_+=e*q,U+=e*D,d+=e*V,E+=e*X,x+=e*j,M+=e*H,m+=e*J,B+=e*Q,l+=(e=t[8])*P,w+=e*N,v+=e*O,p+=e*C,b+=e*F,g+=e*I,A+=e*Z,_+=e*G,U+=e*q,d+=e*D,E+=e*V,x+=e*X,M+=e*j,m+=e*H,B+=e*J,S+=e*Q,w+=(e=t[9])*P,v+=e*N,p+=e*O,b+=e*C,g+=e*F,A+=e*I,_+=e*Z,U+=e*G,d+=e*q,E+=e*D,x+=e*V,M+=e*X,m+=e*j,B+=e*H,S+=e*J,k+=e*Q,v+=(e=t[10])*P,p+=e*N,b+=e*O,g+=e*C,A+=e*F,_+=e*I,U+=e*Z,d+=e*G,E+=e*q,x+=e*D,M+=e*V,m+=e*X,B+=e*j,S+=e*H,k+=e*J,K+=e*Q,p+=(e=t[11])*P,b+=e*N,g+=e*O,A+=e*C,_+=e*F,U+=e*I,d+=e*Z,E+=e*G,x+=e*q,M+=e*D,m+=e*V,B+=e*X,S+=e*j,k+=e*H,K+=e*J,Y+=e*Q,b+=(e=t[12])*P,g+=e*N,A+=e*O,_+=e*C,U+=e*F,d+=e*I,E+=e*Z,x+=e*G,M+=e*q,m+=e*D,B+=e*V,S+=e*X,k+=e*j,K+=e*H,Y+=e*J,L+=e*Q,g+=(e=t[13])*P,A+=e*N,_+=e*O,U+=e*C,d+=e*F,E+=e*I,x+=e*Z,M+=e*G,m+=e*q,B+=e*D,S+=e*V,k+=e*X,K+=e*j,Y+=e*H,L+=e*J,T+=e*Q,A+=(e=t[14])*P,_+=e*N,U+=e*O,d+=e*C,E+=e*F,x+=e*I,M+=e*Z,m+=e*G,B+=e*q,S+=e*D,k+=e*V,K+=e*X,Y+=e*j,L+=e*H,T+=e*J,z+=e*Q,_+=(e=t[15])*P,h+=38*(d+=e*O),a+=38*(E+=e*C),f+=38*(x+=e*F),s+=38*(M+=e*I),u+=38*(m+=e*Z),c+=38*(B+=e*G),y+=38*(S+=e*q),l+=38*(k+=e*D),w+=38*(K+=e*V),v+=38*(Y+=e*X),p+=38*(L+=e*j),b+=38*(T+=e*H),g+=38*(z+=e*J),A+=38*(R+=e*Q),i=(e=(i+=38*(U+=e*N))+(o=1)+65535)-65536*(o=Math.floor(e/65536)),h=(e=h+o+65535)-65536*(o=Math.floor(e/65536)),a=(e=a+o+65535)-65536*(o=Math.floor(e/65536)),f=(e=f+o+65535)-65536*(o=Math.floor(e/65536)),s=(e=s+o+65535)-65536*(o=Math.floor(e/65536)),u=(e=u+o+65535)-65536*(o=Math.floor(e/65536)),c=(e=c+o+65535)-65536*(o=Math.floor(e/65536)),y=(e=y+o+65535)-65536*(o=Math.floor(e/65536)),l=(e=l+o+65535)-65536*(o=Math.floor(e/65536)),w=(e=w+o+65535)-65536*(o=Math.floor(e/65536)),v=(e=v+o+65535)-65536*(o=Math.floor(e/65536)),p=(e=p+o+65535)-65536*(o=Math.floor(e/65536)),b=(e=b+o+65535)-65536*(o=Math.floor(e/65536)),g=(e=g+o+65535)-65536*(o=Math.floor(e/65536)),A=(e=A+o+65535)-65536*(o=Math.floor(e/65536)),_=(e=_+o+65535)-65536*(o=Math.floor(e/65536)),i=(e=(i+=o-1+37*(o-1))+(o=1)+65535)-65536*(o=Math.floor(e/65536)),h=(e=h+o+65535)-65536*(o=Math.floor(e/65536)),a=(e=a+o+65535)-65536*(o=Math.floor(e/65536)),f=(e=f+o+65535)-65536*(o=Math.floor(e/65536)),s=(e=s+o+65535)-65536*(o=Math.floor(e/65536)),u=(e=u+o+65535)-65536*(o=Math.floor(e/65536)),c=(e=c+o+65535)-65536*(o=Math.floor(e/65536)),y=(e=y+o+65535)-65536*(o=Math.floor(e/65536)),l=(e=l+o+65535)-65536*(o=Math.floor(e/65536)),w=(e=w+o+65535)-65536*(o=Math.floor(e/65536)),v=(e=v+o+65535)-65536*(o=Math.floor(e/65536)),p=(e=p+o+65535)-65536*(o=Math.floor(e/65536)),b=(e=b+o+65535)-65536*(o=Math.floor(e/65536)),g=(e=g+o+65535)-65536*(o=Math.floor(e/65536)),A=(e=A+o+65535)-65536*(o=Math.floor(e/65536)),_=(e=_+o+65535)-65536*(o=Math.floor(e/65536)),i+=o-1+37*(o-1),r[0]=i,r[1]=h,r[2]=a,r[3]=f,r[4]=s,r[5]=u,r[6]=c,r[7]=y,r[8]=l,r[9]=w,r[10]=v,r[11]=p,r[12]=b,r[13]=g,r[14]=A,r[15]=_}function I(r,t){F(r,t,t)}function Z(r,t){var n,e=v();for(n=0;n<16;n++)e[n]=t[n];for(n=253;0<=n;n--)I(e,e),2!==n&&4!==n&&F(e,e,t);for(n=0;n<16;n++)r[n]=e[n]}function G(r,t){var n,e=v();for(n=0;n<16;n++)e[n]=t[n];for(n=250;0<=n;n--)I(e,e),1!==n&&F(e,e,t);for(n=0;n<16;n++)r[n]=e[n]}function q(r,t,n){var e,o,i=new Uint8Array(32),h=new Float64Array(80),a=v(),f=v(),s=v(),u=v(),c=v(),y=v();for(o=0;o<31;o++)i[o]=t[o];for(i[31]=127&t[31]|64,i[0]&=248,N(h,n),o=0;o<16;o++)f[o]=h[o],u[o]=a[o]=s[o]=0;for(a[0]=u[0]=1,o=254;0<=o;--o)T(a,f,e=i[o>>>3]>>>(7&o)&1),T(s,u,e),O(c,a,s),C(a,a,s),O(s,f,u),C(f,f,u),I(u,c),I(y,a),F(a,s,a),F(s,f,c),O(c,a,s),C(a,a,s),I(f,a),C(s,u,y),F(a,s,p),O(a,a,u),F(s,s,a),F(a,u,y),F(u,f,h),I(f,c),T(a,f,e),T(s,u,e);for(o=0;o<16;o++)h[o+16]=a[o],h[o+32]=s[o],h[o+48]=f[o],h[o+64]=u[o];var l=h.subarray(32),w=h.subarray(16);return Z(l,l),F(w,w,l),z(r,w),0}function D(r,t){return q(r,t,n)}function V(r,t){return h(t,32),D(r,t)}function X(r,t,n){var e=new Uint8Array(32);return q(e,n,t),_(r,o,e,U)}m.prototype.blocks=function(r,t,n){for(var e,o,i,h,a,f,s,u,c,y,l,w,v,p,b,g,A,_,U,d=this.fin?0:2048,E=this.h[0],x=this.h[1],M=this.h[2],m=this.h[3],B=this.h[4],S=this.h[5],k=this.h[6],K=this.h[7],Y=this.h[8],L=this.h[9],T=this.r[0],z=this.r[1],R=this.r[2],P=this.r[3],N=this.r[4],O=this.r[5],C=this.r[6],F=this.r[7],I=this.r[8],Z=this.r[9];16<=n;)y=c=0,y+=(E+=8191&(e=255&r[t+0]|(255&r[t+1])<<8))*T,y+=(x+=8191&(e>>>13|(o=255&r[t+2]|(255&r[t+3])<<8)<<3))*(5*Z),y+=(M+=8191&(o>>>10|(i=255&r[t+4]|(255&r[t+5])<<8)<<6))*(5*I),y+=(m+=8191&(i>>>7|(h=255&r[t+6]|(255&r[t+7])<<8)<<9))*(5*F),c=(y+=(B+=8191&(h>>>4|(a=255&r[t+8]|(255&r[t+9])<<8)<<12))*(5*C))>>>13,y&=8191,y+=(S+=a>>>1&8191)*(5*O),y+=(k+=8191&(a>>>14|(f=255&r[t+10]|(255&r[t+11])<<8)<<2))*(5*N),y+=(K+=8191&(f>>>11|(s=255&r[t+12]|(255&r[t+13])<<8)<<5))*(5*P),y+=(Y+=8191&(s>>>8|(u=255&r[t+14]|(255&r[t+15])<<8)<<8))*(5*R),l=c+=(y+=(L+=u>>>5|d)*(5*z))>>>13,l+=E*z,l+=x*T,l+=M*(5*Z),l+=m*(5*I),c=(l+=B*(5*F))>>>13,l&=8191,l+=S*(5*C),l+=k*(5*O),l+=K*(5*N),l+=Y*(5*P),c+=(l+=L*(5*R))>>>13,l&=8191,w=c,w+=E*R,w+=x*z,w+=M*T,w+=m*(5*Z),c=(w+=B*(5*I))>>>13,w&=8191,w+=S*(5*F),w+=k*(5*C),w+=K*(5*O),w+=Y*(5*N),v=c+=(w+=L*(5*P))>>>13,v+=E*P,v+=x*R,v+=M*z,v+=m*T,c=(v+=B*(5*Z))>>>13,v&=8191,v+=S*(5*I),v+=k*(5*F),v+=K*(5*C),v+=Y*(5*O),p=c+=(v+=L*(5*N))>>>13,p+=E*N,p+=x*P,p+=M*R,p+=m*z,c=(p+=B*T)>>>13,p&=8191,p+=S*(5*Z),p+=k*(5*I),p+=K*(5*F),p+=Y*(5*C),b=c+=(p+=L*(5*O))>>>13,b+=E*O,b+=x*N,b+=M*P,b+=m*R,c=(b+=B*z)>>>13,b&=8191,b+=S*T,b+=k*(5*Z),b+=K*(5*I),b+=Y*(5*F),g=c+=(b+=L*(5*C))>>>13,g+=E*C,g+=x*O,g+=M*N,g+=m*P,c=(g+=B*R)>>>13,g&=8191,g+=S*z,g+=k*T,g+=K*(5*Z),g+=Y*(5*I),A=c+=(g+=L*(5*F))>>>13,A+=E*F,A+=x*C,A+=M*O,A+=m*N,c=(A+=B*P)>>>13,A&=8191,A+=S*R,A+=k*z,A+=K*T,A+=Y*(5*Z),_=c+=(A+=L*(5*I))>>>13,_+=E*I,_+=x*F,_+=M*C,_+=m*O,c=(_+=B*N)>>>13,_&=8191,_+=S*P,_+=k*R,_+=K*z,_+=Y*T,U=c+=(_+=L*(5*Z))>>>13,U+=E*Z,U+=x*I,U+=M*F,U+=m*C,c=(U+=B*O)>>>13,U&=8191,U+=S*N,U+=k*P,U+=K*R,U+=Y*z,E=y=8191&(c=(c=((c+=(U+=L*T)>>>13)<<2)+c|0)+(y&=8191)|0),x=l+=c>>>=13,M=w&=8191,m=v&=8191,B=p&=8191,S=b&=8191,k=g&=8191,K=A&=8191,Y=_&=8191,L=U&=8191,t+=16,n-=16;this.h[0]=E,this.h[1]=x,this.h[2]=M,this.h[3]=m,this.h[4]=B,this.h[5]=S,this.h[6]=k,this.h[7]=K,this.h[8]=Y,this.h[9]=L},m.prototype.finish=function(r,t){var n,e,o,i,h=new Uint16Array(10);if(this.leftover){for(i=this.leftover,this.buffer[i++]=1;i<16;i++)this.buffer[i]=0;this.fin=1,this.blocks(this.buffer,0,16)}for(n=this.h[1]>>>13,this.h[1]&=8191,i=2;i<10;i++)this.h[i]+=n,n=this.h[i]>>>13,this.h[i]&=8191;for(this.h[0]+=5*n,n=this.h[0]>>>13,this.h[0]&=8191,this.h[1]+=n,n=this.h[1]>>>13,this.h[1]&=8191,this.h[2]+=n,h[0]=this.h[0]+5,n=h[0]>>>13,h[0]&=8191,i=1;i<10;i++)h[i]=this.h[i]+n,n=h[i]>>>13,h[i]&=8191;for(h[9]-=8192,e=(1^n)-1,i=0;i<10;i++)h[i]&=e;for(e=~e,i=0;i<10;i++)this.h[i]=this.h[i]&e|h[i];for(this.h[0]=65535&(this.h[0]|this.h[1]<<13),this.h[1]=65535&(this.h[1]>>>3|this.h[2]<<10),this.h[2]=65535&(this.h[2]>>>6|this.h[3]<<7),this.h[3]=65535&(this.h[3]>>>9|this.h[4]<<4),this.h[4]=65535&(this.h[4]>>>12|this.h[5]<<1|this.h[6]<<14),this.h[5]=65535&(this.h[6]>>>2|this.h[7]<<11),this.h[6]=65535&(this.h[7]>>>5|this.h[8]<<8),this.h[7]=65535&(this.h[8]>>>8|this.h[9]<<5),o=this.h[0]+this.pad[0],this.h[0]=65535&o,i=1;i<8;i++)o=(this.h[i]+this.pad[i]|0)+(o>>>16)|0,this.h[i]=65535&o;r[t+0]=this.h[0]>>>0&255,r[t+1]=this.h[0]>>>8&255,r[t+2]=this.h[1]>>>0&255,r[t+3]=this.h[1]>>>8&255,r[t+4]=this.h[2]>>>0&255,r[t+5]=this.h[2]>>>8&255,r[t+6]=this.h[3]>>>0&255,r[t+7]=this.h[3]>>>8&255,r[t+8]=this.h[4]>>>0&255,r[t+9]=this.h[4]>>>8&255,r[t+10]=this.h[5]>>>0&255,r[t+11]=this.h[5]>>>8&255,r[t+12]=this.h[6]>>>0&255,r[t+13]=this.h[6]>>>8&255,r[t+14]=this.h[7]>>>0&255,r[t+15]=this.h[7]>>>8&255},m.prototype.update=function(r,t,n){var e,o;if(this.leftover){for(n<(o=16-this.leftover)&&(o=n),e=0;e<o;e++)this.buffer[this.leftover+e]=r[t+e];if(n-=o,t+=o,this.leftover+=o,this.leftover<16)return;this.blocks(this.buffer,0,16),this.leftover=0}if(16<=n&&(o=n-n%16,this.blocks(r,t,o),t+=o,n-=o),n){for(e=0;e<n;e++)this.buffer[this.leftover+e]=r[t+e];this.leftover+=n}};var j=k,H=K;var J=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591];function Q(r,t,n,e){for(var o,i,h,a,f,s,u,c,y,l,w,v,p,b,g,A,_,U,d,E,x,M,m,B,S=new Int32Array(16),k=new Int32Array(16),K=r[0],Y=r[1],L=r[2],T=r[3],z=r[4],R=r[5],P=r[6],N=r[7],O=t[0],C=t[1],F=t[2],I=t[3],Z=t[4],G=t[5],q=t[6],D=t[7],V=0;128<=e;){for(_=0;_<16;_++)U=8*_+V,S[_]=n[U+0]<<24|n[U+1]<<16|n[U+2]<<8|n[U+3],k[_]=n[U+4]<<24|n[U+5]<<16|n[U+6]<<8|n[U+7];for(_=0;_<80;_++)if(o=Y,i=L,h=T,c=C,y=F,l=I,x=65535&(E=D),M=E>>>16,m=65535&(d=N),B=d>>>16,x+=65535&(E=((w=Z)>>>14|(a=z)<<18)^(Z>>>18|z<<14)^(z>>>9|Z<<23)),M+=E>>>16,m+=65535&(d=(z>>>14|Z<<18)^(z>>>18|Z<<14)^(Z>>>9|z<<23)),B+=d>>>16,x+=65535&(E=Z&(v=G)^~Z&(p=q)),M+=E>>>16,m+=65535&(d=z&(f=R)^~z&(s=P)),B+=d>>>16,d=J[2*_],x+=65535&(E=J[2*_+1]),M+=E>>>16,m+=65535&d,B+=d>>>16,d=S[_%16],M+=(E=k[_%16])>>>16,m+=65535&d,B+=d>>>16,m+=(M+=(x+=65535&E)>>>16)>>>16,x=65535&(E=A=65535&x|M<<16),M=E>>>16,m=65535&(d=g=65535&m|(B+=m>>>16)<<16),B=d>>>16,x+=65535&(E=(O>>>28|K<<4)^(K>>>2|O<<30)^(K>>>7|O<<25)),M+=E>>>16,m+=65535&(d=(K>>>28|O<<4)^(O>>>2|K<<30)^(O>>>7|K<<25)),B+=d>>>16,M+=(E=O&C^O&F^C&F)>>>16,m+=65535&(d=K&Y^K&L^Y&L),B+=d>>>16,u=65535&(m+=(M+=(x+=65535&E)>>>16)>>>16)|(B+=m>>>16)<<16,b=65535&x|M<<16,x=65535&(E=l),M=E>>>16,m=65535&(d=h),B=d>>>16,M+=(E=A)>>>16,m+=65535&(d=g),B+=d>>>16,Y=K,L=o,T=i,z=h=65535&(m+=(M+=(x+=65535&E)>>>16)>>>16)|(B+=m>>>16)<<16,R=a,P=f,N=s,K=u,C=O,F=c,I=y,Z=l=65535&x|M<<16,G=w,q=v,D=p,O=b,_%16==15)for(U=0;U<16;U++)d=S[U],x=65535&(E=k[U]),M=E>>>16,m=65535&d,B=d>>>16,d=S[(U+9)%16],x+=65535&(E=k[(U+9)%16]),M+=E>>>16,m+=65535&d,B+=d>>>16,g=S[(U+1)%16],x+=65535&(E=((A=k[(U+1)%16])>>>1|g<<31)^(A>>>8|g<<24)^(A>>>7|g<<25)),M+=E>>>16,m+=65535&(d=(g>>>1|A<<31)^(g>>>8|A<<24)^g>>>7),B+=d>>>16,g=S[(U+14)%16],M+=(E=((A=k[(U+14)%16])>>>19|g<<13)^(g>>>29|A<<3)^(A>>>6|g<<26))>>>16,m+=65535&(d=(g>>>19|A<<13)^(A>>>29|g<<3)^g>>>6),B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,S[U]=65535&m|B<<16,k[U]=65535&x|M<<16;x=65535&(E=O),M=E>>>16,m=65535&(d=K),B=d>>>16,d=r[0],M+=(E=t[0])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[0]=K=65535&m|B<<16,t[0]=O=65535&x|M<<16,x=65535&(E=C),M=E>>>16,m=65535&(d=Y),B=d>>>16,d=r[1],M+=(E=t[1])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[1]=Y=65535&m|B<<16,t[1]=C=65535&x|M<<16,x=65535&(E=F),M=E>>>16,m=65535&(d=L),B=d>>>16,d=r[2],M+=(E=t[2])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[2]=L=65535&m|B<<16,t[2]=F=65535&x|M<<16,x=65535&(E=I),M=E>>>16,m=65535&(d=T),B=d>>>16,d=r[3],M+=(E=t[3])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[3]=T=65535&m|B<<16,t[3]=I=65535&x|M<<16,x=65535&(E=Z),M=E>>>16,m=65535&(d=z),B=d>>>16,d=r[4],M+=(E=t[4])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[4]=z=65535&m|B<<16,t[4]=Z=65535&x|M<<16,x=65535&(E=G),M=E>>>16,m=65535&(d=R),B=d>>>16,d=r[5],M+=(E=t[5])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[5]=R=65535&m|B<<16,t[5]=G=65535&x|M<<16,x=65535&(E=q),M=E>>>16,m=65535&(d=P),B=d>>>16,d=r[6],M+=(E=t[6])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[6]=P=65535&m|B<<16,t[6]=q=65535&x|M<<16,x=65535&(E=D),M=E>>>16,m=65535&(d=N),B=d>>>16,d=r[7],M+=(E=t[7])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[7]=N=65535&m|B<<16,t[7]=D=65535&x|M<<16,V+=128,e-=128}return e}function W(r,t,n){var e,o=new Int32Array(8),i=new Int32Array(8),h=new Uint8Array(256),a=n;for(o[0]=1779033703,o[1]=3144134277,o[2]=1013904242,o[3]=2773480762,o[4]=1359893119,o[5]=2600822924,o[6]=528734635,o[7]=1541459225,i[0]=4089235720,i[1]=2227873595,i[2]=4271175723,i[3]=1595750129,i[4]=2917565137,i[5]=725511199,i[6]=4215389547,i[7]=327033209,Q(o,i,t,n),n%=128,e=0;e<n;e++)h[e]=t[a-n+e];for(h[n]=128,h[(n=256-128*(n<112?1:0))-9]=0,f(h,n-8,a/536870912|0,a<<3),Q(o,i,h,n),e=0;e<8;e++)f(r,8*e,o[e],i[e]);return 0}function $(r,t){var n=v(),e=v(),o=v(),i=v(),h=v(),a=v(),f=v(),s=v(),u=v();C(n,r[1],r[0]),C(u,t[1],t[0]),F(n,n,u),O(e,r[0],r[1]),O(u,t[0],t[1]),F(e,e,u),F(o,r[3],t[3]),F(o,o,y),F(i,r[2],t[2]),O(i,i,i),C(h,e,n),C(a,i,o),O(f,i,o),O(s,e,n),F(r[0],h,a),F(r[1],s,f),F(r[2],f,a),F(r[3],h,s)}function rr(r,t,n){var e;for(e=0;e<4;e++)T(r[e],t[e],n)}function tr(r,t){var n=v(),e=v(),o=v();Z(o,t[2]),F(n,t[0],o),F(e,t[1],o),z(r,e),r[31]^=P(n)<<7}function nr(r,t,n){var e,o;for(Y(r[0],s),Y(r[1],u),Y(r[2],u),Y(r[3],s),o=255;0<=o;--o)rr(r,t,e=n[o/8|0]>>(7&o)&1),$(t,r),$(r,r),rr(r,t,e)}function er(r,t){var n=[v(),v(),v(),v()];Y(n[0],e),Y(n[1],a),Y(n[2],u),F(n[3],e,a),nr(r,n,t)}function or(r,t,n){var e,o=new Uint8Array(64),i=[v(),v(),v(),v()];for(n||h(t,32),W(o,t,32),o[0]&=248,o[31]&=127,o[31]|=64,er(i,o),tr(r,i),e=0;e<32;e++)t[e+32]=r[e];return 0}var ir=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function hr(r,t){var n,e,o,i;for(e=63;32<=e;--e){for(n=0,o=e-32,i=e-12;o<i;++o)t[o]+=n-16*t[e]*ir[o-(e-32)],n=Math.floor((t[o]+128)/256),t[o]-=256*n;t[o]+=n,t[e]=0}for(o=n=0;o<32;o++)t[o]+=n-(t[31]>>4)*ir[o],n=t[o]>>8,t[o]&=255;for(o=0;o<32;o++)t[o]-=n*ir[o];for(e=0;e<32;e++)t[e+1]+=t[e]>>8,r[e]=255&t[e]}function ar(r){var t,n=new Float64Array(64);for(t=0;t<64;t++)n[t]=r[t];for(t=0;t<64;t++)r[t]=0;hr(r,n)}function fr(r,t,n,e){var o,i,h=new Uint8Array(64),a=new Uint8Array(64),f=new Uint8Array(64),s=new Float64Array(64),u=[v(),v(),v(),v()];W(h,e,32),h[0]&=248,h[31]&=127,h[31]|=64;var c=n+64;for(o=0;o<n;o++)r[64+o]=t[o];for(o=0;o<32;o++)r[32+o]=h[32+o];for(W(f,r.subarray(32),n+32),ar(f),er(u,f),tr(r,u),o=32;o<64;o++)r[o]=e[o];for(W(a,r,n+64),ar(a),o=0;o<64;o++)s[o]=0;for(o=0;o<32;o++)s[o]=f[o];for(o=0;o<32;o++)for(i=0;i<32;i++)s[o+i]+=a[o]*h[i];return hr(r.subarray(32),s),c}function sr(r,t,n,e){var o,i=new Uint8Array(32),h=new Uint8Array(64),a=[v(),v(),v(),v()],f=[v(),v(),v(),v()];if(n<64)return-1;if(function(r,t){var n=v(),e=v(),o=v(),i=v(),h=v(),a=v(),f=v();if(Y(r[2],u),N(r[1],t),I(o,r[1]),F(i,o,c),C(o,o,r[2]),O(i,r[2],i),I(h,i),I(a,h),F(f,a,h),F(n,f,o),F(n,n,i),G(n,n),F(n,n,o),F(n,n,i),F(n,n,i),F(r[0],n,i),I(e,r[0]),F(e,e,i),R(e,o)&&F(r[0],r[0],l),I(e,r[0]),F(e,e,i),R(e,o))return 1;P(r[0])===t[31]>>7&&C(r[0],s,r[0]),F(r[3],r[0],r[1])}(f,e))return-1;for(o=0;o<n;o++)r[o]=t[o];for(o=0;o<32;o++)r[o+32]=e[o];if(W(h,r,n),ar(h),nr(a,f,h),er(f,t.subarray(32)),$(a,f),tr(i,a),n-=64,g(t,0,i,0)){for(o=0;o<n;o++)r[o]=0;return-1}for(o=0;o<n;o++)r[o]=t[o+64];return n}function ur(r,t){if(32!==r.length)throw new Error("bad key size");if(24!==t.length)throw new Error("bad nonce size")}function cr(){for(var r=0;r<arguments.length;r++)if(!(arguments[r]instanceof Uint8Array))throw new TypeError("unexpected type, use Uint8Array")}function yr(r){for(var t=0;t<r.length;t++)r[t]=0}i.lowlevel={crypto_core_hsalsa20:_,crypto_stream_xor:M,crypto_stream:x,crypto_stream_salsa20_xor:d,crypto_stream_salsa20:E,crypto_onetimeauth:B,crypto_onetimeauth_verify:S,crypto_verify_16:b,crypto_verify_32:g,crypto_secretbox:k,crypto_secretbox_open:K,crypto_scalarmult:q,crypto_scalarmult_base:D,crypto_box_beforenm:X,crypto_box_afternm:j,crypto_box:function(r,t,n,e,o,i){var h=new Uint8Array(32);return X(h,o,i),j(r,t,n,e,h)},crypto_box_open:function(r,t,n,e,o,i){var h=new Uint8Array(32);return X(h,o,i),H(r,t,n,e,h)},crypto_box_keypair:V,crypto_hash:W,crypto_sign:fr,crypto_sign_keypair:or,crypto_sign_open:sr,crypto_secretbox_KEYBYTES:32,crypto_secretbox_NONCEBYTES:24,crypto_secretbox_ZEROBYTES:32,crypto_secretbox_BOXZEROBYTES:16,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_box_PUBLICKEYBYTES:32,crypto_box_SECRETKEYBYTES:32,crypto_box_BEFORENMBYTES:32,crypto_box_NONCEBYTES:24,crypto_box_ZEROBYTES:32,crypto_box_BOXZEROBYTES:16,crypto_sign_BYTES:64,crypto_sign_PUBLICKEYBYTES:32,crypto_sign_SECRETKEYBYTES:64,crypto_sign_SEEDBYTES:32,crypto_hash_BYTES:64,gf:v,D:c,L:ir,pack25519:z,unpack25519:N,M:F,A:O,S:I,Z:C,pow2523:G,add:$,set25519:Y,modL:hr,scalarmult:nr,scalarbase:er},i.randomBytes=function(r){var t=new Uint8Array(r);return h(t,r),t},i.secretbox=function(r,t,n){cr(r,t,n),ur(n,t);for(var e=new Uint8Array(32+r.length),o=new Uint8Array(e.length),i=0;i<r.length;i++)e[i+32]=r[i];return k(o,e,e.length,t,n),o.subarray(16)},i.secretbox.open=function(r,t,n){cr(r,t,n),ur(n,t);for(var e=new Uint8Array(16+r.length),o=new Uint8Array(e.length),i=0;i<r.length;i++)e[i+16]=r[i];return e.length<32||0!==K(o,e,e.length,t,n)?null:o.subarray(32)},i.secretbox.keyLength=32,i.secretbox.nonceLength=24,i.secretbox.overheadLength=16,i.scalarMult=function(r,t){if(cr(r,t),32!==r.length)throw new Error("bad n size");if(32!==t.length)throw new Error("bad p size");var n=new Uint8Array(32);return q(n,r,t),n},i.scalarMult.base=function(r){if(cr(r),32!==r.length)throw new Error("bad n size");var t=new Uint8Array(32);return D(t,r),t},i.scalarMult.scalarLength=32,i.scalarMult.groupElementLength=32,i.box=function(r,t,n,e){var o=i.box.before(n,e);return i.secretbox(r,t,o)},i.box.before=function(r,t){cr(r,t),function(r,t){if(32!==r.length)throw new Error("bad public key size");if(32!==t.length)throw new Error("bad secret key size")}(r,t);var n=new Uint8Array(32);return X(n,r,t),n},i.box.after=i.secretbox,i.box.open=function(r,t,n,e){var o=i.box.before(n,e);return i.secretbox.open(r,t,o)},i.box.open.after=i.secretbox.open,i.box.keyPair=function(){var r=new Uint8Array(32),t=new Uint8Array(32);return V(r,t),{publicKey:r,secretKey:t}},i.box.keyPair.fromSecretKey=function(r){if(cr(r),32!==r.length)throw new Error("bad secret key size");var t=new Uint8Array(32);return D(t,r),{publicKey:t,secretKey:new Uint8Array(r)}},i.box.publicKeyLength=32,i.box.secretKeyLength=32,i.box.sharedKeyLength=32,i.box.nonceLength=24,i.box.overheadLength=i.secretbox.overheadLength,i.sign=function(r,t){if(cr(r,t),64!==t.length)throw new Error("bad secret key size");var n=new Uint8Array(64+r.length);return fr(n,r,r.length,t),n},i.sign.open=function(r,t){if(cr(r,t),32!==t.length)throw new Error("bad public key size");var n=new Uint8Array(r.length),e=sr(n,r,r.length,t);if(e<0)return null;for(var o=new Uint8Array(e),i=0;i<o.length;i++)o[i]=n[i];return o},i.sign.detached=function(r,t){for(var n=i.sign(r,t),e=new Uint8Array(64),o=0;o<e.length;o++)e[o]=n[o];return e},i.sign.detached.verify=function(r,t,n){if(cr(r,t,n),64!==t.length)throw new Error("bad signature size");if(32!==n.length)throw new Error("bad public key size");var e,o=new Uint8Array(64+r.length),i=new Uint8Array(64+r.length);for(e=0;e<64;e++)o[e]=t[e];for(e=0;e<r.length;e++)o[e+64]=r[e];return 0<=sr(i,o,o.length,n)},i.sign.keyPair=function(){var r=new Uint8Array(32),t=new Uint8Array(64);return or(r,t),{publicKey:r,secretKey:t}},i.sign.keyPair.fromSecretKey=function(r){if(cr(r),64!==r.length)throw new Error("bad secret key size");for(var t=new Uint8Array(32),n=0;n<t.length;n++)t[n]=r[32+n];return{publicKey:t,secretKey:new Uint8Array(r)}},i.sign.keyPair.fromSeed=function(r){if(cr(r),32!==r.length)throw new Error("bad seed size");for(var t=new Uint8Array(32),n=new Uint8Array(64),e=0;e<32;e++)n[e]=r[e];return or(t,n,!0),{publicKey:t,secretKey:n}},i.sign.publicKeyLength=32,i.sign.secretKeyLength=64,i.sign.seedLength=32,i.sign.signatureLength=64,i.hash=function(r){cr(r);var t=new Uint8Array(64);return W(t,r,r.length),t},i.hash.hashLength=64,i.verify=function(r,t){return cr(r,t),0!==r.length&&0!==t.length&&(r.length===t.length&&0===w(r,0,t,0,r.length))},i.setPRNG=function(r){h=r},function(){var o="undefined"!=typeof self?self.crypto||self.msCrypto:null;if(o&&o.getRandomValues){i.setPRNG(function(r,t){var n,e=new Uint8Array(t);for(n=0;n<t;n+=65536)o.getRandomValues(e.subarray(n,n+Math.min(t-n,65536)));for(n=0;n<t;n++)r[n]=e[n];yr(e)})}else"undefined"!=typeof require&&(o=require("crypto"))&&o.randomBytes&&i.setPRNG(function(r,t){var n,e=o.randomBytes(t);for(n=0;n<t;n++)r[n]=e[n];yr(e)})}()}("undefined"!=typeof module&&module.exports?module.exports:self.nacl=self.nacl||{});"""


def login_html(error=""):
    if CFG["manual_login"]:
        form = """
      <p>Die automatische Anmeldung über den Windows-Benutzer war in diesem Browser nicht möglich.
         Du kannst stattdessen einen Namen eingeben.</p>
      <form method="post" action="/anmelden">
        <input class="field" name="name" maxlength="40" placeholder="Windows-Benutzername" autofocus required>
        <button class="btn" type="submit">Betreten</button>
      </form>"""
    else:
        form = """
      <p>Die automatische Anmeldung über den Windows-Benutzer war in diesem Browser nicht möglich.</p>"""
    err = '<div class="err">%s</div>' % error if error else ""
    return ("""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netzwerk-Chat – Anmeldung</title><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>""" + BASE_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:16px}
.box{width:min(460px,100%)}
.box .in{padding:22px}
p{color:#a9b7bf;margin:0 0 16px}
form{display:flex;gap:10px}
.hint{margin-top:18px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.hint code{font-family:var(--mono);color:var(--amber)}
.err{color:var(--red);font:600 12px/1.3 var(--mono);margin-bottom:12px}
</style></head><body>
<div class="box panel"><div class="panel-h">Netzwerk-Chat · Anmeldung</div><div class="in">""" + err + form + """
<div class="hint">Tipp für die automatische Anmeldung: Seite über den <b>Rechnernamen</b> aufrufen
(z.&nbsp;B. <code>http://SERVERNAME:%d</code>, nicht über die IP-Adresse) bzw. die Adresse in Windows
unter <i>Internetoptionen → Sicherheit → Lokales Intranet → Sites</i> eintragen.</div>
</div></div></body></html>""" % CFG["port"])


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
    print(" NETZWERK-CHAT  v%s   (Ende-zu-Ende-verschlüsselt)" % VERSION)
    print("=" * 60)
    print(" Adresse für alle im Netzwerk:  http://%s:%d" % (name, CFG["port"]))
    print(" Datenbank:                     %s" % CFG["db"])
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
