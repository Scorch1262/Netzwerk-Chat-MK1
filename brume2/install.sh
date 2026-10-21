#!/bin/sh
# ============================================================
#  Netzwerk-Chat - Installer für GL.iNet Brume 2 (GL-MT2500)
#  Installer v1.0.0 - funktioniert OHNE Internet, wenn der
#  Ordner "ipk" (Python-Pakete) beiliegt.
#
#  Aufruf auf der Brume 2:   sh install.sh
#  Anderer Port:             PORT=8091 sh install.sh
#
#  Ergebnis:
#   - Programm und Daten in /root/Netzwerk-Chat
#   - Autostart über procd (/etc/init.d/netzwerk-chat)
#   - Firewall-Freigabe des Ports auch auf dem WAN-Port
# ============================================================
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
APPDIR=${APPDIR:-/root/Netzwerk-Chat}
INITD=${INITD:-/etc/init.d}
PORT=${PORT:-8090}
SERVICE=netzwerk-chat

say()  { echo "[Netzwerk-Chat] $*"; }
fail() { echo "[FEHLER] $*"; exit 1; }

echo
say "Installation auf GL.iNet Brume 2"

# --- Programmdatei suchen ---
SRC="$HERE/netzwerk_chat.py"
[ -f "$SRC" ] || SRC="$HERE/../netzwerk_chat.py"
[ -f "$SRC" ] || fail "netzwerk_chat.py nicht gefunden (muss neben install.sh oder eine Ebene höher liegen)."
VERSION=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$SRC" | head -n 1)
say "Version: ${VERSION:-unbekannt}"

# --- System prüfen ---
if [ -f /etc/openwrt_release ]; then
    . /etc/openwrt_release
    say "System: ${DISTRIB_DESCRIPTION:-OpenWrt} (${DISTRIB_ARCH:-?})"
fi

case "$PORT" in ''|*[!0-9]*) fail "PORT muss eine Zahl sein." ;; esac

# --- Python prüfen / offline installieren ---
py_ok() {
    python3 -c "import sqlite3, http.server, hashlib, hmac, secrets, json, argparse, http.cookies" >/dev/null 2>&1
}

if py_ok; then
    say "Python 3 ist vorhanden: $(python3 --version 2>&1)"
else
    if [ -f "$HERE/ipk/INHALT.txt" ]; then
        if [ -n "$DISTRIB_ARCH" ] && [ "$DISTRIB_ARCH" != "aarch64_cortex-a53" ]; then
            say "WARNUNG: Pakete sind für aarch64_cortex-a53, dieses Gerät meldet $DISTRIB_ARCH."
        fi
        say "Installiere Python 3 offline aus dem Ordner ipk ..."
        FILES=""
        COUNT=0
        while read -r NAME FILE SUM; do
            case "$NAME" in ''|\#*) continue ;; esac
            [ -f "$HERE/ipk/$FILE" ] || fail "Datei fehlt: ipk/$FILE - Paket unvollständig kopiert."
            if opkg status "$NAME" 2>/dev/null | grep -q "^Status:.* installed"; then
                continue                      # schon vorhanden
            fi
            FILES="$FILES $HERE/ipk/$FILE"
            COUNT=$((COUNT + 1))
        done < "$HERE/ipk/INHALT.txt"
        if [ "$COUNT" -gt 0 ]; then
            say "$COUNT Paket(e) werden installiert ..."
            # shellcheck disable=SC2086
            opkg install $FILES || fail "opkg-Installation fehlgeschlagen (siehe Meldungen oben)."
        fi
    else
        say "Kein Ordner ipk vorhanden - versuche Online-Installation (opkg) ..."
        opkg update && opkg install python3 \
            || fail "Python 3 konnte nicht installiert werden. Offline-Paket mit Ordner ipk verwenden."
    fi
    py_ok || fail "Python 3 ist installiert, aber Module fehlen. Bitte 'opkg install python3' ausführen."
    say "Python 3 installiert: $(python3 --version 2>&1)"
fi

# --- Port prüfen (nur wenn nicht schon von uns belegt) ---
if [ -x "$INITD/$SERVICE" ]; then
    "$INITD/$SERVICE" stop >/dev/null 2>&1 || true
    sleep 1
fi
if netstat -ltn 2>/dev/null | grep -q "[:.]$PORT[[:space:]]"; then
    fail "Port $PORT ist bereits belegt. Anderen Port wählen:  PORT=8091 sh install.sh"
fi

# --- Programm kopieren ---
mkdir -p "$APPDIR"
cp "$SRC" "$APPDIR/netzwerk_chat.py"
cp "$HERE/uninstall.sh" "$APPDIR/uninstall.sh" 2>/dev/null || true
[ -f "$HERE/ANLEITUNG_BRUME2.md" ] && cp "$HERE/ANLEITUNG_BRUME2.md" "$APPDIR/" || true
echo "$PORT" > "$APPDIR/port.txt"
say "Programm liegt in $APPDIR"

# --- Autostart (procd) ---
PY=$(command -v python3)
cat > "$INITD/$SERVICE" <<EOF
#!/bin/sh /etc/rc.common
# Netzwerk-Chat - Autostart (angelegt von install.sh)
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command $PY $APPDIR/netzwerk_chat.py --port $PORT --db $APPDIR/netzwerk_chat.db
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
chmod +x "$INITD/$SERVICE"
"$INITD/$SERVICE" enable
"$INITD/$SERVICE" start
say "Autostart eingerichtet und gestartet."

# --- Firewall: Port auch auf dem WAN-Port erlauben (LAN ist standardmäßig offen) ---
if command -v uci >/dev/null 2>&1; then
    uci -q delete firewall.netzwerkchat || true
    uci set firewall.netzwerkchat=rule
    uci set firewall.netzwerkchat.name='Allow-Netzwerk-Chat'
    uci set firewall.netzwerkchat.src='wan'
    uci set firewall.netzwerkchat.proto='tcp'
    uci set firewall.netzwerkchat.dest_port="$PORT"
    uci set firewall.netzwerkchat.target='ACCEPT'
    uci commit firewall
    /etc/init.d/firewall reload >/dev/null 2>&1 || true
    say "Firewall-Regel 'Allow-Netzwerk-Chat' (TCP $PORT) gesetzt."
fi

# --- Erreichbarkeit anzeigen ---
sleep 2
NAME=$(uci -q get system.@system[0].hostname 2>/dev/null || hostname)
echo
echo "============================================================"
echo " FERTIG - Netzwerk-Chat ${VERSION} läuft."
echo
echo " Aufruf im Browser:"
echo "   http://${NAME}:${PORT}"
for IP in $(ip -4 -o addr show 2>/dev/null | awk '$2 != "lo" {split($4,a,"/"); print a[1]}'); do
    echo "   http://${IP}:${PORT}"
done
echo
echo " Status:      /etc/init.d/$SERVICE status"
echo " Log:         logread -e netzwerk_chat"
echo " Neustart:    /etc/init.d/$SERVICE restart   (verwirft die Chats)"
echo " Entfernen:   sh $APPDIR/uninstall.sh"
echo "============================================================"
echo
