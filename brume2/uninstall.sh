#!/bin/sh
# Netzwerk-Chat - Deinstallation auf der GL.iNet Brume 2 (Installer v1.0.0)
# Entfernt Autostart, Firewall-Regel und /root/Netzwerk-Chat.
# Python 3 bleibt installiert (wird evtl. von anderen Programmen genutzt).
APPDIR=${APPDIR:-/root/Netzwerk-Chat}
INITD=${INITD:-/etc/init.d}
SERVICE=netzwerk-chat

if [ -x "$INITD/$SERVICE" ]; then
    "$INITD/$SERVICE" stop >/dev/null 2>&1
    "$INITD/$SERVICE" disable >/dev/null 2>&1
    rm -f "$INITD/$SERVICE"
    echo "[Netzwerk-Chat] Dienst gestoppt und Autostart entfernt."
fi
if command -v uci >/dev/null 2>&1 && uci -q get firewall.netzwerkchat >/dev/null; then
    uci delete firewall.netzwerkchat
    uci commit firewall
    /etc/init.d/firewall reload >/dev/null 2>&1
    echo "[Netzwerk-Chat] Firewall-Regel entfernt."
fi
rm -rf "$APPDIR"
echo "[Netzwerk-Chat] $APPDIR entfernt. Python 3 bleibt installiert."
