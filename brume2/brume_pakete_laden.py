#!/usr/bin/env python3
"""Netzwerk-Chat - Brume-2-Paket-Downloader v1.0.0

Lädt Python 3 samt allen Abhängigkeiten als .ipk-Dateien für die
GL.iNet Brume 2 (GL-MT2500: OpenWrt 21.02, Architektur aarch64_cortex-a53),
damit die Installation auf der Brume 2 ohne Internet funktioniert.

Läuft auf Mac, Windows und Linux - nur Python-Standardbibliothek.

    python3 brume_pakete_laden.py                  # -> ./ipk
    python3 brume_pakete_laden.py --ziel ipk --release 21.02.7
"""
import argparse
import gzip
import hashlib
import os
import re
import sys
import time
import urllib.request

BASE_URL = "https://downloads.openwrt.org/releases/{release}/packages/{arch}/{feed}/"
FEEDS = ("base", "packages")
# Komplettes Python 3 (alle Standardmodule) - Netzwerk-Chat braucht u. a.
# sqlite3, http.server, email, urllib, hashlib.
WANTED = ("python3",)
# Gehören zur Firmware (Target-/Kernel-Pakete) und sind nicht in den Feeds
FIRMWARE = {"libc", "libpthread", "librt", "libgcc", "libgcc1", "libatomic", "libatomic1",
            "libstdcpp", "libstdcpp6", "kernel", "busybox", "base-files", "ubox", "opkg"}


def fetch(url, tries=4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netzwerk-chat-brume-downloader"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except Exception as exc:          # Netzwerkfehler -> erneut versuchen
            last = exc
            time.sleep(2 * (i + 1))
    raise RuntimeError("Download fehlgeschlagen: %s (%s)" % (url, last))


def parse_index(text, feed_url):
    """Packages-Index (Debian-Format) -> {name: {...}}"""
    pkgs = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        fields = {}
        key = None
        for line in block.splitlines():
            if line.startswith(" ") and key:
                fields[key] += "\n" + line.strip()
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                fields[key] = val.strip()
        name = fields.get("Package")
        if not name or "Filename" not in fields:
            continue
        fields["_url"] = feed_url + fields["Filename"]
        pkgs.setdefault(name, fields)
        for prov in (fields.get("Provides") or "").split(","):
            prov = prov.strip().split(" ")[0]
            if prov:
                pkgs.setdefault("provides:" + prov, fields)
    return pkgs


def dep_names(depends):
    """'libc, python3-light (= 3.9.16-2), a | b' -> ['libc', 'python3-light', 'a']"""
    out = []
    for part in (depends or "").split(","):
        part = part.strip()
        if not part:
            continue
        first = part.split("|")[0].strip()     # bei Alternativen die erste nehmen
        name = first.split("(")[0].strip()
        if name:
            out.append(name)
    return out


def resolve(index, wanted):
    order, seen, skipped = [], set(), set()

    def visit(name):
        if name in seen:
            return
        seen.add(name)
        if name in FIRMWARE:
            skipped.add(name)
            return
        pkg = index.get(name) or index.get("provides:" + name)
        if not pkg:
            skipped.add(name)
            return
        for dep in dep_names(pkg.get("Depends")):
            visit(dep)
        if pkg["Package"] not in [p["Package"] for p in order]:
            order.append(pkg)

    for w in wanted:
        if w not in index:
            raise SystemExit("[FEHLER] Paket '%s' ist in den Feeds nicht vorhanden." % w)
        visit(w)
    return order, sorted(skipped)


def main():
    ap = argparse.ArgumentParser(description="Python-Pakete für die GL.iNet Brume 2 laden")
    ap.add_argument("--ziel", default="ipk", help="Zielordner (Standard: ipk)")
    ap.add_argument("--release", default="21.02.7", help="OpenWrt-Release (Standard: 21.02.7)")
    ap.add_argument("--arch", default="aarch64_cortex-a53", help="Paket-Architektur (Brume 2: aarch64_cortex-a53)")
    ap.add_argument("--index-dir", help=argparse.SUPPRESS)     # Tests: lokale Packages-Dateien
    args = ap.parse_args()

    print("=== Netzwerk-Chat: Python-Pakete für GL.iNet Brume 2 laden ===")
    print("OpenWrt %s, Architektur %s" % (args.release, args.arch))

    index = {}
    for feed in FEEDS:
        feed_url = BASE_URL.format(release=args.release, arch=args.arch, feed=feed)
        if args.index_dir:
            text = open(os.path.join(args.index_dir, feed + ".Packages"), encoding="utf-8").read()
        else:
            print("Lade Paketliste:", feed)
            text = gzip.decompress(fetch(feed_url + "Packages.gz")).decode("utf-8", "replace")
        for name, pkg in parse_index(text, feed_url).items():
            index.setdefault(name, pkg)

    order, skipped = resolve(index, WANTED)
    total = sum(int(p.get("Size", "0") or 0) for p in order)
    print("%d Pakete, zusammen ca. %.1f MB" % (len(order), total / 1e6))
    if skipped:
        print("Nicht geladen (Teil der Firmware):", ", ".join(skipped))

    os.makedirs(args.ziel, exist_ok=True)
    for old in os.listdir(args.ziel):
        if old.endswith(".ipk"):
            os.remove(os.path.join(args.ziel, old))

    lines = []
    for pkg in order:
        fname = os.path.basename(pkg["Filename"])
        path = os.path.join(args.ziel, fname)
        if args.index_dir:
            data = open(os.path.join(args.index_dir, fname), "rb").read()
        else:
            data = fetch(pkg["_url"])
        digest = hashlib.sha256(data).hexdigest()
        want = (pkg.get("SHA256sum") or "").lower()
        if want and digest != want:
            raise SystemExit("[FEHLER] Prüfsumme falsch: %s" % fname)
        with open(path, "wb") as fh:
            fh.write(data)
        lines.append("%s %s %s" % (pkg["Package"], fname, digest))
        print("   OK  %s" % fname)

    # Reihenfolge = Abhängigkeiten zuerst; wird vom Installer gelesen
    with open(os.path.join(args.ziel, "INHALT.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# paket datei sha256 - OpenWrt %s %s\n" % (args.release, args.arch))
        fh.write("\n".join(lines) + "\n")

    print()
    print("FERTIG: %d Pakete in '%s'." % (len(order), os.path.abspath(args.ziel)))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print("[FEHLER]", exc)
        print("Internetverbindung prüfen und erneut starten.")
        sys.exit(1)
