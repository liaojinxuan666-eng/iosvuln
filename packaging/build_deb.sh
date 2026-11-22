#!/bin/bash
# Build the Sileo-installable collector deb.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEB="$ROOT/packaging/deb"
OUT="$ROOT/packaging"

# Rootless layout: files install under /var/jb/usr, never /usr (read-only).
APP="$DEB/var/jb/usr/lib/iosvuln"
mkdir -p "$APP/tweak-source"
find "$ROOT/templates/ellekit" -maxdepth 1 -type f -exec cp {} "$APP/tweak-source/" \;
chmod 0755 "$DEB/DEBIAN/postinst" "$DEB/var/jb/usr/bin/iosvuln-collect" "$APP/collect.sh"
chmod 0644 "$DEB/DEBIAN/control"

dpkg-deb --build --root-owner-group "$DEB" "$OUT/dev.iosvuln.collect_0.1.4_iphoneos-arm64.deb"
echo "built: $OUT/dev.iosvuln.collect_0.1.4_iphoneos-arm64.deb"
dpkg-deb -I "$OUT/dev.iosvuln.collect_0.1.4_iphoneos-arm64.deb" | head -20
