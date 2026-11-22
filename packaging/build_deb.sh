#!/bin/bash
# Build the Sileo-installable collector deb.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEB="$ROOT/packaging/deb"
OUT="$ROOT/packaging"

mkdir -p "$DEB/usr/lib/iosvuln/tweak-source"
cp "$ROOT/templates/ellekit/"* "$DEB/usr/lib/iosvuln/tweak-source/"
chmod 0755 "$DEB/DEBIAN/postinst" "$DEB/usr/bin/iosvuln-collect" "$DEB/usr/lib/iosvuln/collect.sh"
chmod 0644 "$DEB/DEBIAN/control"

dpkg-deb --build --root-owner-group "$DEB" "$OUT/dev.iosvuln.collect_0.1.0_iphoneos-arm64.deb"
echo "built: $OUT/dev.iosvuln.collect_0.1.0_iphoneos-arm64.deb"
dpkg-deb -I "$OUT/dev.iosvuln.collect_0.1.0_iphoneos-arm64.deb" | head -20
