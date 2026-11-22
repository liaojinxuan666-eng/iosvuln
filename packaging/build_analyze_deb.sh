#!/bin/bash
# Build the on-device FULL ANALYZER deb (python3 package + iosvuln CLI).
# This differs from build_deb.sh (collector only): it ships the complete
# static-analysis engine so the iPhone itself can run `iosvuln run/demo/...`.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEB="$ROOT/packaging/analyze-deb"
# Rootless layout: files install under /var/jb/usr, never /usr (read-only).
APP="$DEB/var/jb/usr/lib/iosvuln"
OUT="$ROOT/packaging"

# Clean stale copies from a previous build.
rm -rf "$APP/iosvuln" "$APP/examples"
mkdir -p "$APP/iosvuln" "$APP/examples"

# Ship the entire Python package (exclude caches).
find "$ROOT/iosvuln" -maxdepth 1 -type f -name '*.py' -exec cp {} "$APP/iosvuln/" \;

# Ship demo fixtures so `iosvuln demo` works on-device with no network.
cp "$ROOT"/examples/*.json "$ROOT"/examples/*.log "$APP/examples/" 2>/dev/null || true
cp "$ROOT/README.md" "$APP/README.md" 2>/dev/null || true

# zsh shortcut file is a hand-maintained source file (not generated), keep it.

chmod 0755 "$DEB/DEBIAN/postinst" "$DEB/var/jb/usr/bin/iosvuln"
chmod 0644 "$DEB/DEBIAN/control"

dpkg-deb --build --root-owner-group "$DEB" "$OUT/dev.iosvuln.analyze_0.1.4_iphoneos-arm64.deb"
echo "built: $OUT/dev.iosvuln.analyze_0.1.4_iphoneos-arm64.deb"
dpkg-deb -I "$OUT/dev.iosvuln.analyze_0.1.4_iphoneos-arm64.deb" | head -20
