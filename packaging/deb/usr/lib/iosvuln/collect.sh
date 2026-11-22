#!/bin/bash
# iosvuln on-device collector.
# Usage: iosvuln-collect [path-to-kernelcache-or-kext-dir]
# Output: /var/mobile/iosvuln/collection.json
# This script only reads files. It does not patch, exploit, or execute the target.

OUT_DIR=/var/mobile/iosvuln
OUT_JSON="$OUT_DIR/collection.json"
mkdir -p "$OUT_DIR"

INPUT="$1"
FOUND=""
MODE="auto"

if [ -n "$INPUT" ]; then
  if [ -f "$INPUT" ]; then
    FOUND="$INPUT"; MODE="file"
  elif [ -d "$INPUT" ]; then
    FOUND="$INPUT"; MODE="dir"
  fi
fi

if [ -z "$FOUND" ]; then
  for p in \
    /System/Library/Caches/com.apple.kernelcaches/kernelcache \
    /System/Library/Caches/com.apple.kernelcaches/kernelcache.release \
    /private/System/Library/Caches/com.apple.kernelcaches/kernelcache \
    /var/MobileAsset/Assets/com_apple_MobileAsset_Kernelcache/kernelcache
  do
    if [ -f "$p" ]; then FOUND="$p"; MODE="file"; break; fi
  done
fi

echo "{" > "$OUT_JSON"
echo "  \"tool\": \"iosvuln-collector\"," >> "$OUT_JSON"
echo "  \"mode\": \"$MODE\"," >> "$OUT_JSON"
echo "  \"source\": \"$FOUND\"," >> "$OUT_JSON"

if [ -n "$FOUND" ] && [ "$MODE" = "file" ]; then
  SIZE=$(stat -f %z "$FOUND" 2>/dev/null || stat -c %s "$FOUND" 2>/dev/null || echo 0)
  HASH=$(shasum -a 256 "$FOUND" 2>/dev/null | awk '{print $1}' || sha256sum "$FOUND" 2>/dev/null | awk '{print $1}' || echo "")
  COPY="$OUT_DIR/kernelcache"
  cp "$FOUND" "$COPY" 2>/dev/null || COPY="$FOUND"
  echo "  \"size\": $SIZE," >> "$OUT_JSON"
  echo "  \"sha256\": \"$HASH\"," >> "$OUT_JSON"
  echo "  \"local_copy\": \"$COPY\"," >> "$OUT_JSON"
fi

echo "  \"kext_hits\": [" >> "$OUT_JSON"
FIRST=1
if [ -n "$FOUND" ]; then
  if [ "$MODE" = "dir" ]; then
    TARGETS=$(find "$FOUND" -type f 2>/dev/null | head -200)
  else
    TARGETS="$FOUND"
  fi
  for f in $TARGETS; do
    [ -f "$f" ] || continue
    MATCH=$(strings -a "$f" 2>/dev/null | grep -E 'com\.apple\.driver\.(IOSurface|IOKit)|IOSurface|task_for_pid|mach_msg' | head -20)
    if [ -n "$MATCH" ]; then
      [ $FIRST -eq 0 ] && echo "," >> "$OUT_JSON"
      FIRST=0
      printf '    {"file": "%s", "hits": [' "$f" >> "$OUT_JSON"
      J=1
      for line in $MATCH; do
        [ $J -eq 1 ] || printf ', ' >> "$OUT_JSON"
        J=0
        printf '"%s"' "$line" >> "$OUT_JSON"
      done
      printf ']}' >> "$OUT_JSON"
    fi
  done
fi
echo "" >> "$OUT_JSON"
echo "  ]" >> "$OUT_JSON"
echo "}" >> "$OUT_JSON"

echo "iosvuln: collection written to $OUT_JSON"
cat "$OUT_JSON"
exit 0
