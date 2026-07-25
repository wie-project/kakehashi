#!/usr/bin/env bash
# Stage guest libSystem for bottle install / release tarballs.
#
# Two workflows this supports:
#
# 1) From source (on macOS arm64, or cross aarch64-apple-darwin):
#      cargo build -p kh-libsystem --release
#      # or: cargo build -p kh-libsystem --release --target aarch64-apple-darwin
#      ./scripts/stage-libsystem.sh
#    → dist/guest/libSystem.B.dylib  (LC_ID_DYLIB = /usr/lib/libSystem.B.dylib)
#
# 2) Release layout next to the Linux `kh` binary:
#      kakehashi-*-linux-aarch64/
#        bin/kh
#        lib/kakehashi/libSystem.B.dylib   # copy staged file here
#    Then on the Linux host:
#      ./bin/kh bottle create
#    auto-discovers ../lib/kakehashi/libSystem.B.dylib relative to the binary.
#
# Requires: a built libkh_libsystem.dylib (or pass SOURCE=).
# install_name_tool is optional — `kh bottle create` rewrites LC_ID_DYLIB itself.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/dist/guest}"
SOURCE="${SOURCE:-}"

if [[ -z "$SOURCE" ]]; then
  for cand in \
    target/aarch64-apple-darwin/release/libkh_libsystem.dylib \
    target/release/libkh_libsystem.dylib \
    target/debug/libkh_libsystem.dylib
  do
    if [[ -f "$cand" ]]; then
      SOURCE="$cand"
      break
    fi
  done
fi

if [[ -z "${SOURCE}" || ! -f "$SOURCE" ]]; then
  echo "error: no libkh_libsystem.dylib found." >&2
  echo "  cargo build -p kh-libsystem --release [--target aarch64-apple-darwin]" >&2
  echo "  or: SOURCE=/path/to/libkh_libsystem.dylib $0" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
DEST="$OUT_DIR/libSystem.B.dylib"
cp -f "$SOURCE" "$DEST"

if command -v install_name_tool >/dev/null 2>&1; then
  install_name_tool -id /usr/lib/libSystem.B.dylib "$DEST"
  echo "staged $DEST (install_name_tool id set)"
else
  echo "staged $DEST (LC_ID will be rewritten by kh bottle create)"
fi

if command -v otool >/dev/null 2>&1; then
  otool -D "$DEST" || true
fi

echo "copy into a release tree as:"
echo "  lib/kakehashi/libSystem.B.dylib"
echo "or pass:"
echo "  kh bottle create --libsystem $DEST"
