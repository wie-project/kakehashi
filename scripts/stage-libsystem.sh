#!/usr/bin/env bash
# Stage freestanding guest libSystem for bottle install and crates.io.
#
# Workflow (on macOS arm64, or with aarch64-apple-darwin target):
#   cargo build -p kh-libsystem --release --target aarch64-apple-darwin
#   ./scripts/stage-libsystem.sh
#
# Outputs:
#   1) dist/guest/libSystem.B.dylib
#        Dev / Docker override path (`kh bottle ensure --libsystem …`).
#   2) crates/kh-runtime/resources/libSystem.B.dylib
#        Vendored into the kh-runtime crate and `include_bytes!`-embedded so
#        crates.io packages can `cargo install kakehashi` + `kh bottle ensure`
#        without a separate dylib download. Commit this file when it changes.
#
# Optional env:
#   SOURCE=…     path to libkh_libsystem.dylib (auto-detected otherwise)
#   OUT_DIR=…    staged dist path (default: <repo>/dist/guest)
#   EMBED=0      skip updating crates/kh-runtime/resources/ (dist only)
#
# install_name_tool is optional — `kh bottle create|ensure` rewrites LC_ID_DYLIB.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/dist/guest}"
EMBED_DIR="$ROOT/crates/kh-runtime/resources"
SOURCE="${SOURCE:-}"
EMBED="${EMBED:-1}"

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
  echo "  cargo build -p kh-libsystem --release --target aarch64-apple-darwin" >&2
  echo "  or: SOURCE=/path/to/libkh_libsystem.dylib $0" >&2
  exit 1
fi

stage_one() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cp -f "$SOURCE" "$dest"
  if command -v install_name_tool >/dev/null 2>&1; then
    install_name_tool -id /usr/lib/libSystem.B.dylib "$dest"
  fi
  chmod 755 "$dest" 2>/dev/null || true
}

DEST_DIST="$OUT_DIR/libSystem.B.dylib"
stage_one "$DEST_DIST"
echo "staged $DEST_DIST"

if [[ "$EMBED" != "0" ]]; then
  DEST_EMBED="$EMBED_DIR/libSystem.B.dylib"
  stage_one "$DEST_EMBED"
  echo "staged $DEST_EMBED  (crates.io embed — commit when shipping)"
fi

if command -v otool >/dev/null 2>&1; then
  otool -D "$DEST_DIST" || true
elif command -v install_name_tool >/dev/null 2>&1; then
  :
else
  echo "note: LC_ID will be rewritten by kh bottle create|ensure"
fi

echo
echo "Dev / override:"
echo "  kh bottle ensure --libsystem $DEST_DIST"
echo "crates.io / cargo install (uses embedded resources/ after rebuild):"
echo "  cargo publish -p kh-runtime   # includes resources/libSystem.B.dylib"
echo "  cargo install kakehashi && kh bottle ensure"
