#!/usr/bin/env bash
# Stage freestanding guest libSystem into the crates.io embed path.
#
# Workflow (on macOS arm64, or with aarch64-apple-darwin target):
#   cargo build -p kh-libsystem --release --target aarch64-apple-darwin
#   ./scripts/stage-libsystem.sh
#
# Output:
#   crates/kh-runtime/resources/libSystem.B.dylib
#     Vendored into the kh-runtime crate and `include_bytes!`-embedded so
#     crates.io packages can `cargo install kakehashi` + `kh bottle ensure`
#     without a separate dylib download. Commit this file when it changes.
#
# Optional env:
#   SOURCE=…     path to libkh_libsystem.dylib (auto-detected otherwise)
#   OUT_DIR=…    destination dir (default: crates/kh-runtime/resources)
#
# install_name_tool is optional — `kh bottle create|ensure` rewrites LC_ID_DYLIB.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/crates/kh-runtime/resources}"
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
  echo "  cargo build -p kh-libsystem --release --target aarch64-apple-darwin" >&2
  echo "  or: SOURCE=/path/to/libkh_libsystem.dylib $0" >&2
  exit 1
fi

DEST="$OUT_DIR/libSystem.B.dylib"
mkdir -p "$OUT_DIR"
cp -f "$SOURCE" "$DEST"
if command -v install_name_tool >/dev/null 2>&1; then
  install_name_tool -id /usr/lib/libSystem.B.dylib "$DEST"
fi
chmod 755 "$DEST" 2>/dev/null || true
echo "staged $DEST  (crates.io embed — commit when shipping)"

if command -v otool >/dev/null 2>&1; then
  otool -D "$DEST" || true
else
  echo "note: LC_ID will be rewritten by kh bottle create|ensure"
fi

echo
echo "Dev / crates.io path (embedded after rebuild of kh-runtime):"
echo "  cargo build -p kakehashi"
echo "  kh bottle ensure"
echo "  # or override: kh bottle ensure --libsystem $DEST"
echo "  cargo publish -p kh-runtime   # includes resources/libSystem.B.dylib"
