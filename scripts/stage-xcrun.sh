#!/usr/bin/env bash
# Stage clean-room guest xcrun into the crates.io embed path.
#
# Workflow (on macOS arm64, or with aarch64-apple-darwin target):
#   cargo build -p kh-xcrun --release --target aarch64-apple-darwin
#   ./scripts/stage-xcrun.sh
#
# Output:
#   crates/kh-runtime/resources/xcrun
#     Vendored into the kh-runtime crate and `include_bytes!`-embedded so
#     crates.io packages can `cargo install kakehashi` + `kh bottle ensure`
#     without a separate download. Commit this file when it changes.
#
# Optional env:
#   SOURCE=…     path to xcrun binary (auto-detected otherwise)
#   OUT_DIR=…    destination dir (default: crates/kh-runtime/resources)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/crates/kh-runtime/resources}"
SOURCE="${SOURCE:-}"

if [[ -z "$SOURCE" ]]; then
  for cand in \
    target/aarch64-apple-darwin/release/xcrun \
    target/aarch64-apple-darwin/debug/xcrun \
    target/release/xcrun \
    target/debug/xcrun
  do
    if [[ -f "$cand" ]]; then
      SOURCE="$cand"
      break
    fi
  done
fi

if [[ -z "${SOURCE}" || ! -f "$SOURCE" ]]; then
  echo "error: no xcrun binary found." >&2
  echo "  cargo build -p kh-xcrun --release --target aarch64-apple-darwin" >&2
  echo "  or: SOURCE=/path/to/xcrun $0" >&2
  exit 1
fi

DEST="$OUT_DIR/xcrun"
mkdir -p "$OUT_DIR"
cp -f "$SOURCE" "$DEST"
chmod 755 "$DEST" 2>/dev/null || true
echo "staged $DEST  (crates.io embed — commit when shipping)"

if command -v file >/dev/null 2>&1; then
  file "$DEST" || true
fi
if command -v otool >/dev/null 2>&1; then
  otool -L "$DEST" 2>/dev/null | head -5 || true
fi

echo
echo "Dev / crates.io path (embedded after rebuild of kh-runtime):"
echo "  cargo build -p kakehashi"
echo "  kh bottle ensure"
echo "  # or override: KAKEHASHI_XCRUN=$DEST kh bottle ensure"
