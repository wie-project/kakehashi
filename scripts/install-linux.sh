#!/usr/bin/env bash
# Dev helper: build from a git checkout and run `kh bottle ensure`.
#
# Preferred global install (crates.io):
#   cargo install kakehashi
#   kh bottle ensure          # freestanding libSystem is embedded in kh-runtime
#   kh install 7zip           # optional guest tool into bottle /usr/local/bin
#
# This script is for local trees only (not a substitute for cargo install).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"

echo "==> cargo build -p kakehashi --release"
cargo build -p kakehashi --release

echo "==> install → $BIN_DIR/kh"
mkdir -p "$BIN_DIR"
install -m 755 target/release/kh "$BIN_DIR/kh"

# Prefer a just-built / staged dylib when present; otherwise bottle ensure uses
# the freestanding bytes embedded in kh-runtime (crates.io path).
LIBARGS=()
for cand in \
  dist/guest/libSystem.B.dylib \
  crates/kh-runtime/resources/libSystem.B.dylib \
  target/aarch64-apple-darwin/release/libkh_libsystem.dylib
do
  if [[ -f "$cand" ]]; then
    LIBARGS=(--libsystem "$ROOT/$cand")
    break
  fi
done

echo "==> kh bottle ensure ${LIBARGS[*]:-}"
"$BIN_DIR/kh" bottle ensure "${LIBARGS[@]+"${LIBARGS[@]}"}" || true

echo
echo "Installed $BIN_DIR/kh"
echo "  kh bottle status"
echo "  kh install 7zip          # optional: Darwin 7zz → /usr/local/bin in bottle"
echo "  kh run 7zz -- a /tmp/x.7z ./file"
echo
echo "crates.io:  cargo install kakehashi && kh bottle ensure"
