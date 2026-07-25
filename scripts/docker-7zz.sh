#!/usr/bin/env bash
# Run 7zz (or any guest) under kh inside Linux aarch64 Docker/Colima.
#
# Uses a project-local bottle under .kh/ (gitignored) so you never need a
# hand-made .tmp-bottle tree. Guest libSystem is auto-discovered from
# dist/guest/ or target/ after scripts/stage-libsystem.sh.
#
# Usage:
#   ./scripts/stage-libsystem.sh          # once on macOS / with apple-darwin target
#   ./scripts/docker-7zz.sh --help
#   ./scripts/docker-7zz.sh h /Volumes/linux/src/README.md
#   ./scripts/docker-7zz.sh a /Volumes/linux/tmp/t.7z /Volumes/linux/src/README.md
#
# Extra env:
#   KAKEHASHI_SMOKE_IMAGE  docker image (default: kakehashi:dev)
#   KH_EXTRA_CARGO_ARGS    forwarded to cargo run (e.g. --release)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
# Guest sees the repo at /src; host files → /Volumes/linux/src/...
GUEST_ARGS=("$@")

if [[ ! -f dist/guest/libSystem.B.dylib ]]; then
  if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
    || [[ -f target/release/libkh_libsystem.dylib ]]; then
    ./scripts/stage-libsystem.sh
  else
    echo "error: no staged guest libSystem." >&2
    echo "  cargo build -p kh-libsystem --release --target aarch64-apple-darwin" >&2
    echo "  ./scripts/stage-libsystem.sh" >&2
    exit 1
  fi
fi

# Ensure dev image exists (toolchain only; repo is bind-mounted).
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
fi

# Project-local registry + bottle (persists on the bind mount, not host /tmp).
docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  "${IMAGE}" \
  bash -c '
set -euo pipefail
# Always rebuild the binary we execute (a stale release in the volume cache
# must not win over a freshly compiled debug kh).
cargo build -p kh-cli '"${KH_EXTRA_CARGO_ARGS:-}"'
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi
"$KH" bottle ensure
"$KH" bottle status
# No --root: registered bottle under .kh/data is used automatically.
exec "$KH" run tests/clang-probe/7zz.bin -- "$@"
' -- "${GUEST_ARGS[@]}"
