#!/usr/bin/env bash
# Run Darwin 7zz (tests/clang-probe/7zz.bin) under kh inside Linux aarch64
# Docker/Colima.
#
# Uses a project-local bottle under .kh/ (gitignored). Guest libSystem comes
# from dist/guest/ after scripts/stage-libsystem.sh.
#
# Path map (this is the bit people miss)
# --------------------------------------
#   Host path                         Guest path under kh
#   ----------------------------      ----------------------------------
#   <repo>/…                          /Volumes/linux/src/…
#   container /tmp/…                  /Volumes/linux/tmp/…
#   anything under KH_OUT (below)     /Volumes/linux/out/…
#
# Container /tmp dies with `docker run --rm`. To keep archives on the host,
# write them under /Volumes/linux/out/… (bind-mounted to .tmp/kh-out by
# default) or under /Volumes/linux/src/.tmp/….
#
# Usage:
#   ./scripts/stage-libsystem.sh
#   ./scripts/docker-7zz.sh --help
#   ./scripts/docker-7zz.sh h /Volumes/linux/src/README.md
#
#   # Archive lands on the HOST at .tmp/kh-out/demo.7z
#   ./scripts/docker-7zz.sh a /Volumes/linux/out/demo.7z \
#       /Volumes/linux/src/README.md
#
#   # Or under the repo tree (also host-visible):
#   ./scripts/docker-7zz.sh a /Volumes/linux/src/.tmp/demo.7z \
#       /Volumes/linux/src/README.md
#
# Extra env:
#   KAKEHASHI_SMOKE_IMAGE  docker image (default: kakehashi:dev)
#   KH_EXTRA_CARGO_ARGS    forwarded to cargo build (e.g. --release)
#   KH_DOCKER_MOUNTS       extra docker -v mounts, space-separated
#                          e.g. "/Users/me/Nook:/nook"
#                          Guest: /Volumes/linux/nook/...
#   KH_OUT                 host dir for durable guest output
#                          (default: <repo>/.tmp/kh-out → guest /out
#                           → /Volumes/linux/out/…)
#
# Fair multi-thread benches: Colima defaults to few vCPUs. Prefer
# scripts/bench-fair-local.sh for apples-to-apples numbers. To raise VM size:
#   colima stop && colima start --cpu 8 --memory 8

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
# Durable host output (gitignored). Guest sees it as /out → /Volumes/linux/out.
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
GUEST_ARGS=("$@")

mkdir -p "$KH_OUT"

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

DOCKER_VOLS=(
  -v "${ROOT}:/src"
  -v kh-target-cache:/src/target
  -v "${KH_OUT}:/out"
)
# shellcheck disable=SC2206
if [[ -n "${KH_DOCKER_MOUNTS:-}" ]]; then
  for m in ${KH_DOCKER_MOUNTS}; do
    DOCKER_VOLS+=(-v "$m")
  done
fi

# Hint when the user targets ephemeral container /tmp.
for a in "${GUEST_ARGS[@]+"${GUEST_ARGS[@]}"}"; do
  if [[ "$a" == /Volumes/linux/tmp/* ]] || [[ "$a" == /tmp/* ]]; then
    echo "note: path '$a' is container-local and disappears when Docker exits." >&2
    echo "      Prefer /Volumes/linux/out/…  →  host $KH_OUT/…" >&2
    echo "      or     /Volumes/linux/src/.tmp/…  →  host $ROOT/.tmp/…" >&2
    break
  fi
done

echo "==> guest 7zz via kh  (durable out: $KH_OUT  ↔  /Volumes/linux/out)"
echo "==> args: ${GUEST_ARGS[*]:-<none>}"

# Project-local registry + bottle (persists on the bind mount, not host /tmp).
docker run --rm \
  "${DOCKER_VOLS[@]}" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KAKEHASHI_TRAMPOLINE=${KAKEHASHI_TRAMPOLINE:-}" \
  -e "KAKEHASHI_HYPERCALL=${KAKEHASHI_HYPERCALL:-}" \
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

# After success, if anything was written under KH_OUT, list it.
if compgen -G "$KH_OUT/*" > /dev/null 2>&1; then
  echo
  echo "==> host files under $KH_OUT:"
  ls -lah "$KH_OUT" | sed 's/^/    /'
fi
