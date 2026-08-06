#!/usr/bin/env bash
# Run Apple clang (from CLT) under kh inside Linux aarch64 Docker/Colima.
#
# Install source: public Software Update catalog (same as git / xcode-tools).
#
# Persistence:
#   bottle + cache live under <repo>/.kh/data (bind-mounted as /src/.kh/data)
#
# Usage:
#   ./scripts/docker-clang.sh --version
#   ./scripts/docker-clang.sh -cc1 -help
#   ./scripts/docker-clang.sh -- -x c -c /Volumes/linux/src/tests/clang-probe/puts_hello.c -o /Volumes/linux/out/puts.o
#
# Env:
#   KAKEHASHI_XCODE_TOOLS_VERSION  pin catalog title substring (e.g. 26.6)
#   KAKEHASHI_FORCE_DOWNLOAD=1     re-fetch even if bottle/cache present
#   KAKEHASHI_SMOKE_IMAGE          docker image (default: kakehashi:dev)
#   KH_EXTRA_CARGO_ARGS            cargo flags for kh (default: --release)
#   KH_OUT                         durable guest /out (default: <repo>/.tmp/kh-out)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
  KH_EXTRA_CARGO_ARGS=--release
fi
GUEST_ARGS=("$@")

mkdir -p "$KH_OUT" "$ROOT/.kh"

if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
  || [[ -f target/release/libkh_libsystem.dylib ]]; then
  ./scripts/stage-libsystem.sh
elif [[ -f crates/kh-runtime/resources/libSystem.B.dylib ]]; then
  echo "note: using crates/kh-runtime/resources/libSystem.B.dylib"
else
  echo "error: no guest libSystem (need resources/ embed or a built dylib)." >&2
  exit 1
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
fi

DOCKER_VOLS=(
  -v "${ROOT}:/src"
  -v kh-target-cache:/src/target
  -v "${KH_OUT}:/out"
)
DOCKER_ENVS=()

for e in KAKEHASHI_XCODE_TOOLS_VERSION KAKEHASHI_FORCE_DOWNLOAD \
  KAKEHASHI_BOUNDARY_STATS KAKEHASHI_FUTEX_STATS KAKEHASHI_HEAP_STATS; do
  if [[ -n "${!e:-}" ]]; then
    DOCKER_ENVS+=(-e "${e}=${!e}")
  fi
done

echo "==> guest clang via kh  (bottle+cache: $ROOT/.kh/data)"
echo "==> durable /out:       $KH_OUT  ↔  guest /Volumes/linux/out"
echo "==> args: ${GUEST_ARGS[*]:-<none>}"

set +e
docker run --rm \
  "${DOCKER_VOLS[@]}" \
  "${DOCKER_ENVS[@]+"${DOCKER_ENVS[@]}"}" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS}" \
  "${IMAGE}" \
  bash -c '
set -euo pipefail
cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi
"$KH" bottle ensure
"$KH" install xcode-tools

exec "$KH" run clang -- "$@"
' -- ${GUEST_ARGS[@]+"${GUEST_ARGS[@]}"}
rc=$?
set -e
exit "$rc"
