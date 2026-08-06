#!/usr/bin/env bash
# Run Apple git (from CLT) under kh inside Linux aarch64 Docker/Colima.
#
# Install source: public Software Update catalog (swscan.apple.com) — no Apple ID.
#
# Persistence (no re-download on every docker run):
#   bottle + cache live under <repo>/.kh/data (bind-mounted as /src/.kh/data)
#
# Usage:
#   ./scripts/docker-git.sh --version
#   ./scripts/docker-git.sh status
#   ./scripts/docker-git.sh clone https://github.com/torvalds/linux.git
#     → writes to guest /Volumes/linux/out/linux  ↔  host <repo>/.tmp/kh-out/linux
#   ./scripts/docker-git.sh ls-remote git@github.com:octocat/Hello-World.git
#     → needs host OpenSSH in the image (`openssh-client`); bottle bridges
#       guest /usr/bin/ssh → host. GitHub needs a registered key under
#       ~/.ssh (mounted into the container as /root/.ssh). Full local SSH
#       clone without GitHub keys: ./scripts/docker-git-ssh.sh
#
# Env:
#   KAKEHASHI_XCODE_TOOLS_VERSION  pin catalog title substring (e.g. 26.6)
#   KAKEHASHI_FORCE_DOWNLOAD=1     re-fetch even if bottle/cache present
#   KAKEHASHI_SMOKE_IMAGE          docker image (default: kakehashi:dev)
#   KH_EXTRA_CARGO_ARGS            cargo flags for kh (default: --release)
#                                  Debug rustls is multi‑× slower on HTTPS packs;
#                                  set empty for an unoptimized kh: KH_EXTRA_CARGO_ARGS=
#   KH_OUT                         durable guest /out (default: <repo>/.tmp/kh-out)
#   KH_CLONE_IN_SRC=1              do not rewrite bare `clone <url>` into /out
#   GIT_SSH_COMMAND                passed through to the guest (host OpenSSH flags)
#   KH_NO_SSH_MOUNT=1              do not bind-mount host ~/.ssh → /root/.ssh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
# Default release: host rustls on the TLS FD path is a real bottleneck in debug.
# Override with empty for unoptimized kh: `KH_EXTRA_CARGO_ARGS= ./scripts/docker-git.sh …`
# (bash 3.2-safe: `-v` is not available on stock macOS /bin/bash)
if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
  KH_EXTRA_CARGO_ARGS=--release
fi
GUEST_ARGS=("$@")

# Bare `clone <url>` (no destination) would land under guest CWD → host <repo>/linux
# on the bind mount (easy to miss / slow on large trees). Prefer durable /out.
if [[ "${KH_CLONE_IN_SRC:-}" != "1" ]] \
  && [[ ${#GUEST_ARGS[@]} -eq 2 ]] \
  && [[ "${GUEST_ARGS[0]}" == "clone" ]] \
  && [[ "${GUEST_ARGS[1]}" == https://* || "${GUEST_ARGS[1]}" == http://* \
        || "${GUEST_ARGS[1]}" == git@* || "${GUEST_ARGS[1]}" == ssh://* ]]; then
  url="${GUEST_ARGS[1]}"
  base="${url%/}"
  base="${base%.git}"
  base="${base##*/}"
  # ssh://user@host:port/path/repo.git → last path segment
  if [[ -z "$base" || "$base" == "*" ]]; then
    base="repo"
  fi
  GUEST_ARGS=(clone --progress "$url" "/Volumes/linux/out/${base}")
  echo "==> clone dest: guest /Volumes/linux/out/${base}"
  echo "                host  ${KH_OUT}/${base}"
  echo "    (during receive only .git/ exists; worktree appears after pack)"
fi

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

# Host OpenSSH runs as root inside the container. Mount the developer's
# `~/.ssh` so `git@github.com:…` can use id_ed25519 / config / known_hosts.
# (Mac launchd SSH_AUTH_SOCK does not work inside Colima/Linux — use files.)
if [[ "${KH_NO_SSH_MOUNT:-}" != "1" ]] && [[ -d "${HOME}/.ssh" ]]; then
  DOCKER_VOLS+=(-v "${HOME}/.ssh:/root/.ssh:ro")
  echo "==> SSH identities: host ${HOME}/.ssh → container /root/.ssh (ro)"
fi

for e in KAKEHASHI_XCODE_TOOLS_VERSION KAKEHASHI_FORCE_DOWNLOAD \
  KAKEHASHI_BOUNDARY_STATS KAKEHASHI_FUTEX_STATS KAKEHASHI_HEAP_STATS \
  GIT_SSH_COMMAND; do
  if [[ -n "${!e:-}" ]]; then
    DOCKER_ENVS+=(-e "${e}=${!e}")
  fi
done

echo "==> guest git via kh  (bottle+cache: $ROOT/.kh/data)"
echo "==> durable /out:     $KH_OUT  ↔  guest /Volumes/linux/out"
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
if ! command -v ssh >/dev/null 2>&1; then
  echo "error: host OpenSSH client missing (apt install openssh-client;" >&2
  echo "       rebuild image: docker build -t kakehashi:dev -f Dockerfile.dev .)" >&2
  exit 1
fi
cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi
"$KH" bottle ensure
"$KH" install xcode-tools

"$KH" run git -- config --global user.email "kh@test.io"
"$KH" run git -- config --global user.name "Vladislav"
# Default Git protocol v2 (ls-refs / fetch over smart HTTP). v1 still works if set.
"$KH" run git -- config --global protocol.version 2
# Large want-lists (full monorepo clones) exceed the default ~1 MiB buffer and
# switch git remote-curl to CURLOPT_READFUNCTION + chunked POST. Freestanding
# gathers that path; a high postBuffer keeps the simpler POSTFIELDS path too.
"$KH" run git -- config --global http.postBuffer 524288000

exec "$KH" run git -- "$@"
' -- ${GUEST_ARGS[@]+"${GUEST_ARGS[@]}"}
rc=$?
set -e
exit "$rc"
