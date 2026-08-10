# Shared host-side helpers for Docker/Colima guest runners.
# shellcheck shell=bash
# Sourced by scripts/docker-kh.sh and thin tool wrappers.

kh_docker_root() {
  # Caller must set ROOT before sourcing, or we derive from this file.
  if [[ -z "${ROOT:-}" ]]; then
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  fi
  cd "$ROOT"
}

# Stage freestanding libSystem when a fresh build is present; else require embed.
kh_docker_stage_libsystem() {
  if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
    || [[ -f target/release/libkh_libsystem.dylib ]]; then
    ./scripts/stage-libsystem.sh
  elif [[ -f crates/kh-runtime/resources/libSystem.B.dylib ]]; then
    echo "note: using crates/kh-runtime/resources/libSystem.B.dylib"
  else
    echo "error: no guest libSystem (need resources/ embed or a built dylib)." >&2
    echo "  cargo build -p kh-libsystem --release --target aarch64-apple-darwin" >&2
    echo "  ./scripts/stage-libsystem.sh" >&2
    return 1
  fi
}

# Ensure the dev image exists (toolchain only; repo is bind-mounted).
kh_docker_ensure_image() {
  local image="${1:-${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}}"
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    echo "==> docker build ${image}"
    docker build -t "${image}" -f Dockerfile.dev .
  fi
}

# Hint when args target ephemeral container /tmp.
kh_docker_warn_ephemeral_paths() {
  local kh_out="$1"
  shift
  local a
  for a in "$@"; do
    if [[ "$a" == /Volumes/linux/tmp/* ]] || [[ "$a" == /tmp/* ]]; then
      echo "note: path '$a' is container-local and disappears when Docker exits." >&2
      echo "      Prefer /Volumes/linux/out/…  →  host ${kh_out}/…" >&2
      echo "      or     /Volumes/linux/src/.tmp/…  →  host ${ROOT}/.tmp/…" >&2
      break
    fi
  done
}

# List host KH_OUT after a successful run (if non-empty).
kh_docker_list_out() {
  local kh_out="$1"
  if compgen -G "${kh_out}/*" > /dev/null 2>&1; then
    echo
    echo "==> host files under ${kh_out}:"
    ls -lah "${kh_out}" | sed 's/^/    /'
  fi
}

# Build default docker -v list: repo, cargo cache, durable /out.
# Appends KH_DOCKER_MOUNTS (space-separated host:container pairs).
# Optional extra args are appended as-is (e.g. -v probe mounts).
kh_docker_default_vols() {
  local root="$1"
  local kh_out="$2"
  DOCKER_VOLS=(
    -v "${root}:/src"
    -v kh-target-cache:/src/target
    -v "${kh_out}:/out"
  )
  # shellcheck disable=SC2206
  if [[ -n "${KH_DOCKER_MOUNTS:-}" ]]; then
    local m
    for m in ${KH_DOCKER_MOUNTS}; do
      DOCKER_VOLS+=(-v "$m")
    done
  fi
}

# Forward a fixed set of optional env vars into DOCKER_ENVS when set.
kh_docker_forward_envs() {
  DOCKER_ENVS=()
  local e
  for e in "$@"; do
    if [[ -n "${!e:-}" ]]; then
      DOCKER_ENVS+=(-e "${e}=${!e}")
    fi
  done
}
