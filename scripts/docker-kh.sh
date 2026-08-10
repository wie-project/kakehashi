#!/usr/bin/env bash
# Universal guest runner under Docker/Colima (Linux aarch64).
#
#   cargo build → bottle ensure → optional install → kh run <tool> -- …
#
# Usage:
#   ./scripts/docker-kh.sh 7zz  -- a /Volumes/linux/out/demo.7z /Volumes/linux/src/README.md
#   ./scripts/docker-kh.sh curl -- -sS -o /Volumes/linux/out/body http://example.com/
#   ./scripts/docker-kh.sh curl --probe -- --version
#   ./scripts/docker-kh.sh git  -- --version
#   ./scripts/docker-kh.sh git  -- clone https://github.com/octocat/Hello-World.git
#   ./scripts/docker-kh.sh clang -- --version
#   ./scripts/docker-kh.sh run  -- tests/clang-probe/puts_hello
#   ./scripts/docker-kh.sh run  -- /usr/local/bin/curl --version   # after install
#
# Path map:
#   Host <repo>/…              → guest /Volumes/linux/src/…
#   Host $KH_OUT (default .tmp/kh-out) → guest /Volumes/linux/out/…
#   container /tmp/…           → guest /Volumes/linux/tmp/…  (ephemeral)
#
# Env (shared):
#   KAKEHASHI_SMOKE_IMAGE   docker image (default: kakehashi:dev)
#   KH_EXTRA_CARGO_ARGS     cargo flags (git/clang default --release)
#   KH_OUT                  durable host output dir
#   KH_DOCKER_MOUNTS        extra -v mounts, space-separated
#   KAKEHASHI_XCODE_TOOLS_VERSION / KAKEHASHI_FORCE_DOWNLOAD
#   KAKEHASHI_BOUNDARY_STATS / KAKEHASHI_FUTEX_STATS / KAKEHASHI_HEAP_STATS
#   KAKEHASHI_LOAD_TIMING
#   KAKEHASHI_CURL          host path to Darwin curl (skip download)
#   KH_CURL_PROBE=1         curl: capture stderr + optional kh trace
#   KH_PROBE_DIR            probe logs (default: .tmp/kh-curl-probe)
#   KH_TRACE_JSON           1 = kh trace --json in probe mode (default: 1)
#   KH_CLONE_IN_SRC=1       git: do not rewrite bare clone into /out
#   GIT_SSH_COMMAND         passed into the container
#   KH_NO_SSH_MOUNT=1       do not mount host ~/.ssh
#
# Specialized smokes (not covered here): docker-smoke, docker-curl-options,
# docker-git-{ssh,http,push,github}.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/docker-common.sh
source "$ROOT/scripts/lib/docker-common.sh"
kh_docker_root

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \?//'
  exit 2
}

TOOL=""
PROBE=0
GUEST_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --probe) PROBE=1; shift ;;
    --) shift; GUEST_ARGS+=("$@"); break ;;
    7zz|curl|git|clang|run)
      if [[ -n "$TOOL" ]]; then
        # Already have a tool — remaining tokens are guest args.
        GUEST_ARGS+=("$@")
        break
      fi
      TOOL="$1"
      shift
      # Optional second -- before guest args.
      if [[ "${1:-}" == "--" ]]; then
        shift
      fi
      GUEST_ARGS+=("$@")
      break
      ;;
    *)
      if [[ -z "$TOOL" ]]; then
        echo "error: unknown tool '$1' (use 7zz|curl|git|clang|run)" >&2
        usage
      fi
      GUEST_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$TOOL" ]]; then
  usage
fi

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
KH_PROBE_DIR="${KH_PROBE_DIR:-$ROOT/.tmp/kh-curl-probe}"
KH_TRACE_JSON="${KH_TRACE_JSON:-1}"

# Tool-specific host defaults.
case "$TOOL" in
  git|clang)
    if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
      KH_EXTRA_CARGO_ARGS=--release
    fi
    ;;
  curl)
    if [[ "$PROBE" == "1" ]]; then
      KH_CURL_PROBE=1
    fi
    KH_CURL_PROBE="${KH_CURL_PROBE:-0}"
    ;;
  *)
    KH_CURL_PROBE="${KH_CURL_PROBE:-0}"
    ;;
esac

# git: bare `clone <url>` → durable /out/<name>
if [[ "$TOOL" == "git" ]] \
  && [[ "${KH_CLONE_IN_SRC:-}" != "1" ]] \
  && [[ ${#GUEST_ARGS[@]} -eq 2 ]] \
  && [[ "${GUEST_ARGS[0]}" == "clone" ]] \
  && [[ "${GUEST_ARGS[1]}" == https://* || "${GUEST_ARGS[1]}" == http://* \
        || "${GUEST_ARGS[1]}" == git@* || "${GUEST_ARGS[1]}" == ssh://* ]]; then
  url="${GUEST_ARGS[1]}"
  base="${url%/}"
  base="${base%.git}"
  base="${base##*/}"
  if [[ -z "$base" || "$base" == "*" ]]; then
    base="repo"
  fi
  GUEST_ARGS=(clone --progress "$url" "/Volumes/linux/out/${base}")
  echo "==> clone dest: guest /Volumes/linux/out/${base}"
  echo "                host  ${KH_OUT}/${base}"
fi

mkdir -p "$KH_OUT" "$ROOT/.kh"
if [[ "${KH_CURL_PROBE:-0}" == "1" ]]; then
  mkdir -p "$KH_PROBE_DIR"
fi

kh_docker_stage_libsystem
kh_docker_ensure_image "$IMAGE"
kh_docker_default_vols "$ROOT" "$KH_OUT"
kh_docker_warn_ephemeral_paths "$KH_OUT" ${GUEST_ARGS[@]+"${GUEST_ARGS[@]}"}

# Optional mounts / envs per tool.
case "$TOOL" in
  curl)
    if [[ "${KH_CURL_PROBE:-0}" == "1" ]]; then
      DOCKER_VOLS+=(-v "${KH_PROBE_DIR}:/probe")
    fi
    if [[ -n "${KAKEHASHI_CURL:-}" && -f "${KAKEHASHI_CURL}" ]]; then
      DOCKER_VOLS+=(-v "${KAKEHASHI_CURL}:/host-curl:ro")
      DOCKER_ENVS=(-e KAKEHASHI_CURL=/host-curl)
      echo "==> using host KAKEHASHI_CURL=$KAKEHASHI_CURL"
    else
      DOCKER_ENVS=()
      echo "==> kh install curl will download Darwin arm64 archive"
    fi
    ;;
  git)
    DOCKER_ENVS=()
    if [[ "${KH_NO_SSH_MOUNT:-}" != "1" ]] && [[ -d "${HOME}/.ssh" ]]; then
      DOCKER_VOLS+=(-v "${HOME}/.ssh:/root/.ssh:ro")
      echo "==> SSH identities: host ${HOME}/.ssh → container /root/.ssh (ro)"
    fi
    ;;
  *)
    DOCKER_ENVS=()
    ;;
esac

# Common forwarded envs.
for e in KAKEHASHI_XCODE_TOOLS_VERSION KAKEHASHI_FORCE_DOWNLOAD \
  KAKEHASHI_BOUNDARY_STATS KAKEHASHI_FUTEX_STATS KAKEHASHI_HEAP_STATS \
  KAKEHASHI_LOAD_TIMING GIT_SSH_COMMAND; do
  if [[ -n "${!e:-}" ]]; then
    DOCKER_ENVS+=(-e "${e}=${!e}")
  fi
done

echo "==> guest ${TOOL} via kh  (bottle+cache: $ROOT/.kh/data)"
echo "==> durable /out:       $KH_OUT  ↔  guest /Volumes/linux/out"
echo "==> args: ${GUEST_ARGS[*]:-<none>}"
if [[ "${KH_CURL_PROBE:-0}" == "1" ]]; then
  echo "==> probe mode: logs → $KH_PROBE_DIR"
fi

set +e
docker run --rm \
  "${DOCKER_VOLS[@]}" \
  "${DOCKER_ENVS[@]+"${DOCKER_ENVS[@]}"}" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS:-}" \
  -e "KH_CURL_PROBE=${KH_CURL_PROBE:-0}" \
  -e "KH_TRACE_JSON=${KH_TRACE_JSON}" \
  -e "KH_TOOL=${TOOL}" \
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

case "${KH_TOOL}" in
  7zz)
    "$KH" bottle status
    if [[ -x tests/clang-probe/7zz.bin ]]; then
      export KAKEHASHI_7ZZ=/src/tests/clang-probe/7zz.bin
    fi
    "$KH" install 7zip || true
    exec "$KH" run 7zz -- "$@"
    ;;
  curl)
    # c-ares (static curl) reads guest /etc/resolv.conf → bottle private/etc.
    if [[ -f /etc/resolv.conf ]]; then
      mkdir -p "${KAKEHASHI_DATA_DIR}/bottle/private/etc"
      cp /etc/resolv.conf "${KAKEHASHI_DATA_DIR}/bottle/private/etc/resolv.conf" || true
    fi
    "$KH" bottle status
    "$KH" install curl
    BOTTLE="${KAKEHASHI_DATA_DIR}/bottle"
    HOST_CURL="${BOTTLE}/usr/local/bin/curl"
    echo "==> installed guest /usr/local/bin/curl"
    echo "    host file: ${HOST_CURL}"
    ls -la "${HOST_CURL}" || true

    if [[ "${KH_CURL_PROBE:-0}" != "1" ]]; then
      exec "$KH" run curl -- "$@"
    fi

    summarize_unknown() {
      local stderr_file="$1" out_file="$2"
      if [[ -f "$stderr_file" ]]; then
        grep -E "unknown BSD syscall #" "$stderr_file" \
          | sed -E "s/.*unknown BSD syscall #([0-9]+).*/\1/" \
          | sort -n | uniq -c | sort -k2 -n \
          > "$out_file" || true
      else
        : > "$out_file"
      fi
      if [[ -s "$out_file" ]]; then
        echo "==> unique unknown BSD syscall numbers (count  number):"
        cat "$out_file"
      else
        echo "==> no \"unknown BSD syscall\" lines in stderr"
      fi
    }
    run_one() {
      local label="$1"; shift
      local stderr_f="/probe/${label}.stderr"
      local stdout_f="/probe/${label}.stdout"
      local exit_f="/probe/${label}.exit"
      local unknown_f="/probe/${label}.unknown-syscalls.txt"
      set +e
      "$@" >"$stdout_f" 2>"$stderr_f"
      local rc=$?
      set -e
      echo "$rc" >"$exit_f"
      echo "==> $label exit=$rc  stdout=$stdout_f  stderr=$stderr_f"
      [[ -s "$stdout_f" ]] && { echo "---- stdout (head) ----"; head -n 40 "$stdout_f" || true; }
      [[ -s "$stderr_f" ]] && { echo "---- stderr (head) ----"; head -n 60 "$stderr_f" || true; }
      summarize_unknown "$stderr_f" "$unknown_f"
      return "$rc"
    }
    run_rc=0
    run_one run "$KH" run curl -- "$@" || run_rc=$?
    if [[ "${KH_TRACE_JSON:-1}" == "1" ]]; then
      run_one trace "$KH" trace --json curl -- "$@" || true
    else
      run_one trace "$KH" trace curl -- "$@" || true
    fi
    echo
    echo "==> probe artifacts under /probe"
    ls -lah /probe | sed "s/^/    /"
    exit "$run_rc"
    ;;
  git)
    if ! command -v ssh >/dev/null 2>&1; then
      echo "error: host OpenSSH client missing (apt install openssh-client;" >&2
      echo "       rebuild image: docker build -t kakehashi:dev -f Dockerfile.dev .)" >&2
      exit 1
    fi
    "$KH" install xcode-tools
    "$KH" run git -- config --global user.email "kh@test.io"
    "$KH" run git -- config --global user.name "Vladislav"
    "$KH" run git -- config --global protocol.version 2
    "$KH" run git -- config --global http.postBuffer 524288000
    exec "$KH" run git -- "$@"
    ;;
  clang)
    "$KH" install xcode-tools
    exec "$KH" run clang -- "$@"
    ;;
  run)
    if [[ $# -lt 1 ]]; then
      echo "error: docker-kh run requires a guest binary path" >&2
      exit 2
    fi
    exec "$KH" run "$@"
    ;;
  *)
    echo "error: internal unknown KH_TOOL=${KH_TOOL}" >&2
    exit 2
    ;;
esac
' -- ${GUEST_ARGS[@]+"${GUEST_ARGS[@]}"}
rc=$?
set -e

kh_docker_list_out "$KH_OUT"

if [[ "${KH_CURL_PROBE:-0}" == "1" ]]; then
  echo
  echo "==> host probe dir: $KH_PROBE_DIR"
  ls -lah "$KH_PROBE_DIR" | sed 's/^/    /' || true
  if compgen -G "$KH_PROBE_DIR/*.unknown-syscalls.txt" > /dev/null 2>&1; then
    echo
    echo "==> unknown-syscalls summaries:"
    for f in "$KH_PROBE_DIR"/*.unknown-syscalls.txt; do
      echo "--- $(basename "$f") ---"
      cat "$f" || true
    done
  fi
fi

exit "$rc"
