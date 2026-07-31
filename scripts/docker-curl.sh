#!/usr/bin/env bash
# Run Darwin curl under kh inside Linux aarch64 Docker/Colima.
#
# Same shape as scripts/docker-7zz.sh:
#   cargo build → bottle ensure → kh install curl → kh run curl -- …
#
# `kh install curl` downloads a public Darwin arm64 archive (no macOS extract,
# no cross-compile). Override with KAKEHASHI_CURL=/path/to/darwin-curl.
#
# Path map (this is the bit people miss)
# --------------------------------------
#   Host path                         Guest path under kh
#   ----------------------------      ----------------------------------
#   <repo>/…                          /Volumes/linux/src/…
#   container /tmp/…                  /Volumes/linux/tmp/…
#   anything under KH_OUT (below)     /Volumes/linux/out/…
#
# Guest binary after install: /usr/local/bin/curl
# Host (Docker bottle):       <repo>/.kh/data/bottle/usr/local/bin/curl
#
# Usage (like docker-7zz):
#   ./scripts/docker-curl.sh --version
#   ./scripts/docker-curl.sh -sS -o /Volumes/linux/out/body http://example.com/
#
# Trace-first expansion (capture stderr + unknown BSD #):
#   KH_CURL_PROBE=1 ./scripts/docker-curl.sh --version
#   # or: ./scripts/docker-curl-probe.sh --version
#
# Env:
#   KAKEHASHI_CURL         optional host path to skip download
#   KAKEHASHI_SMOKE_IMAGE  docker image (default: kakehashi:dev)
#   KH_EXTRA_CARGO_ARGS    e.g. --release
#   KH_DOCKER_MOUNTS       extra docker -v mounts, space-separated
#   KH_OUT                 durable guest /out (default: <repo>/.tmp/kh-out)
#   KH_CURL_PROBE          1 = also run kh trace + save probe artifacts
#   KH_PROBE_DIR           probe logs (default: <repo>/.tmp/kh-curl-probe)
#   KH_TRACE_JSON          1 = kh trace --json when probing (default: 1)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
KH_PROBE_DIR="${KH_PROBE_DIR:-$ROOT/.tmp/kh-curl-probe}"
KH_CURL_PROBE="${KH_CURL_PROBE:-0}"
KH_TRACE_JSON="${KH_TRACE_JSON:-1}"
GUEST_ARGS=("$@")

mkdir -p "$KH_OUT"
if [[ "$KH_CURL_PROBE" == "1" ]]; then
  mkdir -p "$KH_PROBE_DIR"
fi

# Prefer a freshly staged dylib when the developer just rebuilt kh-libsystem;
# otherwise bottle ensure falls back to the crate-embedded resources/ dylib.
if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
  || [[ -f target/release/libkh_libsystem.dylib ]]; then
  ./scripts/stage-libsystem.sh
elif [[ -f crates/kh-runtime/resources/libSystem.B.dylib ]]; then
  echo "note: using crates/kh-runtime/resources/libSystem.B.dylib"
else
  echo "error: no guest libSystem (need resources/ embed or a built dylib)." >&2
  echo "  cargo build -p kh-libsystem --release --target aarch64-apple-darwin" >&2
  echo "  ./scripts/stage-libsystem.sh" >&2
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

if [[ "$KH_CURL_PROBE" == "1" ]]; then
  DOCKER_VOLS+=(-v "${KH_PROBE_DIR}:/probe")
fi

DOCKER_ENVS=()
if [[ -n "${KAKEHASHI_CURL:-}" && -f "${KAKEHASHI_CURL}" ]]; then
  DOCKER_VOLS+=(-v "${KAKEHASHI_CURL}:/host-curl:ro")
  DOCKER_ENVS+=(-e KAKEHASHI_CURL=/host-curl)
  echo "==> using host KAKEHASHI_CURL=$KAKEHASHI_CURL"
else
  echo "==> kh install curl will download Darwin arm64 archive (see DARWIN_CURL_URL)"
fi

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

echo "==> guest curl via kh  (durable out: $KH_OUT  ↔  /Volumes/linux/out)"
echo "==> guest path: /usr/local/bin/curl"
echo "==> args: ${GUEST_ARGS[*]:-<none>}"
if [[ "$KH_CURL_PROBE" == "1" ]]; then
  echo "==> probe mode: logs → $KH_PROBE_DIR"
fi

# Project-local registry + bottle (persists on the bind mount, not host /tmp).
set +e
docker run --rm \
  "${DOCKER_VOLS[@]}" \
  "${DOCKER_ENVS[@]+"${DOCKER_ENVS[@]}"}" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KAKEHASHI_HYPERCALL=${KAKEHASHI_HYPERCALL:-}" \
  -e "KH_CURL_PROBE=${KH_CURL_PROBE}" \
  -e "KH_TRACE_JSON=${KH_TRACE_JSON}" \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS:-}" \
  "${IMAGE}" \
  bash -c '
set -euo pipefail

# Always rebuild the binary we execute (a stale release in the volume cache
# must not win over a freshly compiled debug kh).
cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi

"$KH" bottle ensure
# c-ares (static curl) reads guest /etc/resolv.conf → bottle private/etc.
if [[ -f /etc/resolv.conf ]]; then
  mkdir -p "${KAKEHASHI_DATA_DIR}/bottle/private/etc"
  cp /etc/resolv.conf "${KAKEHASHI_DATA_DIR}/bottle/private/etc/resolv.conf" || true
fi
# OpenSSL CAfile default + SecTrust host helper (also seeded by bottle ensure).
if [[ ! -s "${KAKEHASHI_DATA_DIR}/bottle/private/etc/ssl/cert.pem" ]]; then
  mkdir -p "${KAKEHASHI_DATA_DIR}/bottle/private/etc/ssl/certs"
  if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    cp /etc/ssl/certs/ca-certificates.crt "${KAKEHASHI_DATA_DIR}/bottle/private/etc/ssl/cert.pem" || true
  elif [[ -f /etc/ssl/cert.pem ]]; then
    cp /etc/ssl/cert.pem "${KAKEHASHI_DATA_DIR}/bottle/private/etc/ssl/cert.pem" || true
  elif [[ -f /src/crates/kh-runtime/resources/ssl/cert.pem ]]; then
    cp /src/crates/kh-runtime/resources/ssl/cert.pem "${KAKEHASHI_DATA_DIR}/bottle/private/etc/ssl/cert.pem" || true
  fi
fi
"$KH" bottle status
"$KH" install curl

BOTTLE="${KAKEHASHI_DATA_DIR}/bottle"
HOST_CURL="${BOTTLE}/usr/local/bin/curl"
echo "==> installed guest /usr/local/bin/curl"
echo "    host file: ${HOST_CURL}"
ls -la "${HOST_CURL}" || true
file "${HOST_CURL}" 2>/dev/null || true

if [[ "${KH_CURL_PROBE:-0}" != "1" ]]; then
  # Same as docker-7zz: exec so container exit code is the guest exit code.
  exec "$KH" run curl -- "$@"
fi

# Probe mode: capture run + optional trace for G1/G2 (unknown BSD #).
summarize_unknown() {
  local stderr_file="$1"
  local out_file="$2"
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
    echo "==> no \"unknown BSD syscall\" lines in stderr (good, or failed earlier)"
  fi
}

run_one() {
  local label="$1"
  shift
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
  if [[ -s "$stdout_f" ]]; then
    echo "---- stdout (head) ----"
    head -n 40 "$stdout_f" || true
  fi
  if [[ -s "$stderr_f" ]]; then
    echo "---- stderr (head) ----"
    head -n 60 "$stderr_f" || true
  fi
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
' -- ${GUEST_ARGS[@]+"${GUEST_ARGS[@]}"}
rc=$?
set -e

# After success, if anything was written under KH_OUT, list it.
if compgen -G "$KH_OUT/*" > /dev/null 2>&1; then
  echo
  echo "==> host files under $KH_OUT:"
  ls -lah "$KH_OUT" | sed 's/^/    /'
fi

if [[ "$KH_CURL_PROBE" == "1" ]]; then
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
