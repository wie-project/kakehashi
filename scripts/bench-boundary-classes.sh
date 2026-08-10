#!/usr/bin/env bash
# Roadmap2 P1: rank host **dispatch** cost by crossing class inside Linux aarch64
# Docker (Colima). Optionally dump M0 boundary stats from a real guest exit.
#
# Why Docker?
#   Live `kh run` / hypercall is Linux aarch64 only. Host-side `cargo test` on
#   macOS still works for a quick ranking, but production numbers and M0 guest
#   dumps must come from the same image path as docker-kh 7zz / docker-smoke.
#
# What is measured
# ----------------
#   Phase A — `syscall::dispatch` only (getpid, open+close, readdir, park
#             uncontended). Excludes hypercall NEON/TLS/alt-stack.
#   Phase B — short real guest under kh with KAKEHASHI_BOUNDARY_STATS (M0 dump
#             at exit on **stderr**). Proves counters on the production path.
#
# Usage:
#   ./scripts/bench-boundary-classes.sh
#   KAKEHASHI_BOUNDARY_BENCH_ITERS=250000 ./scripts/bench-boundary-classes.sh
#   LOCAL=1 ./scripts/bench-boundary-classes.sh          # no Docker (this host)
#   GUEST_STATS=0 ./scripts/bench-boundary-classes.sh    # skip phase B
#   RELEASE=1 ./scripts/bench-boundary-classes.sh        # --release microbench
#
# Env:
#   KAKEHASHI_SMOKE_IMAGE           default: kakehashi:dev
#   KAKEHASHI_BOUNDARY_BENCH_ITERS  default: 100000 (phase A)
#   KAKEHASHI_BOUNDARY_STATS        default for phase B: 1  (set ns for timing)
#   LOCAL=1                         run on this machine (no docker wrapper)
#   RELEASE=1                       cargo test --release for phase A
#   GUEST_STATS=0                   skip real-guest M0 dump
#   KH_EXTRA_CARGO_ARGS             extra flags for cargo build (phase B)
#
# Internal (set by docker entry, do not use by hand):
#   KH_BENCH_INNER=1                already inside the container
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
ITERS="${KAKEHASHI_BOUNDARY_BENCH_ITERS:-100000}"
LOCAL="${LOCAL:-0}"
INNER="${KH_BENCH_INNER:-0}"
RELEASE="${RELEASE:-0}"
GUEST_STATS="${GUEST_STATS:-1}"
# Phase B default: counts only; override with ns/time if desired.
export KAKEHASHI_BOUNDARY_STATS="${KAKEHASHI_BOUNDARY_STATS:-1}"

run_phase_a() {
  echo "=== Phase A: boundary class microbench (host dispatch)  iters=$ITERS ==="
  echo "note: excludes hypercall NEON/TLS/alt-stack"
  echo
  export KAKEHASHI_BOUNDARY_BENCH_ITERS="$ITERS"
  local release_args=()
  if [[ "$RELEASE" == "1" ]]; then
    release_args=(--release)
  fi
  if ! cargo test -p kh-runtime "${release_args[@]}" --lib boundary_class_microbench_large \
      -- --nocapture --ignored; then
    echo "large test failed or filtered; running smoke with same ITERS…"
    cargo test -p kh-runtime "${release_args[@]}" --lib boundary_class_microbench_smoke \
      -- --nocapture
  fi
}

run_phase_b() {
  if [[ "$GUEST_STATS" == "0" ]]; then
    echo "=== Phase B: skipped (GUEST_STATS=0) ==="
    return 0
  fi
  echo
  echo "=== Phase B: real guest + KAKEHASHI_BOUNDARY_STATS=${KAKEHASHI_BOUNDARY_STATS} ==="
  echo "note: M0 dump is on **stderr** at guest process exit"
  echo

  # shellcheck disable=SC2086
  cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
  local KH
  if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]] || [[ "$RELEASE" == "1" ]]; then
    if [[ -x ./target/release/kh ]]; then
      KH=./target/release/kh
    else
      cargo build -p kakehashi --release
      KH=./target/release/kh
    fi
  else
    KH=./target/debug/kh
  fi

  if [[ -d /src ]]; then
    export KAKEHASHI_CONFIG_DIR="${KAKEHASHI_CONFIG_DIR:-/src/.kh/config}"
    export KAKEHASHI_DATA_DIR="${KAKEHASHI_DATA_DIR:-/src/.kh/data}"
  else
    export KAKEHASHI_CONFIG_DIR="${KAKEHASHI_CONFIG_DIR:-$ROOT/.kh/config}"
    export KAKEHASHI_DATA_DIR="${KAKEHASHI_DATA_DIR:-$ROOT/.kh/data}"
  fi
  mkdir -p "$KAKEHASHI_CONFIG_DIR" "$KAKEHASHI_DATA_DIR"

  "$KH" bottle ensure

  # Minimal guest: few crossings (write + exit). Stats dump exercises M0.
  if [[ -x tests/clang-probe/write_exit ]]; then
    echo "--- clang probe: write_exit ---"
    if ! "$KH" run --expect-code 0 tests/clang-probe/write_exit; then
      echo "warn: write_exit run failed (live guest needs Linux aarch64 + bottle)" >&2
    fi
  fi

  # Short guest with more crossings. Prefer bottle 7zz.
  # Do **not** redirect stderr — M0 boundary stats are printed there at exit.
  # Quiet guest stdout only (`7zz i` is a multi-page format dump).
  echo
  echo "--- guest: 7zz (version; stdout→file, stderr=stats on this terminal) ---"
  if ! "$KH" install 7zip; then
    echo "note: 7zip install failed; trying tree clang-probe binary" >&2
  fi
  local out_tmp
  out_tmp="$(mktemp)"
  # Bare `7zz` / `7zz --` prints a short version banner (not the huge `i` list).
  if "$KH" run 7zz -- >"$out_tmp"; then
    echo "7zz ok (stdout $(wc -l <"$out_tmp" | tr -d ' ') lines; first line:)"
    head -n 1 "$out_tmp" || true
  elif [[ -x tests/clang-probe/7zz.bin ]] && \
       "$KH" run tests/clang-probe/7zz.bin -- >"$out_tmp"; then
    echo "7zz (clang-probe path) ok (stdout $(wc -l <"$out_tmp" | tr -d ' ') lines)"
    head -n 1 "$out_tmp" || true
  else
    echo "note: 7zz guest sample skipped (install/run failed)" >&2
  fi
  rm -f "$out_tmp"
}

run_all() {
  run_phase_a
  run_phase_b
}

# ── Inner work (container or LOCAL=1) ────────────────────────────────────────
if [[ "$INNER" == "1" ]] || [[ "$LOCAL" == "1" ]]; then
  if [[ "$INNER" == "1" ]]; then
    echo "==> inside Docker container (Linux aarch64 work path)"
  else
    echo "==> LOCAL=1: running on this host (no Docker wrapper)"
    echo "    Live hypercall/guest may be unavailable off Linux aarch64."
  fi
  run_all
  exit 0
fi

# ── Docker entry (default from macOS / host) ─────────────────────────────────
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
fi

echo "==> docker run ${IMAGE}  (P1 boundary classes + optional M0 guest dump)"
echo "    iters=$ITERS  RELEASE=$RELEASE  GUEST_STATS=$GUEST_STATS  BOUNDARY_STATS=$KAKEHASHI_BOUNDARY_STATS"

docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -w /src \
  -e CARGO_TARGET_DIR=/src/target \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e "KAKEHASHI_BOUNDARY_BENCH_ITERS=${ITERS}" \
  -e "KAKEHASHI_BOUNDARY_STATS=${KAKEHASHI_BOUNDARY_STATS}" \
  -e "RELEASE=${RELEASE}" \
  -e "GUEST_STATS=${GUEST_STATS}" \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS:-}" \
  -e KH_BENCH_INNER=1 \
  "${IMAGE}" \
  bash -c 'set -euo pipefail; ./scripts/bench-boundary-classes.sh'
