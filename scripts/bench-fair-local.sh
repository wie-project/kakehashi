#!/usr/bin/env bash
# Fair CPU bench: one large blob in the container's local /tmp (no Virtio-FS),
# Linux native 7zz vs kh + Darwin 7zz.
#
# Why /tmp and not a host bind-mount?
#   Thousands of small files through Colima virtiofs measure the disk bridge,
#   not the translator. One blob on the VM-local filesystem isolates LZMA/CPU
#   and a handful of syscalls.
#
# Prerequisites (macOS arm64 + Colima, from repo root):
#   ./scripts/stage-libsystem.sh
#   docker build -t kakehashi:dev -f Dockerfile.dev .
#   # Linux aarch64 7zz next to the script cache (downloaded once):
#   #   https://www.7-zip.org/  →  7z*-linux-arm64.tar.xz
#
# Usage:
#   ./scripts/bench-fair-local.sh              # 200 MiB, mx=5, mmt=2
#   SIZE_MB=64 MMT=1 ./scripts/bench-fair-local.sh
#
# Env:
#   SIZE_MB, MX, MMT, KAKEHASHI_SMOKE_IMAGE, KAKEHASHI_HYPERCALL
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${KH_BENCH_OUT:-$ROOT/.tmp/kh-bench-fair}"
IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
SIZE_MB="${SIZE_MB:-200}"
MX="${MX:-5}"
MMT="${MMT:-2}"
mkdir -p "$OUT/bin"

if [[ ! -f dist/guest/libSystem.B.dylib ]]; then
  ./scripts/stage-libsystem.sh
fi

if [[ ! -x "$OUT/bin/7zz" ]]; then
  echo "==> fetch Linux aarch64 7zz into $OUT/bin"
  tmp="$(mktemp)"
  curl -fsSL -o "$tmp" "https://www.7-zip.org/a/7z2501-linux-arm64.tar.xz" \
    || curl -fsSL -o "$tmp" "https://www.7-zip.org/a/7z2409-linux-arm64.tar.xz"
  tar -xJf "$tmp" -C "$OUT/bin" 7zz 2>/dev/null || tar -xJf "$tmp" -C "$OUT/bin"
  chmod +x "$OUT/bin/7zz"
  rm -f "$tmp"
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" -f Dockerfile.dev .
fi

echo "=== fair local bench size=${SIZE_MB}MiB mx=$MX mmt=$MMT ==="
docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -v "${OUT}:/results" \
  -v "${OUT}/bin:/bin7:ro" \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KAKEHASHI_HYPERCALL=${KAKEHASHI_HYPERCALL:-1}" \
  -e SIZE_MB="$SIZE_MB" -e MX="$MX" -e MMT="$MMT" \
  -w /src \
  "$IMAGE" \
  bash -c '
set -euo pipefail
W=/tmp/khbench-fair
mkdir -p "$W"
KH=./target/release/kh
cargo build -p kh-cli --release 2>&1 | tail -3
$KH bottle ensure >/dev/null

echo "nproc=$(nproc)" | tee /results/summary.txt
/bin7/7zz 2>&1 | head -1 | tee -a /results/summary.txt
dd if=/dev/urandom of="$W/blob.bin" bs=1M count="$SIZE_MB" status=none
ls -lh "$W/blob.bin" | tee -a /results/summary.txt

echo "" | tee -a /results/summary.txt
echo "=== A: native Linux 7zz (local /tmp) ===" | tee -a /results/summary.txt
rm -f "$W/native.7z"
START=$(date +%s%N)
/bin7/7zz a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" "$W/native.7z" "$W/blob.bin" | tee /results/native.log
END=$(date +%s%N)
NATIVE_MS=$(( (END-START)/1000000 ))
echo "native_ms=$NATIVE_MS" | tee -a /results/summary.txt

echo "" | tee -a /results/summary.txt
echo "=== B: kh + Darwin 7zz (HYPERCALL=${KAKEHASHI_HYPERCALL:-1}) ===" | tee -a /results/summary.txt
rm -f "$W/kh.7z"
START=$(date +%s%N)
$KH run --max-syscalls 500000000 tests/clang-probe/7zz.bin -- \
  a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" \
  /Volumes/linux/tmp/khbench-fair/kh.7z /Volumes/linux/tmp/khbench-fair/blob.bin \
  | tee /results/kh.log
END=$(date +%s%N)
KH_MS=$(( (END-START)/1000000 ))
echo "kh_ms=$KH_MS" | tee -a /results/summary.txt

python3 - <<PY | tee -a /results/summary.txt
n=$NATIVE_MS; k=$KH_MS
print(f"ratio_kh_over_native={k/n:.2f}x" if n else "ratio=n/a")
print(f"native_s={n/1000:.2f} kh_s={k/1000:.2f}")
print("note: guest 7zz (Darwin) and host 7zz (Linux) are different builds;")
print("      compare hyper vs brk (KAKEHASHI_HYPERCALL=0) for pure path cost.")
PY
/bin7/7zz t "$W/native.7z" >/dev/null && echo native_archive=ok | tee -a /results/summary.txt
/bin7/7zz t "$W/kh.7z" >/dev/null && echo kh_archive=ok | tee -a /results/summary.txt
'

echo "wrote $OUT/summary.txt"
cat "$OUT/summary.txt"
