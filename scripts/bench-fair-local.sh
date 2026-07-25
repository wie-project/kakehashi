#!/usr/bin/env bash
# Fair CPU bench: one large blob on container-local /tmp (not Virtio-FS),
# Linux native 7zz vs kh + Darwin 7zz.
#
# Why /tmp and not a host bind-mount for the work dir?
#   Thousands of small files through Colima virtiofs measure the disk bridge,
#   not the translator. One blob on the VM-local filesystem isolates LZMA/CPU
#   and a handful of syscalls. Archives are *copied out* to the host at the end.
#
# Prerequisites (macOS arm64 + Colima, from repo root):
#   ./scripts/stage-libsystem.sh
#   docker build -t kakehashi:dev -f Dockerfile.dev .
#
# Usage:
#   ./scripts/bench-fair-local.sh              # 200 MiB, mx=5, mmt=2
#   SIZE_MB=64 MMT=1 ./scripts/bench-fair-local.sh
#   KAKEHASHI_HYPERCALL=0 ./scripts/bench-fair-local.sh
#
# Env:
#   SIZE_MB, MX, MMT          workload (defaults: 200, 5, 2)
#   KAKEHASHI_SMOKE_IMAGE     docker image (default: kakehashi:dev)
#   KAKEHASHI_HYPERCALL       1=hypercall path, 0=svc→brk path
#   KH_BENCH_OUT              host results dir (default: <repo>/.tmp/kh-bench-fair)
#   KEEP_BLOB=1               also copy the random blob to results (large)
#
# After a successful run, open:
#   .tmp/kh-bench-fair/README.txt     — what each file is
#   .tmp/kh-bench-fair/summary.txt    — timings + verify status
#   .tmp/kh-bench-fair/artifacts/     — native.7z, kh.7z, checksums
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${KH_BENCH_OUT:-$ROOT/.tmp/kh-bench-fair}"
IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
SIZE_MB="${SIZE_MB:-200}"
MX="${MX:-5}"
MMT="${MMT:-2}"
KEEP_BLOB="${KEEP_BLOB:-0}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$OUT/bin" "$OUT/artifacts"

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

# Host-visible guide (rewritten each run so paths stay accurate).
cat >"$OUT/README.txt" <<EOF
Kakehashi fair local bench — results layout
===========================================

Host directory (this folder):
  $OUT

What is here
------------
  README.txt          this file
  summary.txt         timings, ratio, archive verify status
  native.log          stdout from Linux 7zz compress
  kh.log              stdout from kh + Darwin 7zz compress
  artifacts/
    native.7z         archive produced by Linux 7zz (host-side binary)
    kh.7z             archive produced by Darwin 7zz under kh
    native.7z.sha256  checksum of native.7z
    kh.7z.sha256      checksum of kh.7z
    blob.sha256       checksum of the random input blob (not the blob itself)
    sizes.txt         byte sizes of blob + both archives
    verify-native.txt full \`7zz t\` output for native.7z
    verify-kh.txt     full \`7zz t\` output for kh.7z
    run-meta.txt      knobs used for this run (size, mx, mmt, hypercall, …)

How to re-check yourself
------------------------
  # Integrity of the archives (macOS / Linux):
  (cd artifacts && shasum -a 256 -c native.7z.sha256 kh.7z.sha256)

  # Test with any 7zz (macOS: brew install sevenzip):
  7zz t artifacts/native.7z
  7zz t artifacts/kh.7z

  # Or the Linux binary the bench cached (Linux aarch64 host only):
  ./bin/7zz t artifacts/native.7z
  ./bin/7zz t artifacts/kh.7z

  # Compare sizes:
  cat artifacts/sizes.txt
  ls -lh artifacts/*.7z

Notes
-----
  - Guest Darwin 7zz and host Linux 7zz are *different builds*.
    Compare hypercall vs KAKEHASHI_HYPERCALL=0 for path overhead, not absolute
    "native × N" across product versions.
  - Work files during the run live in the container at /tmp/khbench-fair and
    are deleted with the container. Only what lands under artifacts/ is kept.
  - Default OUT is gitignored (.tmp/). Override with KH_BENCH_OUT=/path.
EOF

echo "=== fair local bench ==="
echo "  size=${SIZE_MB} MiB  mx=$MX  mmt=$MMT  hypercall=${KAKEHASHI_HYPERCALL:-1}"
echo "  results → $OUT"
echo "  run_id  → $RUN_ID"
echo

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
  -e KEEP_BLOB="$KEEP_BLOB" -e RUN_ID="$RUN_ID" \
  -w /src \
  "$IMAGE" \
  bash -c '
set -euo pipefail

W=/tmp/khbench-fair
ART=/results/artifacts
rm -rf "$W"
mkdir -p "$W" "$ART"
# Fresh logs each run
: > /results/summary.txt
: > /results/native.log
: > /results/kh.log

KH=./target/release/kh
echo "==> cargo build -p kh-cli --release"
cargo build -p kh-cli --release 2>&1 | tail -5
$KH bottle ensure >/dev/null

{
  echo "run_id=$RUN_ID"
  echo "nproc=$(nproc)"
  echo "size_mb=$SIZE_MB"
  echo "mx=$MX"
  echo "mmt=$MMT"
  echo "hypercall=${KAKEHASHI_HYPERCALL:-1}"
  echo "guest_7zz=tests/clang-probe/7zz.bin"
  echo "host_7zz=/bin7/7zz"
  /bin7/7zz 2>&1 | head -1 || true
  date -u +%Y-%m-%dT%H:%M:%SZ
} | tee "$ART/run-meta.txt" | tee /results/summary.txt

echo "" | tee -a /results/summary.txt
echo "==> create random blob (${SIZE_MB} MiB) on container-local $W" | tee -a /results/summary.txt
dd if=/dev/urandom of="$W/blob.bin" bs=1M count="$SIZE_MB" status=none
ls -lh "$W/blob.bin" | tee -a /results/summary.txt
sha256sum "$W/blob.bin" | tee "$ART/blob.sha256" | tee -a /results/summary.txt

echo "" | tee -a /results/summary.txt
echo "=== A: native Linux 7zz (local /tmp) ===" | tee -a /results/summary.txt
rm -f "$W/native.7z"
START=$(date +%s%N)
/bin7/7zz a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" "$W/native.7z" "$W/blob.bin" \
  | tee /results/native.log
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
print(f"native_s={n/1000:.2f}  kh_s={k/1000:.2f}")
print("note: guest 7zz (Darwin) and host 7zz (Linux) are different builds;")
print("      compare hyper vs brk (KAKEHASHI_HYPERCALL=0) for pure path cost.")
PY

# ---- persist artifacts on the bind-mounted /results (host OUT) ----
echo "" | tee -a /results/summary.txt
echo "==> copy archives to /results/artifacts (host-visible)" | tee -a /results/summary.txt
cp -f "$W/native.7z" "$ART/native.7z"
cp -f "$W/kh.7z"     "$ART/kh.7z"
if [[ "${KEEP_BLOB}" == "1" ]]; then
  cp -f "$W/blob.bin" "$ART/blob.bin"
  echo "kept blob.bin (KEEP_BLOB=1)" | tee -a /results/summary.txt
fi

# Checksums relative to artifacts/ so `shasum -c` works from that directory
( cd "$ART" && sha256sum native.7z > native.7z.sha256 )
( cd "$ART" && sha256sum kh.7z     > kh.7z.sha256 )

{
  echo "blob_bytes=$(stat -c%s "$W/blob.bin")"
  echo "native_7z_bytes=$(stat -c%s "$ART/native.7z")"
  echo "kh_7z_bytes=$(stat -c%s "$ART/kh.7z")"
  ls -lh "$W/blob.bin" "$ART/native.7z" "$ART/kh.7z"
} | tee "$ART/sizes.txt" | tee -a /results/summary.txt

echo "" | tee -a /results/summary.txt
echo "==> verify archives with host 7zz (t = test integrity)" | tee -a /results/summary.txt
/bin7/7zz t "$ART/native.7z" | tee "$ART/verify-native.txt"
/bin7/7zz t "$ART/kh.7z"     | tee "$ART/verify-kh.txt"
grep -q "Everything is Ok" "$ART/verify-native.txt" \
  && echo "native_archive=ok" | tee -a /results/summary.txt \
  || { echo "native_archive=FAIL" | tee -a /results/summary.txt; exit 1; }
grep -q "Everything is Ok" "$ART/verify-kh.txt" \
  && echo "kh_archive=ok" | tee -a /results/summary.txt \
  || { echo "kh_archive=FAIL" | tee -a /results/summary.txt; exit 1; }

echo "" | tee -a /results/summary.txt
echo "artifacts_ready=1" | tee -a /results/summary.txt
'

echo
echo "================================================================"
echo " Bench finished — results on the HOST (not inside Docker)"
echo "================================================================"
echo "  Directory : $OUT"
echo "  Summary   : $OUT/summary.txt"
echo "  Guide     : $OUT/README.txt"
echo "  Archives  : $OUT/artifacts/native.7z"
echo "              $OUT/artifacts/kh.7z"
echo
echo "  Quick verify (no Docker):"
echo "    cat $OUT/summary.txt"
echo "    ls -lh $OUT/artifacts/*.7z"
echo "    (cd $OUT/artifacts && shasum -a 256 -c native.7z.sha256 kh.7z.sha256)"
if [[ -x "$OUT/bin/7zz" ]]; then
  echo "    $OUT/bin/7zz t $OUT/artifacts/native.7z"
  echo "    $OUT/bin/7zz t $OUT/artifacts/kh.7z"
fi
echo "================================================================"
echo
cat "$OUT/summary.txt"
