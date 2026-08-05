#!/usr/bin/env bash
# Multi-file 7zz plate (roadmap2 plate A / S-smoke) on Linux aarch64 Docker.
#
# Builds a tree of many small files on **container-local /tmp** (not host
# virtiofs), then:
#   A) native Linux 7z/7zz (if available) — wall baseline
#   B) kh + Darwin 7zz with KAKEHASHI_BOUNDARY_STATS — wall + crossing dump
#   C) kh 7zz t — correctness smoke
#
# Guest input mode (MODE):
#   list   (default) — `7zz a … @listfile` with one guest path per line.
#           Still useful for plate-A FS chats without dirent walk cost.
#   dir    — pass the tree directory (recursive opendir/readdir; fixed after
#           freestanding ENOSYS-spin + size-class heap; was EINVAL/0 files).
#
# Why /tmp? Thousands of small files through Colima virtiofs measure the disk
# bridge more than the translator (see bench-fair-local.sh).
#
# Usage:
#   ./scripts/bench-multifile-7zz.sh
#   NFILES=8000 FILE_BYTES=4096 MX=5 MMT=4 ./scripts/bench-multifile-7zz.sh
#   NFILES=2000 MX=0 MMT=1 ./scripts/bench-multifile-7zz.sh   # plate A-ish
#
# Env:
#   NFILES          file count (default: 4000; UTM plateau used ~8000)
#   FILE_BYTES      size per file (default: 1024)
#   DIRS            top-level subdirs to spread files (default: 40)
#   MODE            list (default) | dir
#   MX, MMT         7zz -mx / -mmt (default: 5, 4 — product gate shape)
#   KAKEHASHI_BOUNDARY_STATS  default: 1 (use ns for host-dispatch timing)
#   KAKEHASHI_FUTEX_STATS     default: 0
#   KH_EXTRA_CARGO_ARGS       default: --release
#   KH_BENCH_OUT              host results dir (default: .tmp/kh-bench-multifile)
#   KAKEHASHI_SMOKE_IMAGE     default: kakehashi:dev
#   SKIP_NATIVE=1             only kh path
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
OUT="${KH_BENCH_OUT:-$ROOT/.tmp/kh-bench-multifile}"
NFILES="${NFILES:-4000}"
FILE_BYTES="${FILE_BYTES:-1024}"
DIRS="${DIRS:-40}"
MODE="${MODE:-list}"
MX="${MX:-5}"
MMT="${MMT:-4}"
SKIP_NATIVE="${SKIP_NATIVE:-0}"
export KAKEHASHI_BOUNDARY_STATS="${KAKEHASHI_BOUNDARY_STATS:-1}"
export KAKEHASHI_FUTEX_STATS="${KAKEHASHI_FUTEX_STATS:-0}"
# Multi-file needs a release kh for honest wall; override with empty or debug.
KH_EXTRA_CARGO_ARGS="${KH_EXTRA_CARGO_ARGS---release}"

mkdir -p "$OUT"

if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
  || [[ -f target/release/libkh_libsystem.dylib ]]; then
  ./scripts/stage-libsystem.sh || true
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "==> docker build $IMAGE"
  docker build -t "$IMAGE" -f Dockerfile.dev .
fi

TREE_MB=$(( (NFILES * FILE_BYTES) / 1024 / 1024 ))
echo "=== multi-file 7zz bench ==="
echo "  nfiles=$NFILES  file_bytes=$FILE_BYTES  (~${TREE_MB} MiB payload)  dirs=$DIRS  mode=$MODE"
echo "  mx=$MX  mmt=$MMT"
echo "  BOUNDARY_STATS=$KAKEHASHI_BOUNDARY_STATS  FUTEX_STATS=$KAKEHASHI_FUTEX_STATS"
echo "  cargo: $KH_EXTRA_CARGO_ARGS"
echo "  results → $OUT"
echo

docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -v "${OUT}:/results" \
  -w /src \
  -e CARGO_TARGET_DIR=/src/target \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e "KAKEHASHI_BOUNDARY_STATS=${KAKEHASHI_BOUNDARY_STATS}" \
  -e "KAKEHASHI_FUTEX_STATS=${KAKEHASHI_FUTEX_STATS}" \
  -e "NFILES=${NFILES}" \
  -e "FILE_BYTES=${FILE_BYTES}" \
  -e "DIRS=${DIRS}" \
  -e "MODE=${MODE}" \
  -e "MX=${MX}" \
  -e "MMT=${MMT}" \
  -e "SKIP_NATIVE=${SKIP_NATIVE}" \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS}" \
  "$IMAGE" \
  bash -c '
set -euo pipefail

W=/tmp/khbench-multifile
ART=/results
rm -rf "$W"
mkdir -p "$W/tree" "$ART"
: > "$ART/summary.txt"
: > "$ART/kh-create.log"
: > "$ART/kh-stats.txt"
: > "$ART/native.log"

echo "==> cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS}" | tee -a "$ART/summary.txt"
# shellcheck disable=SC2086
cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS} 2>&1 | tail -8 | tee -a "$ART/summary.txt"
if [[ "${KH_EXTRA_CARGO_ARGS}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi

$KH bottle ensure >/dev/null
if [[ -x tests/clang-probe/7zz.bin ]]; then
  export KAKEHASHI_7ZZ=/src/tests/clang-probe/7zz.bin
fi
$KH install 7zip >/dev/null || true

# Host Linux 7zz: p7zip package or cached binary
NATIVE_7ZZ=""
if command -v 7zz >/dev/null 2>&1; then
  NATIVE_7ZZ=$(command -v 7zz)
elif command -v 7z >/dev/null 2>&1; then
  NATIVE_7ZZ=$(command -v 7z)
elif [[ -x /results/bin/7zz ]]; then
  NATIVE_7ZZ=/results/bin/7zz
fi

{
  echo "nproc=$(nproc)"
  echo "nfiles=$NFILES file_bytes=$FILE_BYTES dirs=$DIRS mode=$MODE"
  echo "mx=$MX mmt=$MMT"
  echo "boundary_stats=${KAKEHASHI_BOUNDARY_STATS:-1}"
  echo "native_7zz=${NATIVE_7ZZ:-none}"
  echo "guest=kh run 7zz"
  date -u +%Y-%m-%dT%H:%M:%SZ
} | tee "$ART/run-meta.txt" | tee -a "$ART/summary.txt"

echo "" | tee -a "$ART/summary.txt"
echo "==> build multi-file tree on $W/tree (+ guest path list)" | tee -a "$ART/summary.txt"
# Spread files across subdirs; write @listfile with Darwin guest paths.
python3 - <<PY
import pathlib
root = pathlib.Path("$W/tree")
n, sz, nd = int("$NFILES"), int("$FILE_BYTES"), int("$DIRS")
payload = (b"kh" * ((sz // 2) + 1))[:sz]
paths = []
for i in range(n):
    d = root / f"d{i % nd:04d}"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"f{i:06d}.bin"
    p.write_bytes(payload)
    # Host /tmp/... ↔ guest /private/tmp/...
    guest = "/private/tmp/khbench-multifile/tree/" + str(p.relative_to(root))
    paths.append(guest)
list_path = pathlib.Path("$W/files.list")
list_path.write_text("\n".join(paths) + "\n", encoding="utf-8")
print(f"wrote {n} files under {root} ({sz} bytes each)")
print(f"listfile={list_path} lines={len(paths)}")
PY
du -sh "$W/tree" | tee -a "$ART/summary.txt"
find "$W/tree" -type f | wc -l | tee -a "$ART/summary.txt"
wc -l "$W/files.list" | tee -a "$ART/summary.txt"

# Guest paths: /private/tmp/... bridges to host /tmp (see bottle/path.rs).
G_TREE=/private/tmp/khbench-multifile/tree
G_LIST=/private/tmp/khbench-multifile/files.list
G_OUT=/private/tmp/khbench-multifile/out.7z

NATIVE_MS=""
if [[ "$SKIP_NATIVE" != "1" && -n "$NATIVE_7ZZ" ]]; then
  echo "" | tee -a "$ART/summary.txt"
  echo "=== native Linux 7zz (create) ===" | tee -a "$ART/summary.txt"
  rm -f "$W/out.7z"
  START=$(date +%s%N)
  if [[ "$MODE" == "list" ]]; then
    # Host list with host paths (not guest /private/tmp).
    find "$W/tree" -type f | sort > "$W/native.list"
    "$NATIVE_7ZZ" a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" "$W/out.7z" @"$W/native.list" \
      >"$ART/native.log" 2>&1 || true
  else
    "$NATIVE_7ZZ" a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" "$W/out.7z" "$W/tree" \
      >"$ART/native.log" 2>&1 || true
  fi
  END=$(date +%s%N)
  NATIVE_MS=$(( (END - START) / 1000000 ))
  echo "native_ms=$NATIVE_MS" | tee -a "$ART/summary.txt"
  echo "native_s=$(python3 -c "print(f\"{$NATIVE_MS/1000:.2f}\")")" | tee -a "$ART/summary.txt"
  if [[ -f "$W/out.7z" ]]; then
    ls -lh "$W/out.7z" | tee -a "$ART/summary.txt"
    cp -f "$W/out.7z" "$ART/native.7z"
  else
    echo "native create failed; see native.log" | tee -a "$ART/summary.txt"
    NATIVE_MS=""
  fi
else
  echo "skip native (SKIP_NATIVE=$SKIP_NATIVE native_7zz=${NATIVE_7ZZ:-unset})" | tee -a "$ART/summary.txt"
fi

rm -f "$W/out.7z"

echo "" | tee -a "$ART/summary.txt"
echo "=== kh + Darwin 7zz (create, mode=$MODE) ===" | tee -a "$ART/summary.txt"
START=$(date +%s%N)
# Split fds: guest/7zz stdout → log; stderr (boundary stats) → raw file
set +e
if [[ "$MODE" == "list" ]]; then
  $KH run --max-syscalls 500000000 7zz -- \
    a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" \
    "$G_OUT" @"$G_LIST" \
    >"$ART/kh-create.log" 2>"$ART/kh-stats.raw"
else
  $KH run --max-syscalls 500000000 7zz -- \
    a -t7z -m0=lzma2 -mx="$MX" -mmt="$MMT" \
    "$G_OUT" "$G_TREE" \
    >"$ART/kh-create.log" 2>"$ART/kh-stats.raw"
fi
KH_RC=$?
set -e
END=$(date +%s%N)
KH_MS=$(( (END - START) / 1000000 ))
echo "kh_create_ms=$KH_MS kh_rc=$KH_RC" | tee -a "$ART/summary.txt"
echo "kh_create_s=$(python3 -c "print(f\"{$KH_MS/1000:.2f}\")")" | tee -a "$ART/summary.txt"
# Fail fast if archive is empty / create clearly failed.
if grep -q "Files read from disk: 0" "$ART/kh-create.log" 2>/dev/null; then
  echo "error: guest read 0 files (tree empty, bad path, or readdir regression; try MODE=list)" | tee -a "$ART/summary.txt"
  tail -30 "$ART/kh-create.log" | tee -a "$ART/summary.txt"
  exit 1
fi

# Extract boundary / futex dumps from stderr for a clean summary
if [[ -f "$ART/kh-stats.raw" ]]; then
  grep -E "^(kh boundary stats|kh futex stats|kh heap stats|	)" "$ART/kh-stats.raw" \
    >"$ART/kh-stats.txt" || true
  # Also keep non-stats stderr noise
  grep -vE "^(kh boundary stats|kh futex stats|kh heap stats|	)" "$ART/kh-stats.raw" \
    >"$ART/kh-stderr-other.txt" || true
  echo "" | tee -a "$ART/summary.txt"
  echo "--- boundary stats (from create) ---" | tee -a "$ART/summary.txt"
  if [[ -s "$ART/kh-stats.txt" ]]; then
    cat "$ART/kh-stats.txt" | tee -a "$ART/summary.txt"
  else
    echo "(no stats lines; is KAKEHASHI_BOUNDARY_STATS set? raw stderr:)" | tee -a "$ART/summary.txt"
    head -40 "$ART/kh-stats.raw" | tee -a "$ART/summary.txt" || true
  fi
fi

if [[ -f "$W/out.7z" ]]; then
  ls -lh "$W/out.7z" | tee -a "$ART/summary.txt"
  cp -f "$W/out.7z" "$ART/kh.7z"
else
  echo "error: no archive at $W/out.7z" | tee -a "$ART/summary.txt"
  tail -50 "$ART/kh-create.log" | tee -a "$ART/summary.txt"
  exit 1
fi

if [[ -n "$NATIVE_MS" && "$NATIVE_MS" != "0" ]]; then
  python3 - <<PY | tee -a "$ART/summary.txt"
n=float("$NATIVE_MS"); k=float("$KH_MS")
print(f"ratio_kh_over_native={k/n:.2f}x")
print(f"native_s={n/1000:.2f}  kh_s={k/1000:.2f}")
PY
fi

echo "" | tee -a "$ART/summary.txt"
echo "=== kh + Darwin 7zz (test archive) ===" | tee -a "$ART/summary.txt"
# Stats off for test pass noise, or leave on — keep on for completeness
set +e
$KH run --max-syscalls 500000000 7zz -- t "$G_OUT" \
  >"$ART/kh-test.log" 2>"$ART/kh-test-stats.raw"
T_RC=$?
set -e
echo "kh_test_rc=$T_RC" | tee -a "$ART/summary.txt"
if grep -q "Everything is Ok" "$ART/kh-test.log" 2>/dev/null; then
  echo "verify: Everything is Ok" | tee -a "$ART/summary.txt"
else
  echo "verify: FAILED (see kh-test.log)" | tee -a "$ART/summary.txt"
  tail -30 "$ART/kh-test.log" | tee -a "$ART/summary.txt"
  exit 1
fi

echo "" | tee -a "$ART/summary.txt"
echo "done. host results: bind-mounted /results" | tee -a "$ART/summary.txt"
'

echo
echo "==> host results: $OUT"
echo "    summary:     $OUT/summary.txt"
echo "    stats:       $OUT/kh-stats.txt"
echo "    create log:  $OUT/kh-create.log"
if [[ -f "$OUT/summary.txt" ]]; then
  echo
  echo "-------- summary --------"
  cat "$OUT/summary.txt"
fi
