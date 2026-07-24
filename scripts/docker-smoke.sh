#!/usr/bin/env bash
# Build and run the reproducible Linux smoke image (Colima / Docker aarch64).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:smoke}"

echo "==> docker build ${IMAGE}"
docker build -t "${IMAGE}" -f Dockerfile .

echo "==> PAGE_SIZE inside image"
docker run --rm --entrypoint getconf "${IMAGE}" PAGE_SIZE

KH=(docker run --rm --entrypoint kh -w /app "${IMAGE}")

echo "==> kh --help"
"${KH[@]}" --help

echo "==> kh run --dry-load (fixture)"
"${KH[@]}" run --dry-load tests/fixtures/minimal_arm64_execute.macho

echo "==> kh run --expect-code 0 (write+exit)"
out="$("${KH[@]}" run --expect-code 0 tests/fixtures/minimal_arm64_execute.macho)"
test "${out}" = "kh"

echo "==> kh run --expect-code 0 (errno unknown then exit)"
"${KH[@]}" run --expect-code 0 tests/fixtures/errno_unknown_then_exit.macho

echo "==> kh run --expect-code 0 (mmap+munmap+exit)"
"${KH[@]}" run --expect-code 0 tests/fixtures/mmap_touch_exit.macho

echo "==> kh run --expect-code 0 (file mmap roundtrip)"
# Fresh container keeps pristine payload from the image layer.
"${KH[@]}" run --expect-code 0 tests/fixtures/memory_file_roundtrip.macho

echo "==> kh run --dry-load (call_dylib multi-image)"
"${KH[@]}" run --dry-load tests/fixtures/call_dylib.macho

echo "==> kh run --expect-code 42 (call sibling dylib via GOT)"
# On match, kh re-exits with the guest code (42), not 0 — allow that under set -e.
"${KH[@]}" run --expect-code 42 tests/fixtures/call_dylib.macho || test $? -eq 42

echo "==> kh run --expect-code 42 (call sibling dylib via chained fixups)"
"${KH[@]}" run --expect-code 42 tests/fixtures/call_dylib_chained.macho || test $? -eq 42

echo "==> kh run --expect-code 0 (dylib mod_init before main)"
ctor_out="$("${KH[@]}" run --expect-code 0 tests/fixtures/ctor_main.macho)"
test "${ctor_out}" = "ctor"

echo "==> kh run --dry-load --root (bottle libSystem mapped)"
"${KH[@]}" run --dry-load --root tests/fixtures/bottle tests/fixtures/call_libsystem.macho

echo "==> kh run --expect-code 77 --root (call bottle libSystem export)"
"${KH[@]}" run --expect-code 77 --root tests/fixtures/bottle \
  tests/fixtures/call_libsystem.macho || test $? -eq 77

if [[ -x tests/clang-probe/write_exit ]]; then
  echo "==> kh run --dry-load --root (clang write_exit)"
  "${KH[@]}" run --dry-load --root tests/fixtures/bottle tests/clang-probe/write_exit

  echo "==> kh run --expect-code 0 --root (clang write+exit → hello)"
  clang_out="$("${KH[@]}" run --expect-code 0 --root tests/fixtures/bottle \
    tests/clang-probe/write_exit)"
  test "${clang_out}" = "hello"
fi

if [[ -x tests/clang-probe/return_zero ]]; then
  echo "==> kh run --expect-code 0 --root (clang return 0 from main)"
  "${KH[@]}" run --expect-code 0 --root tests/fixtures/bottle \
    tests/clang-probe/return_zero
fi

if [[ -x tests/clang-probe/puts_hello ]]; then
  echo "==> kh run --expect-code 0 --root (clang puts → hello)"
  puts_out="$("${KH[@]}" run --expect-code 0 --root tests/fixtures/bottle \
    tests/clang-probe/puts_hello)"
  test "${puts_out}" = "hello"
fi

if [[ -x tests/clang-probe/printf_hello ]]; then
  echo "==> kh run --expect-code 0 --root (clang printf → hello)"
  printf_out="$("${KH[@]}" run --expect-code 0 --root tests/fixtures/bottle \
    tests/clang-probe/printf_hello)"
  test "${printf_out}" = "hello"
fi

echo "==> kh trace (write+exit)"
"${KH[@]}" trace --max-events 16 tests/fixtures/minimal_arm64_execute.macho

echo "smoke ok"
