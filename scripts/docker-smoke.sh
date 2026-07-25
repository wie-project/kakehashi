#!/usr/bin/env bash
# Build and run the reproducible Linux smoke image (Colima / Docker aarch64).
#
# What this proves (all exit codes / stdout checked in-script):
#   - bottle create / ensure / Volumes/linux R-W / destroy
#   - synthetic fixtures (write+exit, errno, mmap, threads, dylib, ctor, …)
#   - clang probes when present (write_exit, puts_hello, printf_hello, …)
#   - kh trace smoke
#
# This script is pass/fail in the terminal only — it does not leave large
# artifacts. For inspectable .7z archives see:
#   ./scripts/docker-7zz.sh        →  .tmp/kh-out/
#   ./scripts/bench-fair-local.sh  →  .tmp/kh-bench-fair/artifacts/
#
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

echo "==> kh bottle create / ensure / Volumes/linux R-W / libSystem install / destroy (inside Linux)"
docker run --rm --entrypoint bash -w /app "${IMAGE}" -c '
set -euo pipefail
export KAKEHASHI_CONFIG_DIR=/tmp/kh-cfg
export KAKEHASHI_DATA_DIR=/tmp/kh-data
mkdir -p "$KAKEHASHI_CONFIG_DIR" "$KAKEHASHI_DATA_DIR"
BOTTLE=/tmp/kh-data/custom-bottle-name
# Release-like path: explicit dylib (synthetic fixture stands in for staged guest).
LIBSYS=/app/tests/fixtures/bottle/usr/lib/libSystem.B.dylib

kh bottle create --path "$BOTTLE" --libsystem "$LIBSYS"
test -L "$BOTTLE/Volumes/linux"
test -d "$BOTTLE/usr/lib"
test -d "$BOTTLE/Applications"
test -L "$BOTTLE/etc"
test -f "$BOTTLE/.kakehashi-bottle"
test -f "$BOTTLE/usr/lib/libSystem.B.dylib"
test -L "$BOTTLE/usr/lib/libc++.1.dylib"
test "$(readlink "$BOTTLE/usr/lib/libc++.1.dylib")" = "libSystem.B.dylib"
kh bottle status | grep -q "libSystem: true"
kh bottle status | grep -q "libc++:    true"

# Host (Linux) file readable through the bottle bridge.
TOKEN="kh-vol-$$"
echo "hello-outside" >"/tmp/${TOKEN}"
test "$(cat "$BOTTLE/Volumes/linux/tmp/${TOKEN}")" = "hello-outside"

# Write via bottle path, observe outside the bottle on the real FS.
echo "from-bottle" >"$BOTTLE/Volumes/linux/tmp/${TOKEN}-2"
test "$(cat "/tmp/${TOKEN}-2")" = "from-bottle"

# Exactly one bottle: second create must fail.
if kh bottle create --path /tmp/kh-data/other --skip-libsystem 2>/dev/null; then
  echo "expected second create to fail" >&2
  exit 1
fi

# ensure is idempotent and refreshes libSystem without destroy.
kh bottle ensure --libsystem "$LIBSYS"
test -f "$BOTTLE/usr/lib/libSystem.B.dylib"
kh bottle status | grep -q "libSystem: true"

kh bottle destroy --yes
test ! -e "$BOTTLE"
kh bottle status | grep -q "no bottle"

# ensure with no prior bottle behaves like create.
kh bottle ensure --path "$BOTTLE" --libsystem "$LIBSYS"
test -f "$BOTTLE/.kakehashi-bottle"
kh bottle destroy --yes
echo "bottle lifecycle ok"
'

echo "==> kh run --dry-load (fixture)"
"${KH[@]}" run --dry-load tests/fixtures/minimal_arm64_execute.macho

echo "==> kh run --expect-code 0 (write+exit)"
out="$("${KH[@]}" run --expect-code 0 tests/fixtures/minimal_arm64_execute.macho)"
test "${out}" = "kh"

echo "==> kh run --expect-code 0 (errno unknown then exit)"
"${KH[@]}" run --expect-code 0 tests/fixtures/errno_unknown_then_exit.macho

echo "==> kh run --expect-code 0 (mmap+munmap+exit)"
"${KH[@]}" run --expect-code 0 tests/fixtures/mmap_touch_exit.macho

echo "==> kh run --expect-code 0 (bsdthread create + join)"
thread_out="$("${KH[@]}" run --expect-code 0 tests/fixtures/bsdthread_create_join.macho)"
test "${thread_out}" = "T"

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

echo
echo "================================================================"
echo " smoke ok  (image: ${IMAGE})"
echo "  checked: bottle lifecycle, fixtures, clang probes (if present), trace"
echo "  no host artifacts  — for .7z you can open yourself:"
echo "    ./scripts/docker-7zz.sh a /Volumes/linux/out/demo.7z \\"
echo "        /Volumes/linux/src/README.md"
echo "    ls -lh .tmp/kh-out/"
echo "    ./scripts/bench-fair-local.sh   # → .tmp/kh-bench-fair/artifacts/"
echo "================================================================"
