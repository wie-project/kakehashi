#!/usr/bin/env bash
# Build and run the reproducible Linux smoke image (Colima / Docker aarch64).
#
# What this proves (all exit codes / stdout checked in-script):
#   - bottle create / ensure / Volumes/linux R-W / destroy
#   - clang probes (write_exit, puts_hello, printf_hello, return_zero)
#   - kh trace smoke
#
# This script is pass/fail in the terminal only — it does not leave large
# artifacts. For inspectable .7z archives see:
#   ./scripts/docker-kh.sh 7zz --        →  .tmp/kh-out/
#   ./scripts/bench-fair-local.sh  →  .tmp/kh-bench-fair/artifacts/
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:smoke}"
LIBSYS_HOST="${ROOT}/crates/kh-runtime/resources/libSystem.B.dylib"

if [[ ! -f "$LIBSYS_HOST" ]]; then
  echo "error: missing guest libSystem at $LIBSYS_HOST" >&2
  exit 1
fi

echo "==> docker build ${IMAGE}"
docker build -t "${IMAGE}" -f Dockerfile .

echo "==> PAGE_SIZE inside image"
docker run --rm --entrypoint getconf "${IMAGE}" PAGE_SIZE

KH=(docker run --rm --entrypoint kh -w /app "${IMAGE}")

echo "==> kh --help"
"${KH[@]}" --help

echo "==> bottle lifecycle + clang probes + trace (inside Linux)"
docker run --rm --entrypoint bash -w /app "${IMAGE}" -c '
set -euo pipefail
export KAKEHASHI_CONFIG_DIR=/tmp/kh-cfg
export KAKEHASHI_DATA_DIR=/tmp/kh-data
mkdir -p "$KAKEHASHI_CONFIG_DIR" "$KAKEHASHI_DATA_DIR"
BOTTLE=/tmp/kh-data/custom-bottle-name
LIBSYS=/app/crates/kh-runtime/resources/libSystem.B.dylib

echo "==> kh bottle create / ensure / Volumes/linux R-W / libSystem install / destroy"
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
echo "bottle lifecycle ok"

# Reuse the active bottle for clang probes.
if [[ -x tests/clang-probe/write_exit ]]; then
  echo "==> kh run --dry-load (clang write_exit)"
  kh run --dry-load --root "$BOTTLE" tests/clang-probe/write_exit

  echo "==> kh run --expect-code 0 (clang write+exit → hello)"
  clang_out="$(kh run --expect-code 0 --root "$BOTTLE" tests/clang-probe/write_exit)"
  test "${clang_out}" = "hello"
fi

if [[ -x tests/clang-probe/return_zero ]]; then
  echo "==> kh run --expect-code 0 (clang return 0 from main)"
  kh run --expect-code 0 --root "$BOTTLE" tests/clang-probe/return_zero
fi

if [[ -x tests/clang-probe/puts_hello ]]; then
  echo "==> kh run --expect-code 0 (clang puts → hello)"
  puts_out="$(kh run --expect-code 0 --root "$BOTTLE" tests/clang-probe/puts_hello)"
  test "${puts_out}" = "hello"
fi

if [[ -x tests/clang-probe/printf_hello ]]; then
  echo "==> kh run --expect-code 0 (clang printf → hello)"
  printf_out="$(kh run --expect-code 0 --root "$BOTTLE" tests/clang-probe/printf_hello)"
  test "${printf_out}" = "hello"
fi

if [[ -x tests/clang-probe/write_exit ]]; then
  echo "==> kh trace (clang write_exit)"
  # Freestanding process startup seeds env via many host getenvs after I/O.
  kh trace --max-events 64 --root "$BOTTLE" tests/clang-probe/write_exit
fi

kh bottle destroy --yes
echo "probes ok"
'

echo
echo "================================================================"
echo " smoke ok  (image: ${IMAGE})"
echo "  checked: bottle lifecycle, clang probes (if present), trace"
echo "  no host artifacts  — for .7z you can open yourself:"
echo "    ./scripts/docker-kh.sh 7zz -- a /Volumes/linux/out/demo.7z \\"
echo "        /Volumes/linux/src/README.md"
echo "    ls -lh .tmp/kh-out/"
echo "    ./scripts/bench-fair-local.sh   # → .tmp/kh-bench-fair/artifacts/"
echo "================================================================"
