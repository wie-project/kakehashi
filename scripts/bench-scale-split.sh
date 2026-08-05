#!/usr/bin/env bash
# Scale plate-A (mx=0 list) to measure us/crossing vs nfiles × payload.
# Run inside Docker (kakehashi:dev) or: docker run ... bash scripts/bench-scale-split.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ART="${KH_BENCH_OUT:-$ROOT/.tmp/kh-bench-scale}"
mkdir -p "$ART"
: >"$ART/scale.txt"

if [[ ! -x ./target/release/kh ]]; then
  cargo build -p kakehashi --release
fi
KH=./target/release/kh
$KH bottle ensure >/dev/null
if [[ -x tests/clang-probe/7zz.bin ]]; then
  export KAKEHASHI_7ZZ="$ROOT/tests/clang-probe/7zz.bin"
fi
$KH install 7zip >/dev/null || true
export KAKEHASHI_BOUNDARY_STATS=ns

W=/tmp/scale
rm -rf "$W"
mkdir -p "$W"
NATIVE=""
if command -v 7zz >/dev/null 2>&1; then NATIVE=$(command -v 7zz)
elif command -v 7z >/dev/null 2>&1; then NATIVE=$(command -v 7z)
fi

run() {
  local n=$1 sz=$2 tag=$3
  local root="$W/$tag"
  rm -rf "$root"
  mkdir -p "$root/tree"
  python3 - "$root" "$n" "$sz" "$tag" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1]) / "tree"
n, sz = int(sys.argv[2]), int(sys.argv[3])
tag = sys.argv[4]
payload = (b"ab" * ((sz // 2) + 1))[:sz]
paths = []
nd = 40
for i in range(n):
    d = root / f"d{i % nd:04d}"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"f{i:06d}.bin"
    p.write_bytes(payload)
    paths.append(f"/private/tmp/scale/{tag}/tree/" + str(p.relative_to(root)))
(root.parent / "files.list").write_text("\n".join(paths) + "\n")
(root.parent / "native.list").write_text(
    "\n".join(str(p) for p in sorted(root.rglob("*.bin"))) + "\n"
)
print(f"built n={n} sz={sz} tag={tag}", flush=True)
PY

  local nms=0
  if [[ -n "$NATIVE" ]]; then
    local s e
    s=$(date +%s%N)
    "$NATIVE" a -t7z -mx=0 -mmt=1 "$root/native.7z" @"$root/native.list" \
      >/dev/null 2>&1 || true
    e=$(date +%s%N)
    nms=$(( (e - s) / 1000000 ))
  fi

  local s e kms
  s=$(date +%s%N)
  $KH run --max-syscalls 500000000 7zz -- \
    a -t7z -m0=lzma2 -mx=0 -mmt=1 \
    "/private/tmp/scale/$tag/out.7z" @"/private/tmp/scale/$tag/files.list" \
    >"$root/kh.log" 2>"$root/kh.stats"
  e=$(date +%s%N)
  kms=$(( (e - s) / 1000000 ))

  local total hostns files
  total=$(grep -oE "total=[0-9]+" "$root/kh.stats" | head -1 | cut -d= -f2)
  hostns=$(grep -oE "host_dispatch_ns_sum=[0-9]+" "$root/kh.stats" | head -1 | cut -d= -f2 || true)
  hostns=${hostns:-0}
  files=$(grep -oE "Files read from disk: [0-9]+" "$root/kh.log" | head -1 | awk '{print $5}')
  files=${files:-0}

  python3 -c "
n=$n; sz=$sz; kms=$kms; total=int('$total' or 0); hostns=int('$hostns' or 0)
nms=$nms; files=int('$files' or 0)
host_ms=hostns/1e6
res=kms-host_ms
ratio=(kms/nms) if nms else 0
print(
  f'n={n:5} sz={sz:5} files={files} kh_ms={kms:6} native_ms={nms:5} '
  f'total={total:6} host_ms={host_ms:6.1f} residual_ms={res:6.1f} '
  f'us_cross={(kms*1000)/max(total,1):6.1f} ms_file={kms/max(n,1):6.3f} '
  f'ratio={ratio:5.1f}x'
)
" | tee -a "$ART/scale.txt"
  cp "$root/kh.stats" "$ART/${tag}.stats"
}

run 100 1 warm100
run 1000 1 n1k_b1
run 1000 1024 n1k_b1k
run 4000 1 n4k_b1
run 4000 1024 n4k_b1k
run 4000 1024 n4k_b1k_rep

echo "---"
cat "$ART/scale.txt"
