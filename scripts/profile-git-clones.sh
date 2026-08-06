#!/usr/bin/env bash
# Profile three full git clones under kh with KAKEHASHI_BOUNDARY_STATS=ns.
#
# Cases (small → medium → large):
#   1) octocat/Hello-World
#   2) wie-project/kakehashi (this product repo)
#   3) facebook/folly
#
# Artifacts: .tmp/kh-clone-profile/<case>/{wall.txt,stderr.txt,stats.txt,summary bits}
# Wall clock is host-side around `kh run git clone`. Crossing counts come from
# the boundary dump on guest exit (stderr).
#
# Usage:
#   ./scripts/profile-git-clones.sh
#   KAKEHASHI_BOUNDARY_STATS=1 ./scripts/profile-git-clones.sh   # counts only
#
# Env: same as docker-git.sh (KH_EXTRA_CARGO_ARGS defaults to --release).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
ART="${KH_CLONE_PROFILE_DIR:-$ROOT/.tmp/kh-clone-profile}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
  KH_EXTRA_CARGO_ARGS=--release
fi
export KAKEHASHI_BOUNDARY_STATS="${KAKEHASHI_BOUNDARY_STATS:-ns}"

mkdir -p "$ART" "$KH_OUT" "$ROOT/.kh"

if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
  || [[ -f target/release/libkh_libsystem.dylib ]]; then
  ./scripts/stage-libsystem.sh
elif [[ -f crates/kh-runtime/resources/libSystem.B.dylib ]]; then
  echo "note: using crates/kh-runtime/resources/libSystem.B.dylib"
else
  echo "error: no guest libSystem" >&2
  exit 1
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
fi

echo "==> profile dir: $ART"
echo "==> KAKEHASHI_BOUNDARY_STATS=$KAKEHASHI_BOUNDARY_STATS"
echo "==> KH_EXTRA_CARGO_ARGS=$KH_EXTRA_CARGO_ARGS"

docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -v "${KH_OUT}:/out" \
  -v "${ART}:/report" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS}" \
  -e "KAKEHASHI_BOUNDARY_STATS=${KAKEHASHI_BOUNDARY_STATS}" \
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
"$KH" install xcode-tools >/dev/null

"$KH" run git -- config --global user.email "kh@test.io"
"$KH" run git -- config --global user.name "kh-profile"
"$KH" run git -- config --global protocol.version 2
"$KH" run git -- config --global http.postBuffer 524288000

# name|url|dest_under_/out
CASES=(
  "hello|https://github.com/octocat/Hello-World.git|clone-hello"
  "kakehashi|https://github.com/wie-project/kakehashi.git|clone-kakehashi"
  "folly|https://github.com/facebook/folly.git|clone-folly"
)

SUMMARY=/report/summary.tsv
{
  echo -e "case\twall_s\texit\ttotal_crossings\thost_dispatch_ms\tus_per_crossing\tdu_mib\ttop1\ttop1_count\ttop2\ttop2_count\ttop3\ttop3_count"
} >"$SUMMARY"

parse_stats() {
  local f="$1"
  # total=N
  TOTAL=$(grep -oE "total=[0-9]+" "$f" | head -1 | cut -d= -f2 || true)
  TOTAL=${TOTAL:-0}
  # host_dispatch_ns_sum=N  (~M ms)
  HOST_NS=$(grep -oE "host_dispatch_ns_sum=[0-9]+" "$f" | head -1 | cut -d= -f2 || true)
  HOST_NS=${HOST_NS:-0}
  HOST_MS=$(awk -v n="$HOST_NS" 'BEGIN { printf "%.1f", n/1e6 }')
  # top3 rows: "   1  count  ns  avg  name (#0x..)" (tab/space padded)
  mapfile -t TOP < <(awk '
    $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {
      print; if (++n >= 3) exit
    }
  ' "$f" 2>/dev/null || true)

  t1n=""; t1c=""; t2n=""; t2c=""; t3n=""; t3c=""
  local i line count name
  for i in 0 1 2; do
    line="${TOP[$i]:-}"
    [[ -z "$line" ]] && continue
    count=$(echo "$line" | awk '{print $2}')
    name=$(echo "$line" | sed -E 's/.*[[:space:]]([A-Za-z0-9_]+)[[:space:]]+\(.*/\1/')
    case $i in
      0) t1n=$name; t1c=$count ;;
      1) t2n=$name; t2c=$count ;;
      2) t3n=$name; t3c=$count ;;
    esac
  done

  echo "$TOTAL|$HOST_MS|$t1n|$t1c|$t2n|$t2c|$t3n|$t3c"
}

for entry in "${CASES[@]}"; do
  IFS="|" read -r name url dest <<<"$entry"
  out="/out/${dest}"
  rep="/report/${name}"
  mkdir -p "$rep"
  rm -rf "$out"

  echo ""
  echo "======== clone $name ========"
  echo "url=$url"
  echo "dest=guest /Volumes/linux/out/${dest}"

  set +e
  start=$(date +%s%N)
  "$KH" run --max-syscalls 500000000 git -- \
    clone --progress "$url" "/Volumes/linux/out/${dest}" \
    >"$rep/stdout.txt" 2>"$rep/stderr.txt"
  rc=$?
  end=$(date +%s%N)
  set -e

  wall_ns=$((end - start))
  wall_s=$(awk -v n="$wall_ns" "BEGIN { printf \"%.3f\", n/1e9 }")
  echo "$wall_s" >"$rep/wall_s.txt"
  echo "$rc" >"$rep/exit.txt"

  # Extract boundary dump (may be mixed with clone progress on stderr)
  grep -E "kh boundary stats:|^[[:space:]]*host_dispatch|^[[:space:]]*rank |^[[:space:]]*[0-9]+ +[0-9]+|other sample" \
    "$rep/stderr.txt" >"$rep/stats.txt" || true
  # Full stderr kept; also a short tail for human
  tail -80 "$rep/stderr.txt" >"$rep/stderr.tail.txt" || true

  du_k=0
  if [[ -d "$out" ]]; then
    du_k=$(du -sk "$out" | awk "{print \$1}")
  fi
  du_mib=$(awk -v k="$du_k" "BEGIN { printf \"%.2f\", k/1024 }")

  parsed=$(parse_stats "$rep/stats.txt")
  IFS="|" read -r total host_ms t1n t1c t2n t2c t3n t3c <<<"$parsed"
  total=${total:-0}
  us_cross="0"
  if [[ "$total" != "0" && -n "$total" ]]; then
    us_cross=$(awk -v w="$wall_s" -v tot="$total" 'BEGIN { printf "%.2f", (w*1e6)/tot }')
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$wall_s" "$rc" "$total" "$host_ms" "$us_cross" "$du_mib" \
    "${t1n:-}" "${t1c:-}" "${t2n:-}" "${t2c:-}" "${t3n:-}" "${t3c:-}" \
    | tee -a "$SUMMARY"

  echo "wall_s=$wall_s exit=$rc total_crossings=$total host_dispatch_ms=$host_ms us/cross=$us_cross du_mib=$du_mib"
  if [[ -s "$rep/stats.txt" ]]; then
    echo "--- top of boundary stats ---"
    head -20 "$rep/stats.txt"
  else
    echo "WARN: no boundary stats lines in stderr (is KAKEHASHI_BOUNDARY_STATS set?)"
  fi
done

echo ""
echo "==== summary.tsv ===="
cat "$SUMMARY"

# Scaling analysis (python) — prefer host-side re-parse of stats.txt if present
python3 - <<'PY'
from pathlib import Path
import csv, re

report = Path("/report")
summary = report / "summary.tsv"
rows = list(csv.DictReader(summary.open(), delimiter="\t"))
if len(rows) < 2:
    raise SystemExit("need ≥2 cases")

def f(r, k):
    try:
        return float(r.get(k) or 0)
    except Exception:
        return 0.0

print("\n==== scaling analysis ====")
print(f"{'case':12} {'du_mib':>10} {'wall_s':>10} {'crossings':>12} {'us/x':>8} {'host_ms':>10} {'wall/MiB':>10} {'x/MiB':>10}")
for r in rows:
    du = max(f(r, "du_mib"), 1e-6)
    wall = f(r, "wall_s")
    tot = f(r, "total_crossings")
    us = f(r, "us_per_crossing")
    host = f(r, "host_dispatch_ms")
    print(
        f"{r['case']:12} {du:10.2f} {wall:10.3f} {tot:12.0f} {us:8.2f} {host:10.1f} "
        f"{wall/du:10.4f} {tot/du:10.1f}"
    )

print("\nPairwise (size → wall, crossings, us/x):")
for i in range(len(rows) - 1):
    a, b = rows[i], rows[i + 1]
    sr = f(b, "du_mib") / max(f(a, "du_mib"), 1e-9)
    wr = f(b, "wall_s") / max(f(a, "wall_s"), 1e-9)
    xr = f(b, "total_crossings") / max(f(a, "total_crossings"), 1.0)
    ur = f(b, "us_per_crossing") / max(f(a, "us_per_crossing"), 1e-9)
    print(f"  {a['case']} → {b['case']}: size×{sr:.2f} wall×{wr:.2f} crossings×{xr:.2f} us/x×{ur:.2f}")

print("\nNotes:")
print("- wall/MiB high on tiny repos = fixed clone setup, not monorepo tax.")
print("- crossings track checkout (files) more than pack MiB.")
print("- us/x falling on larger packs = larger read amortizes boundary.")
print("- host_dispatch_ms is sum across threads inside dispatch only.")
PY
'
echo "==> done: $ART"
