#!/usr/bin/env bash
# Profile pure git *checkout* under kh with KAKEHASHI_BOUNDARY_STATS=ns.
#
# Isolates worktree materialization from network/pack receive:
#   1) ensure objects exist (reuse local clone or `clone --no-checkout`)
#   2) strip worktree (keep .git)
#   3) time + boundary-stats only: `git checkout -f HEAD`
#
# Cases (same as clone profile): hello / kakehashi / folly
#
# Artifacts: .tmp/kh-checkout-profile/<case>/{wall,stats,stderr,...}
# Compare against .tmp/kh-clone-profile/ to see how much of full-clone `read`
# was pack/TLS vs object→worktree I/O.
#
# Usage:
#   ./scripts/profile-git-checkout.sh
#   KH_CHECKOUT_FORCE_FETCH=1 ./scripts/profile-git-checkout.sh  # re-fetch packs
#   KAKEHASHI_BOUNDARY_STATS=1 ./scripts/profile-git-checkout.sh  # counts only
#
# Env: same as docker-git.sh (KH_EXTRA_CARGO_ARGS defaults to --release).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
ART="${KH_CHECKOUT_PROFILE_DIR:-$ROOT/.tmp/kh-checkout-profile}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
  KH_EXTRA_CARGO_ARGS=--release
fi
export KAKEHASHI_BOUNDARY_STATS="${KAKEHASHI_BOUNDARY_STATS:-ns}"
FORCE_FETCH="${KH_CHECKOUT_FORCE_FETCH:-0}"

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
echo "==> KH_CHECKOUT_FORCE_FETCH=$FORCE_FETCH"

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
  -e "KH_CHECKOUT_FORCE_FETCH=${FORCE_FETCH}" \
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
  echo -e "case\twall_s\texit\ttotal_crossings\thost_dispatch_ms\tus_per_crossing\tdu_mib\tworktree_files\tread_count\tread_avg_us\twrite_count\topen_count\tlstat_count\ttop1\ttop1_count\ttop2\ttop2_count\ttop3\ttop3_count"
} >"$SUMMARY"

parse_stats() {
  local f="$1"
  TOTAL=$(grep -oE "total=[0-9]+" "$f" | head -1 | cut -d= -f2 || true)
  TOTAL=${TOTAL:-0}
  HOST_NS=$(grep -oE "host_dispatch_ns_sum=[0-9]+" "$f" | head -1 | cut -d= -f2 || true)
  HOST_NS=${HOST_NS:-0}
  HOST_MS=$(awk -v n="$HOST_NS" "BEGIN { printf \"%.1f\", n/1e6 }")

  # Per-name: count and avg_ns from ranked lines
  # format: rank count ns avg_ns name (0x..)
  read_count=0; read_avg_us=0; write_count=0; open_count=0; lstat_count=0
  while read -r _rank cnt _ns avg name _rest; do
    [[ -z "${cnt:-}" ]] && continue
    case "$name" in
      read)
        read_count=$cnt
        read_avg_us=$(awk -v a="$avg" "BEGIN { printf \"%.2f\", a/1000 }")
        ;;
      write) write_count=$cnt ;;
      open) open_count=$cnt ;;
      lstat) lstat_count=$cnt ;;
    esac
  done < <(awk '\''$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ { print }'\'' "$f" 2>/dev/null || true)

  mapfile -t TOP < <(awk '\''
    $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {
      print; if (++n >= 3) exit
    }
  '\'' "$f" 2>/dev/null || true)

  t1n=""; t1c=""; t2n=""; t2c=""; t3n=""; t3c=""
  local i line count name
  for i in 0 1 2; do
    line="${TOP[$i]:-}"
    [[ -z "$line" ]] && continue
    count=$(echo "$line" | awk "{print \$2}")
    name=$(echo "$line" | sed -E "s/.*[[:space:]]([A-Za-z0-9_]+)[[:space:]]+\\(.*/\\1/")
    case $i in
      0) t1n=$name; t1c=$count ;;
      1) t2n=$name; t2c=$count ;;
      2) t3n=$name; t3c=$count ;;
    esac
  done

  echo "$TOTAL|$HOST_MS|$read_count|$read_avg_us|$write_count|$open_count|$lstat_count|$t1n|$t1c|$t2n|$t2c|$t3n|$t3c"
}

strip_worktree() {
  local dir="$1"
  # Keep only .git; remove index so checkout rewrites everything.
  find "$dir" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  rm -f "$dir/.git/index"
}

ensure_objects() {
  local name="$1" url="$2" out="$3" prep="$4"
  if [[ "${KH_CHECKOUT_FORCE_FETCH:-0}" != "1" && -d "$out/.git" ]]; then
    echo "reuse existing objects: $out" | tee -a "$prep"
    return 0
  fi
  echo "fetch objects (clone --no-checkout): $url" | tee -a "$prep"
  rm -rf "$out"
  set +e
  "$KH" run --max-syscalls 500000000 git -- \
    clone --no-checkout --progress "$url" "/Volumes/linux/out/${out##*/}" \
    >>"$prep" 2>&1
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "ERROR: clone --no-checkout failed rc=$rc" | tee -a "$prep"
    return "$rc"
  fi
}

for entry in "${CASES[@]}"; do
  IFS="|" read -r name url dest <<<"$entry"
  out="/out/${dest}"
  rep="/report/${name}"
  mkdir -p "$rep"
  : >"$rep/prepare.txt"

  echo ""
  echo "======== checkout $name ========"
  echo "url=$url"
  echo "dest=guest /Volumes/linux/out/${dest}"

  ensure_objects "$name" "$url" "$out" "$rep/prepare.txt"
  strip_worktree "$out"

  # Sanity: only .git should remain
  leftover=$(find "$out" -mindepth 1 -maxdepth 1 ! -name .git | wc -l | tr -d " ")
  if [[ "$leftover" != "0" ]]; then
    echo "WARN: strip left $leftover non-.git entries" | tee -a "$rep/prepare.txt"
  fi

  set +e
  start=$(date +%s%N)
  "$KH" run --max-syscalls 500000000 git -- \
    -C "/Volumes/linux/out/${dest}" checkout -f HEAD \
    >"$rep/stdout.txt" 2>"$rep/stderr.txt"
  rc=$?
  end=$(date +%s%N)
  set -e

  wall_ns=$((end - start))
  wall_s=$(awk -v n="$wall_ns" "BEGIN { printf \"%.3f\", n/1e9 }")
  echo "$wall_s" >"$rep/wall_s.txt"
  echo "$rc" >"$rep/exit.txt"

  grep -E "kh boundary stats:|^[[:space:]]*host_dispatch|^[[:space:]]*rank |^[[:space:]]*[0-9]+ +[0-9]+|other sample" \
    "$rep/stderr.txt" >"$rep/stats.txt" || true
  tail -80 "$rep/stderr.txt" >"$rep/stderr.tail.txt" || true

  du_k=0
  wt_files=0
  if [[ -d "$out" ]]; then
    du_k=$(du -sk "$out" | awk "{print \$1}")
    # worktree files only (exclude .git)
    wt_files=$(find "$out" -type f ! -path "*/.git/*" 2>/dev/null | wc -l | tr -d " ")
  fi
  du_mib=$(awk -v k="$du_k" "BEGIN { printf \"%.2f\", k/1024 }")

  parsed=$(parse_stats "$rep/stats.txt")
  IFS="|" read -r total host_ms read_c read_avg write_c open_c lstat_c t1n t1c t2n t2c t3n t3c <<<"$parsed"
  total=${total:-0}
  us_cross="0"
  if [[ "$total" != "0" && -n "$total" ]]; then
    us_cross=$(awk -v w="$wall_s" -v tot="$total" "BEGIN { printf \"%.2f\", (w*1e6)/tot }")
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$name" "$wall_s" "$rc" "$total" "$host_ms" "$us_cross" "$du_mib" "$wt_files" \
    "${read_c:-0}" "${read_avg:-0}" "${write_c:-0}" "${open_c:-0}" "${lstat_c:-0}" \
    "${t1n:-}" "${t1c:-}" "${t2n:-}" "${t2c:-}" "${t3n:-}" "${t3c:-}" \
    | tee -a "$SUMMARY"

  echo "wall_s=$wall_s exit=$rc total=$total host_ms=$host_ms us/x=$us_cross files=$wt_files read=$read_c avg_us=$read_avg write=$write_c open=$open_c lstat=$lstat_c"
  if [[ -s "$rep/stats.txt" ]]; then
    echo "--- boundary stats (top) ---"
    head -25 "$rep/stats.txt"
  else
    echo "WARN: no boundary stats in stderr"
  fi
done

echo ""
echo "==== summary.tsv ===="
cat "$SUMMARY"

python3 - <<'\''PY'\''
from pathlib import Path
import csv

report = Path("/report")
rows = list(csv.DictReader((report / "summary.tsv").open(), delimiter="\t"))
if len(rows) < 2:
    raise SystemExit("need ≥2 cases")

def f(r, k):
    try:
        return float(r.get(k) or 0)
    except Exception:
        return 0.0

print("\n==== checkout scaling ====")
hdr = f"{'case':12} {'files':>7} {'wall_s':>8} {'cross':>10} {'read':>10} {'r_avg_us':>9} {'write':>8} {'open':>8} {'lstat':>8} {'us/x':>8} {'wall/file_ms':>12}"
print(hdr)
for r in rows:
    files = max(f(r, "worktree_files"), 1e-9)
    wall = f(r, "wall_s")
    print(
        f"{r['case']:12} {f(r,'worktree_files'):7.0f} {wall:8.3f} {f(r,'total_crossings'):10.0f} "
        f"{f(r,'read_count'):10.0f} {f(r,'read_avg_us'):9.2f} {f(r,'write_count'):8.0f} "
        f"{f(r,'open_count'):8.0f} {f(r,'lstat_count'):8.0f} {f(r,'us_per_crossing'):8.2f} "
        f"{(wall*1000)/files:12.3f}"
    )

print("\nPairwise (files → wall, crossings, read):")
for i in range(len(rows) - 1):
    a, b = rows[i], rows[i + 1]
    fr = f(b, "worktree_files") / max(f(a, "worktree_files"), 1e-9)
    wr = f(b, "wall_s") / max(f(a, "wall_s"), 1e-9)
    xr = f(b, "total_crossings") / max(f(a, "total_crossings"), 1.0)
    rr = f(b, "read_count") / max(f(a, "read_count"), 1.0)
    ar = f(b, "read_avg_us") / max(f(a, "read_avg_us"), 1e-9)
    print(
        f"  {a['case']} → {b['case']}: files×{fr:.2f} wall×{wr:.2f} "
        f"cross×{xr:.2f} read×{rr:.2f} read_avg×{ar:.2f}"
    )

print("\nPer-file rates (checkout surface):")
for r in rows:
    files = max(f(r, "worktree_files"), 1e-9)
    print(
        f"  {r['case']:12} cross/file={f(r,'total_crossings')/files:6.1f}  "
        f"read/file={f(r,'read_count')/files:6.2f}  "
        f"write/file={f(r,'write_count')/files:6.2f}  "
        f"open/file={f(r,'open_count')/files:6.2f}  "
        f"lstat/file={f(r,'lstat_count')/files:6.2f}"
    )

# Optional compare to full-clone profile if mounted sibling exists
clone_sum = Path("/src/.tmp/kh-clone-profile/summary.tsv")
if clone_sum.is_file():
    clone_rows = {r["case"]: r for r in csv.DictReader(clone_sum.open(), delimiter="\t")}
    print("\n==== checkout vs full clone (same cases) ====")
    print(f"{'case':12} {'clone_wall':>10} {'co_wall':>10} {'co_pct':>10} {'clone_read':>12} {'co_read':>10} {'co_r_pct':>10}")
    for r in rows:
        c = clone_rows.get(r["case"])
        if not c:
            continue
        cw = f(c, "wall_s")
        cow = f(r, "wall_s")
        print(
            f"{r['case']:12} {cw:10.3f} {cow:10.3f} {(100*cow/max(cw,1e-9)):10.1f} "
            f"{'n/a':>12} {f(r,'read_count'):10.0f} {'n/a':>10}"
        )
    # Fill clone read from stats.txt when present
    print("\n(with clone stats.txt read counts if available)")
    for r in rows:
        st = Path("/src/.tmp/kh-clone-profile") / r["case"] / "stats.txt"
        clone_read = None
        clone_wall = f(clone_rows.get(r["case"], {}), "wall_s") if r["case"] in clone_rows else 0
        if st.is_file():
            for line in st.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[-2] == "read" or (len(parts) >= 5 and "read" in parts):
                    # "1  174697  ...  read (0x3)"
                    try:
                        # find token 'read'
                        for i, p in enumerate(parts):
                            if p == "read":
                                clone_read = int(parts[1])
                                break
                    except Exception:
                        pass
        if clone_read is not None:
            cr = f(r, "read_count")
            print(
                f"  {r['case']:12} clone_read={clone_read:>8}  checkout_read={cr:>8}  "
                f"checkout/clone_read%={100*cr/max(clone_read,1):5.1f}  "
                f"checkout/clone_wall%={100*f(r,'wall_s')/max(clone_wall,1e-9):5.1f}"
            )

print("\nNotes:")
print("- Pure checkout = object DB → worktree (no TLS/network).")
print("- If read still dominates, it is pack/object file I/O, not protocol v1.")
print("- Healthy scaling: wall ~ linear in files; cross/file and read/file roughly flat.")
print("- Rising read_avg_us with size is OK if larger blob reads; rising *count*/file is a bug smell.")
PY
'
echo "==> done: $ART"
